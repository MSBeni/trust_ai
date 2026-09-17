import copy
import hashlib
import hmac
import http.client
import threading
import json
import time
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from trustai.approval_callback import (
    APPROVAL_CALLBACK_SCHEMA,
    append_approval_callback,
    approval_from_callback,
    build_approval_callback,
    build_approval_callback_from_slack_interaction,
    verify_approval_callback,
)
from trustai.approvals import APPROVAL_ENTRY_TYPE, approval_entries_for_contract
from trustai.chain import EvidenceChain
from trustai.cicd import build_promotion_check_payload, build_slack_approval_request
from trustai.contracts import contract_hash, load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.server import serve
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"


class ApprovalCallbackTests(unittest.TestCase):
    def _results_without_approvals(self) -> dict:
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        results.pop("approvals", None)
        return results

    def _slack_interaction(self, request: dict, role: str = "model_risk") -> dict:
        for block in request["request"]["body"].get("blocks", []):
            for action in block.get("elements", []) if isinstance(block, dict) else []:
                if action.get("action_id") == f"trustai_approve_{role}":
                    return {
                        "type": "block_actions",
                        "user": {"id": "U123", "username": "model-risk", "profile": {"email": "model-risk@example.com"}},
                        "team": {"id": "T456"},
                        "channel": {"id": request["channel"]},
                        "message": {"metadata": request["request"]["body"].get("metadata", {})},
                        "actions": [action],
                    }
        raise AssertionError(f"no Slack action found for role {role}")

    def _slack_signature(self, secret: str, body: bytes, timestamp: str) -> str:
        base = b"v0:" + timestamp.encode("utf-8") + b":" + body
        return "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()


    def _pack_missing_approvals(self, chain: EvidenceChain, contract: dict) -> tuple[dict, dict]:
        results = self._results_without_approvals()
        eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
        self.assertFalse(decision["passed"])
        self.assertIn("model_risk", {item["role"] for item in decision["approvals"]["required"]})
        return results, compile_proof_pack(chain, contract, eval_entry, gate_entry, decision)

    def test_signed_callback_appends_chain_approval_and_satisfies_gate(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            results, pack = self._pack_missing_approvals(chain, contract)

            request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                requester="risk@example.com",
                callback_url="https://example.test/trustai/approval-callbacks",
            )
            callback = build_approval_callback(
                request,
                role="model_risk",
                approver="model-risk@example.com",
                approved_at="2026-07-03T13:00:00Z",
                reason="Approved from signed callback.",
                external_user_id="U123",
                team_id="T456",
            )

            verification = verify_approval_callback(request, callback)
            approval = approval_from_callback(request, callback)
            entry = append_approval_callback(chain, contract, request, callback)

            self.assertTrue(verification.ok, verification.errors)
            self.assertEqual(APPROVAL_CALLBACK_SCHEMA, callback["schema"])
            self.assertEqual("slack-callback", approval["source"])
            self.assertEqual(callback["callback_id"], approval["metadata"]["callback_id"])
            self.assertEqual(APPROVAL_ENTRY_TYPE, entry["entry_type"])

            trading_ops_request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["trading_ops"],
                requester="risk@example.com",
            )
            trading_ops_callback = build_approval_callback(
                trading_ops_request,
                role="trading_ops",
                approver="ops@example.com",
                approved_at="2026-07-03T13:05:00Z",
            )
            append_approval_callback(chain, contract, trading_ops_request, trading_ops_callback)

            approval_entries = approval_entries_for_contract(chain.entries, contract_hash(contract))
            eval_entry, gate_entry, decision = append_eval_and_gate(
                chain,
                contract,
                results,
                approval_entries=approval_entries,
            )
            callback_pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision)
            proof_result = verify_proof_pack(callback_pack)

            self.assertTrue(decision["passed"], decision["approvals"]["errors"])
            self.assertTrue(proof_result.ok, proof_result.errors)
            actual_sources = {item.get("source") for item in decision["approvals"]["actual"]}
            self.assertEqual({"slack-callback"}, actual_sources)

    def test_slack_approval_callback_binds_provider_promotion_target(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            _, pack = self._pack_missing_approvals(chain, contract)
            verification = verify_proof_pack(pack)
            promotion_payload = build_promotion_check_payload(
                pack,
                verification,
                provider="github",
                commit_sha="0123456789abcdef0123456789abcdef01234567",
                repository="MSBeni/trust_ai",
                target_url="https://example.test/proof-pack",
            )
            request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                requester="risk@example.com",
                promotion_payload=promotion_payload,
            )
            callback = build_approval_callback(
                request,
                role="model_risk",
                approver="model-risk@example.com",
                approved_at="2026-07-03T13:00:00Z",
            )
            approval = approval_from_callback(request, callback)
            result = verify_approval_callback(request, callback)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual("trustai.approval-promotion-binding/0.1", request["promotion_binding"]["schema"])
            self.assertEqual(promotion_payload["payload_hash"], request["promotion_binding"]["promotion_payload_hash"])
            self.assertEqual("MSBeni/trust_ai", request["promotion_binding"]["target_ref"]["repository"])
            self.assertEqual("0123456789abcdef0123456789abcdef01234567", request["promotion_binding"]["target_ref"]["commit_sha"])
            self.assertEqual(request["promotion_binding"], callback["promotion_binding"])
            self.assertEqual(request["promotion_binding"], approval["metadata"]["promotion_binding"])
            self.assertEqual(request["promotion_binding"]["target_ref"], approval["metadata"]["promotion_target"])

    def test_slack_approval_callback_rejects_provider_target_replay(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            _, pack = self._pack_missing_approvals(chain, contract)
            verification = verify_proof_pack(pack)
            first_payload = build_promotion_check_payload(
                pack,
                verification,
                provider="github",
                commit_sha="0123456789abcdef0123456789abcdef01234567",
                repository="MSBeni/trust_ai",
                target_url="https://example.test/proof-pack",
            )
            second_payload = build_promotion_check_payload(
                pack,
                verification,
                provider="github",
                commit_sha="fedcba9876543210fedcba9876543210fedcba98",
                repository="MSBeni/trust_ai",
                target_url="https://example.test/proof-pack",
            )
            first_request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                promotion_payload=first_payload,
            )
            second_request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                promotion_payload=second_payload,
            )
            callback = build_approval_callback(
                first_request,
                role="model_risk",
                approver="model-risk@example.com",
                approved_at="2026-07-03T13:00:00Z",
            )

            result = verify_approval_callback(second_request, callback)

            self.assertFalse(result.ok)
            self.assertIn("callback request_payload_hash does not match request", result.errors)
            self.assertIn("callback promotion_binding does not match request", result.errors)

    def test_slack_interaction_builds_signed_callback(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            _, pack = self._pack_missing_approvals(chain, contract)
            request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                callback_url="https://example.test/trustai/approval-callbacks",
            )
            interaction = self._slack_interaction(request)
            callback = build_approval_callback_from_slack_interaction(
                request,
                interaction,
                approved_at="2026-07-03T13:00:00Z",
            )
            verification = verify_approval_callback(request, callback)

            self.assertTrue(verification.ok, verification.errors)
            self.assertEqual("model_risk", callback["role"])
            self.assertEqual("model-risk@example.com", callback["approver"])
            self.assertEqual("U123", callback["external_user_id"])
            self.assertEqual("T456", callback["team_id"])

    def test_server_slack_callback_endpoint_appends_approval(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            chain = EvidenceChain.load(state_path, tenant_id="approval-server")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            _, pack = self._pack_missing_approvals(chain, contract)
            chain.save()
            request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                callback_url="http://127.0.0.1/v0/approval-callbacks/slack",
            )
            interaction = self._slack_interaction(request)
            server = serve("127.0.0.1", 0, str(state_path), "approval-server", input_dir=str(CONTRACT.parent))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request(
                    "POST",
                    "/v0/approval-callbacks/slack",
                    body=json.dumps(
                        {
                            "approval_request": request,
                            "interaction": interaction,
                            "contract_path": CONTRACT.name,
                            "approved_at": "2026-07-03T13:00:00Z",
                        }
                    ),
                    headers={"Content-Type": "application/json"},
                )
                response = conn.getresponse()
                body = json.loads(response.read().decode("utf-8"))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            updated_chain = EvidenceChain.load(state_path, tenant_id="approval-server")
            approval_entries = approval_entries_for_contract(updated_chain.entries, contract_hash(contract))

            self.assertEqual(200, response.status, body)
            self.assertTrue(body["ok"])
            self.assertEqual("model_risk", body["role"])
            self.assertEqual(1, len(approval_entries))
            self.assertEqual(body["approval_entry_id"], approval_entries[0]["entry_id"])
            self.assertTrue(updated_chain.verify_all().ok)


    def test_server_slack_callback_endpoint_accepts_signed_form_payload(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            chain = EvidenceChain.load(state_path, tenant_id="approval-server")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            _, pack = self._pack_missing_approvals(chain, contract)
            chain.save()
            request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                callback_url="http://127.0.0.1/v0/approval-callbacks/slack",
            )
            interaction = self._slack_interaction(request)
            secret = "test-slack-signing-secret"
            form = {
                "payload": json.dumps(interaction, separators=(",", ":")),
                "approval_request": json.dumps(request, separators=(",", ":")),
                "contract_path": CONTRACT.name,
                "approved_at": "2026-07-03T13:00:00Z",
            }
            raw_body = urlencode(form).encode("utf-8")
            timestamp = str(int(time.time()))
            signature = self._slack_signature(secret, raw_body, timestamp)
            server = serve("127.0.0.1", 0, str(state_path), "approval-server", slack_signing_secret=secret, input_dir=str(CONTRACT.parent))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request(
                    "POST",
                    "/v0/approval-callbacks/slack",
                    body=raw_body,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Slack-Request-Timestamp": timestamp,
                        "X-Slack-Signature": signature,
                    },
                )
                response = conn.getresponse()
                body = json.loads(response.read().decode("utf-8"))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            updated_chain = EvidenceChain.load(state_path, tenant_id="approval-server")
            approval_entries = approval_entries_for_contract(updated_chain.entries, contract_hash(contract))

            self.assertEqual(200, response.status, body)
            self.assertTrue(body["ok"])
            self.assertEqual("model_risk", body["role"])
            self.assertEqual(1, len(approval_entries))
            self.assertEqual(body["approval_entry_id"], approval_entries[0]["entry_id"])
            self.assertTrue(updated_chain.verify_all().ok)

    def test_server_slack_callback_endpoint_resolves_registered_pending_request(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            store_path = tmp / "approval-requests.json"
            chain = EvidenceChain.load(state_path, tenant_id="approval-server")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            _, pack = self._pack_missing_approvals(chain, contract)
            chain.save()
            request = build_slack_approval_request(
                pack,
                channel="C07TRUSTAI",
                requested_roles=["model_risk"],
                callback_url="http://127.0.0.1/v0/approval-callbacks/slack",
            )
            interaction = self._slack_interaction(request)
            secret = "test-slack-signing-secret"
            server = serve(
                "127.0.0.1",
                0,
                str(state_path),
                "approval-server",
                approval_request_store_path=str(store_path),
                slack_signing_secret=secret,
                input_dir=str(CONTRACT.parent),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request(
                    "POST",
                    "/v0/approval-requests/slack",
                    body=json.dumps({"approval_request": request, "contract_path": CONTRACT.name}),
                    headers={"Content-Type": "application/json"},
                )
                register_response = conn.getresponse()
                register_body = json.loads(register_response.read().decode("utf-8"))
                form = {
                    "payload": json.dumps(interaction, separators=(",", ":")),
                    "approved_at": "2026-07-03T13:00:00Z",
                }
                raw_body = urlencode(form).encode("utf-8")
                timestamp = str(int(time.time()))
                signature = self._slack_signature(secret, raw_body, timestamp)
                conn.request(
                    "POST",
                    "/v0/approval-callbacks/slack",
                    body=raw_body,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Slack-Request-Timestamp": timestamp,
                        "X-Slack-Signature": signature,
                    },
                )
                response = conn.getresponse()
                body = json.loads(response.read().decode("utf-8"))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            updated_chain = EvidenceChain.load(state_path, tenant_id="approval-server")
            approval_entries = approval_entries_for_contract(updated_chain.entries, contract_hash(contract))

            self.assertEqual(200, register_response.status, register_body)
            self.assertEqual(request["approval_request_id"], register_body["approval_request_id"])
            self.assertTrue(store_path.exists())
            self.assertEqual(200, response.status, body)
            self.assertTrue(body["ok"])
            self.assertEqual("pending-store", body["approval_request_source"])
            self.assertEqual("model_risk", body["role"])
            self.assertEqual(1, len(approval_entries))
            self.assertEqual(body["approval_entry_id"], approval_entries[0]["entry_id"])
            self.assertTrue(updated_chain.verify_all().ok)

    def test_server_slack_callback_endpoint_rejects_stale_signed_form_payload(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            chain = EvidenceChain.load(state_path, tenant_id="approval-server")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            _, pack = self._pack_missing_approvals(chain, contract)
            chain.save()
            request = build_slack_approval_request(pack, channel="C07TRUSTAI", requested_roles=["model_risk"])
            interaction = self._slack_interaction(request)
            secret = "test-slack-signing-secret"
            form = {
                "payload": json.dumps(interaction, separators=(",", ":")),
                "approval_request": json.dumps(request, separators=(",", ":")),
                "contract_path": str(CONTRACT),
                "approved_at": "2026-07-03T13:00:00Z",
            }
            raw_body = urlencode(form).encode("utf-8")
            timestamp = str(int(time.time()) - 600)
            signature = self._slack_signature(secret, raw_body, timestamp)
            server = serve(
                "127.0.0.1",
                0,
                str(state_path),
                "approval-server",
                slack_signing_secret=secret,
                slack_replay_window_seconds=300,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request(
                    "POST",
                    "/v0/approval-callbacks/slack",
                    body=raw_body,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Slack-Request-Timestamp": timestamp,
                        "X-Slack-Signature": signature,
                    },
                )
                response = conn.getresponse()
                body = json.loads(response.read().decode("utf-8"))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            updated_chain = EvidenceChain.load(state_path, tenant_id="approval-server")
            approval_entries = approval_entries_for_contract(updated_chain.entries, contract_hash(contract))

            self.assertEqual(422, response.status, body)
            self.assertIn("replay window", body["error"])
            self.assertEqual(0, len(approval_entries))

    def test_callback_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            _, pack = self._pack_missing_approvals(chain, contract)
            request = build_slack_approval_request(pack, channel="C07TRUSTAI", requested_roles=["model_risk"])
            callback = build_approval_callback(
                request,
                role="model_risk",
                approver="model-risk@example.com",
                approved_at="2026-07-03T13:00:00Z",
            )
            tampered = copy.deepcopy(callback)
            tampered["action_value"] = "wrong"

            result = verify_approval_callback(request, tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("action_value" in error or "callback_id" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
