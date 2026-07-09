import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.policy_backend_enforcement import (
    POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE,
    POLICY_BACKEND_ENFORCEMENT_SCHEMA,
    append_policy_backend_enforcement_receipt,
    build_policy_backend_enforcement_receipt,
    verify_policy_backend_enforcement_receipt,
)
from trustai.policy_engine import build_policy_engine_receipt, write_policy_engine_receipt
from trustai.policy_export import export_policy_pack, write_policy_export
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class PolicyBackendEnforcementTests(unittest.TestCase):
    def _fixtures(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="policy-backend-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        action = load_action(ACTION)
        append_runtime_attestation(chain, contract, action)
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        policy = load_policy_pack(POLICY)
        policy_decision = append_policy_decision(
            chain,
            policy,
            action,
            proof_pack=pack,
            now="2026-07-04T02:00:00Z",
        )
        policy_export = export_policy_pack(policy)
        engine_receipt = build_policy_engine_receipt(
            policy,
            action,
            pack,
            policy_decision,
            policy_export=policy_export,
            engine="opa",
            evaluated_at="2026-07-04T02:00:00Z",
        )
        return chain, policy, action, pack, policy_decision, policy_export, engine_receipt

    def _receipt(self, policy, action, pack, policy_decision, policy_export, engine_receipt, **overrides):
        values = {
            "policy_pack": policy,
            "action": action,
            "proof_pack": pack,
            "decision": policy_decision,
            "policy_export": policy_export,
            "policy_engine_receipt": engine_receipt,
            "backend_ref": "opa:trustai-runtime:prod",
            "engine": "opa",
            "endpoint_url": "https://opa.example/v1/data/trustai/runtime/allow",
            "credential_ref": "env:OPA_BACKEND_TOKEN",
            "request_hash": "sha256:policy-backend-request",
            "response_status": 200,
            "response_hash": "sha256:policy-backend-response",
            "actor_ref": "oidc:trustai.example/runtime-policy",
            "latency_ms": 18,
            "evidence_refs": ["evidence:policy-backend/opa-runtime"],
            "mode": "hosted-backend",
            "environment": "local",
            "enforced_at": "2026-07-04T02:00:01Z",
        }
        values.update(overrides)
        return build_policy_backend_enforcement_receipt(**values)

    def test_policy_backend_enforcement_verifies_and_appends_to_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, policy, action, pack, policy_decision, policy_export, engine_receipt = self._fixtures(Path(tmp_dir))
            receipt = self._receipt(policy, action, pack, policy_decision, policy_export, engine_receipt)

            result = verify_policy_backend_enforcement_receipt(
                receipt,
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                policy_engine_receipt=engine_receipt,
            )
            entry = append_policy_backend_enforcement_receipt(
                chain,
                receipt,
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                policy_engine_receipt=engine_receipt,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_BACKEND_ENFORCEMENT_SCHEMA, receipt["schema"])
            self.assertEqual("hosted-backend", receipt["mode"])
            self.assertEqual("opa", receipt["backend"]["engine"])
            self.assertEqual("env:OPA_BACKEND_TOKEN", receipt["credential"]["ref"])
            self.assertTrue(receipt["backend_decision"]["matches_policy_decision"])
            self.assertEqual(POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["enforcement_id"], entry["payload"]["enforcement_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_policy_backend_enforcement_rejects_insecure_hosted_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, policy, action, pack, policy_decision, policy_export, engine_receipt = self._fixtures(Path(tmp_dir))
            receipt = self._receipt(policy, action, pack, policy_decision, policy_export, engine_receipt)
            tampered = copy.deepcopy(receipt)
            tampered["backend"]["endpoint_url"] = "http://opa.example/v1/data/trustai/runtime/allow"

            result = verify_policy_backend_enforcement_receipt(
                tampered,
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                policy_engine_receipt=engine_receipt,
            )

            self.assertFalse(result.ok)
            self.assertIn("policy backend enforcement backend.endpoint_url must use HTTPS", result.errors)

    def test_policy_backend_enforcement_rejects_backend_decision_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, policy, action, pack, policy_decision, policy_export, engine_receipt = self._fixtures(Path(tmp_dir))
            receipt = self._receipt(
                policy,
                action,
                pack,
                policy_decision,
                policy_export,
                engine_receipt,
                response_allowed=False,
                response_outcome="denied",
            )

            result = verify_policy_backend_enforcement_receipt(
                receipt,
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                policy_engine_receipt=engine_receipt,
            )

            self.assertFalse(result.ok)
            self.assertIn("policy backend enforcement backend outcome does not match policy decision", result.errors)
            self.assertIn("policy backend enforcement backend allowed flag does not match policy decision", result.errors)

    def test_cli_policy_backend_enforcement_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, policy, action, pack, policy_decision, policy_export, engine_receipt = self._fixtures(tmp)
            pack_path = tmp / "pack.json"
            decision_path = tmp / "policy-decision.json"
            export_path = tmp / "policy-export.json"
            engine_receipt_path = tmp / "policy-engine-receipt.json"
            receipt_path = tmp / "policy-backend-enforcement.json"
            entry_path = tmp / "policy-backend-enforcement-entry.json"
            state_path = tmp / "policy-backend-chain.json"
            _write_json(pack_path, pack)
            _write_json(decision_path, policy_decision)
            write_policy_export(export_path, policy_export)
            write_policy_engine_receipt(engine_receipt_path, engine_receipt)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common = [
                str(POLICY),
                str(ACTION),
                "--pack",
                str(pack_path),
                "--decision",
                str(decision_path),
                "--export",
                str(export_path),
                "--policy-engine-receipt",
                str(engine_receipt_path),
            ]
            backend_args = [
                "--backend-ref",
                "opa:trustai-runtime:prod",
                "--engine",
                "opa",
                "--endpoint-url",
                "https://opa.example/v1/data/trustai/runtime/allow",
                "--credential-ref",
                "env:OPA_BACKEND_TOKEN",
                "--request-hash",
                "sha256:policy-backend-request",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:policy-backend-response",
                "--actor-ref",
                "oidc:trustai.example/runtime-policy",
                "--latency-ms",
                "18",
                "--evidence-ref",
                "evidence:policy-backend/opa-runtime",
                "--mode",
                "hosted-backend",
                "--enforced-at",
                "2026-07-04T02:00:01Z",
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-enforcement",
                    *common,
                    *backend_args,
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-enforcement-verify",
                    str(receipt_path),
                    *common,
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-enforcement-append",
                    str(receipt_path),
                    *common,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(receipt_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
