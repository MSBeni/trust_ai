import copy
import hashlib
import http.server
import json
import os
import subprocess
import sys
import threading
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.cicd import (
    PROMOTION_STATUS_ENTRY_TYPE,
    PROMOTION_STATUS_SCHEMA,
    append_promotion_status_receipt,
    build_promotion_check_payload,
    build_promotion_status_receipt,
    build_slack_approval_request,
    verify_promotion_status_receipt,
)
from trustai.delivery import (
    PROVIDER_DELIVERY_ENTRY_TYPE,
    PROVIDER_DELIVERY_SCHEMA,
    append_provider_delivery,
    build_provider_delivery,
    dispatch_provider_payload,
    verify_provider_delivery,
)
from trustai.verifier import load_proof_pack, verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class _ProviderDispatchHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        self.server.calls.append(
            {
                "path": self.path,
                "body": json.loads(raw_body),
                "authorization": self.headers.get("Authorization"),
                "content_type": self.headers.get("Content-Type"),
            }
        )
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Request-Id", "local-dispatch-1")
        self.end_headers()
        self.wfile.write(b'{"ok":true,"id":"local-dispatch-1"}')

    def log_message(self, format, *args):
        return


class ProviderDeliveryTests(unittest.TestCase):
    def _pack(self) -> dict:
        return load_proof_pack(PACK)

    def test_github_delivery_receipt_verifies_and_appends_to_chain(self):
        pack = self._pack()
        payload = build_promotion_check_payload(
            pack,
            verify_proof_pack(pack),
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            mode="dry-run",
            delivered_at="2026-07-04T00:00:00Z",
        )

        result = verify_provider_delivery(delivery, payload)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_DELIVERY_SCHEMA, delivery["schema"])
        self.assertEqual("github", delivery["provider"])
        self.assertEqual("dry-run", delivery["mode"])
        self.assertTrue(delivery["credential"]["redacted"])
        self.assertIn("dry-run", " ".join(result.warnings))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="delivery-test")
            entry = append_provider_delivery(chain, delivery, payload)

            self.assertEqual(PROVIDER_DELIVERY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(delivery["delivery_id"], entry["payload"]["delivery_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_delivery_replays_retained_payload_artifact_bytes(self):
        pack = self._pack()
        payload = build_promotion_check_payload(
            pack,
            verify_proof_pack(pack),
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload_path = Path(tmp_dir) / "payload.json"
            payload_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            delivery = build_provider_delivery(
                payload,
                endpoint_base="https://api.github.com",
                credential_ref="env:GITHUB_TOKEN",
                mode="dry-run",
                delivered_at="2026-07-04T00:00:00Z",
                payload_artifact_path=payload_path,
            )

            artifact = delivery["payload_artifact"]
            result = verify_provider_delivery(delivery, payload, payload_artifact_path=payload_path)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(hashlib.sha256(payload_path.read_bytes()).hexdigest(), artifact["sha256"])
            self.assertEqual(payload_path.stat().st_size, artifact["size_bytes"])
            self.assertEqual(content_hash(payload), artifact["content_hash"])
            self.assertEqual(payload["payload_hash"], artifact["payload_hash"])

            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="delivery-artifact-test")
            entry = append_provider_delivery(chain, delivery, payload, payload_artifact_path=payload_path)

            self.assertEqual(artifact, entry["payload"]["payload_artifact"])
            self.assertTrue(chain.verify_all().ok)

    def test_delivery_detects_retained_payload_artifact_byte_tamper(self):
        pack = self._pack()
        payload = build_promotion_check_payload(
            pack,
            verify_proof_pack(pack),
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload_path = Path(tmp_dir) / "payload.json"
            payload_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            delivery = build_provider_delivery(
                payload,
                endpoint_base="https://api.github.com",
                credential_ref="env:GITHUB_TOKEN",
                mode="dry-run",
                delivered_at="2026-07-04T00:00:00Z",
                payload_artifact_path=payload_path,
            )
            payload_path.write_text(json.dumps(payload, indent=4, sort_keys=True), encoding="utf-8")

            result = verify_provider_delivery(delivery, payload, payload_artifact_path=payload_path)

            self.assertFalse(result.ok)
            self.assertTrue(any("payload_artifact" in error and "bytes" in error for error in result.errors))


    def test_promotion_status_receipt_binds_gate_payload_and_delivery(self):
        pack = self._pack()
        verification = verify_proof_pack(pack)
        payload = build_promotion_check_payload(
            pack,
            verification,
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            mode="dry-run",
            delivered_at="2026-07-04T00:00:00Z",
        )
        receipt = build_promotion_status_receipt(
            pack,
            verification,
            payload,
            delivery=delivery,
            attested_at="2026-07-04T00:01:00Z",
        )

        result = verify_promotion_status_receipt(
            receipt,
            proof_pack=pack,
            verification=verification,
            payload=payload,
            delivery=delivery,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROMOTION_STATUS_SCHEMA, receipt["schema"])
        self.assertTrue(receipt["passed"])
        self.assertEqual("github", receipt["provider"])
        self.assertTrue(receipt["source"]["provider_status_matches_gate"])
        self.assertTrue(receipt["source"]["delivery_verified"])
        self.assertTrue(receipt["source"]["delivery_payload_matches"])

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="promotion-status-test")
            entry = append_promotion_status_receipt(
                chain,
                receipt,
                proof_pack=pack,
                verification=verification,
                payload=payload,
                delivery=delivery,
            )

            self.assertEqual(PROMOTION_STATUS_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertTrue(chain.verify_all().ok)


    def test_gitlab_promotion_status_receipt_binds_project_commit_ref(self):
        pack = self._pack()
        verification = verify_proof_pack(pack)
        payload = build_promotion_check_payload(
            pack,
            verification,
            provider="gitlab",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="123456",
            branch="main",
            target_url="https://example.test/proof-pack",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://gitlab.example/api/v4",
            credential_ref="env:GITLAB_TOKEN",
            mode="dry-run",
            delivered_at="2026-07-04T00:00:00Z",
        )
        receipt = build_promotion_status_receipt(
            pack,
            verification,
            payload,
            delivery=delivery,
            attested_at="2026-07-04T00:01:00Z",
        )
        result = verify_promotion_status_receipt(
            receipt,
            proof_pack=pack,
            verification=verification,
            payload=payload,
            delivery=delivery,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertTrue(receipt["passed"])
        self.assertTrue(receipt["source"]["provider_status_shape_valid"])
        self.assertTrue(receipt["source"]["provider_target_ref_bound"])
        self.assertEqual("123456", receipt["provider_payload"]["target_ref"]["project_ref"])
        self.assertEqual("0123456789abcdef0123456789abcdef01234567", receipt["provider_payload"]["target_ref"]["commit_sha"])
    def test_promotion_status_receipt_requires_concrete_provider_target_ref(self):
        pack = self._pack()
        verification = verify_proof_pack(pack)
        payload = build_promotion_check_payload(
            pack,
            verification,
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            target_url="https://example.test/proof-pack",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            mode="dry-run",
            delivered_at="2026-07-04T00:00:00Z",
        )
        receipt = build_promotion_status_receipt(
            pack,
            verification,
            payload,
            delivery=delivery,
            attested_at="2026-07-04T00:01:00Z",
        )

        result = verify_promotion_status_receipt(
            receipt,
            proof_pack=pack,
            verification=verification,
            payload=payload,
            delivery=delivery,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(receipt["passed"])
        self.assertFalse(receipt["source"]["provider_target_ref_bound"])
        self.assertEqual(":owner/:repo", receipt["provider_payload"]["target_ref"]["repository"])
        self.assertTrue(any(item["check"] == "provider_target_ref_bound" for item in receipt["violations"]))
        self.assertTrue(result.warnings)

    def test_promotion_status_receipt_requires_valid_provider_commit_sha(self):
        pack = self._pack()
        verification = verify_proof_pack(pack)
        payload = build_promotion_check_payload(
            pack,
            verification,
            provider="github",
            commit_sha="not-a-sha",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            mode="dry-run",
            delivered_at="2026-07-04T00:00:00Z",
        )
        receipt = build_promotion_status_receipt(
            pack,
            verification,
            payload,
            delivery=delivery,
            attested_at="2026-07-04T00:01:00Z",
        )

        result = verify_promotion_status_receipt(
            receipt,
            proof_pack=pack,
            verification=verification,
            payload=payload,
            delivery=delivery,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(receipt["passed"])
        self.assertFalse(receipt["source"]["provider_status_shape_valid"])
        self.assertFalse(receipt["source"]["provider_target_ref_bound"])
        self.assertFalse(receipt["provider_payload"]["target_ref"]["commit_sha_bound"])
        self.assertTrue(any(item["check"] == "provider_status_shape_valid" for item in receipt["violations"]))
        self.assertTrue(any(item["check"] == "provider_target_ref_bound" for item in receipt["violations"]))
        self.assertTrue(result.warnings)

    def test_promotion_status_receipt_detects_status_payload_tamper(self):
        pack = self._pack()
        verification = verify_proof_pack(pack)
        payload = build_promotion_check_payload(
            pack,
            verification,
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            mode="dry-run",
            delivered_at="2026-07-04T00:00:00Z",
        )
        receipt = build_promotion_status_receipt(
            pack,
            verification,
            payload,
            delivery=delivery,
            attested_at="2026-07-04T00:01:00Z",
        )
        tampered_payload = copy.deepcopy(payload)
        tampered_payload["request"]["body"]["conclusion"] = "failure"
        tampered_payload["payload_hash"] = content_hash(without_keys(tampered_payload, "payload_hash"))

        result = verify_promotion_status_receipt(
            receipt,
            proof_pack=pack,
            verification=verification,
            payload=tampered_payload,
            delivery=delivery,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("promotion status" in error and "mismatch" in error for error in result.errors))


    def test_cli_promotion_status_round_trip(self):
        pack = self._pack()
        verification = verify_proof_pack(pack)
        payload = build_promotion_check_payload(
            pack,
            verification,
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            mode="dry-run",
            delivered_at="2026-07-04T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            payload_path = tmp_path / "payload.json"
            delivery_path = tmp_path / "delivery.json"
            receipt_path = tmp_path / "promotion-status.json"
            entry_path = tmp_path / "promotion-status-entry.json"
            state_path = tmp_path / "chain.json"
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            delivery_path.write_text(json.dumps(delivery), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "promotion-status",
                    str(PACK),
                    str(payload_path),
                    "--delivery",
                    str(delivery_path),
                    "--attested-at",
                    "2026-07-04T00:01:00Z",
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "promotion-status-verify",
                    str(receipt_path),
                    "--pack",
                    str(PACK),
                    "--payload",
                    str(payload_path),
                    "--delivery",
                    str(delivery_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "promotion-status-append",
                    str(receipt_path),
                    "--pack",
                    str(PACK),
                    "--payload",
                    str(payload_path),
                    "--delivery",
                    str(delivery_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "promotion-status-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertEqual(PROMOTION_STATUS_ENTRY_TYPE, entry["entry_type"])

    def test_slack_recorded_response_delivery_verifies(self):
        pack = self._pack()
        payload = build_slack_approval_request(
            pack,
            channel="C07TRUSTAI",
            requested_roles=["model_risk"],
            requester="risk@example.com",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://slack.com",
            credential_ref="env:SLACK_BOT_TOKEN",
            mode="recorded-response",
            response_status=200,
            response_body={"ok": True, "ts": "1720011600.000100"},
            delivered_at="2026-07-04T00:00:00Z",
        )

        result = verify_provider_delivery(delivery, payload)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("slack", delivery["provider"])
        self.assertTrue(delivery["response"]["accepted"])

    def test_http_dispatch_posts_payload_and_binds_response_without_secret(self):
        pack = self._pack()
        payload = build_promotion_check_payload(
            pack,
            verify_proof_pack(pack),
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        server = http.server.HTTPServer(("127.0.0.1", 0), _ProviderDispatchHandler)
        server.calls = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        old_token = os.environ.get("TRUSTAI_TEST_PROVIDER_TOKEN")
        os.environ["TRUSTAI_TEST_PROVIDER_TOKEN"] = "secret-token"
        try:
            delivery = dispatch_provider_payload(
                payload,
                endpoint_base=f"http://127.0.0.1:{server.server_port}",
                credential_ref="env:TRUSTAI_TEST_PROVIDER_TOKEN",
                timeout_seconds=5,
                delivered_at="2026-07-04T00:00:00Z",
            )
        finally:
            if old_token is None:
                os.environ.pop("TRUSTAI_TEST_PROVIDER_TOKEN", None)
            else:
                os.environ["TRUSTAI_TEST_PROVIDER_TOKEN"] = old_token
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        result = verify_provider_delivery(delivery, payload)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("http-dispatch", delivery["mode"])
        self.assertTrue(delivery["response"]["accepted"])
        self.assertEqual(202, delivery["response"]["status"])
        self.assertEqual(1, len(server.calls))
        self.assertEqual(payload["request"]["path"], server.calls[0]["path"])
        self.assertEqual("Bearer secret-token", server.calls[0]["authorization"])
        self.assertEqual(payload["request"]["body"], server.calls[0]["body"])
        self.assertIn("headers_hash", delivery["request"])
        self.assertIn("headers_hash", delivery["response"])
        self.assertNotIn("secret-token", json.dumps(delivery, sort_keys=True))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="delivery-dispatch-test")
            entry = append_provider_delivery(chain, delivery, payload)

            self.assertEqual(PROVIDER_DELIVERY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual("http-dispatch", entry["payload"]["mode"])
            self.assertTrue(chain.verify_all().ok)


    def test_cli_send_dispatch_receipt_verifies(self):
        pack = self._pack()
        payload = build_promotion_check_payload(
            pack,
            verify_proof_pack(pack),
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
        )
        server = http.server.HTTPServer(("127.0.0.1", 0), _ProviderDispatchHandler)
        server.calls = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                payload_path = tmp_path / "payload.json"
                delivery_path = tmp_path / "delivery.json"
                payload_path.write_text(json.dumps(payload), encoding="utf-8")
                env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "TRUSTAI_TEST_PROVIDER_TOKEN": "secret-token"}
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "trustai",
                        "provider-delivery",
                        str(payload_path),
                        "--endpoint-base",
                        f"http://127.0.0.1:{server.server_port}",
                        "--credential-ref",
                        "env:TRUSTAI_TEST_PROVIDER_TOKEN",
                        "--send",
                        "--timeout-seconds",
                        "5",
                        "--out",
                        str(delivery_path),
                    ],
                    cwd=ROOT,
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                delivery = json.loads(delivery_path.read_text(encoding="utf-8"))
                self.assertIn("payload_artifact", delivery)
                self.assertEqual(hashlib.sha256(payload_path.read_bytes()).hexdigest(), delivery["payload_artifact"]["sha256"])
                path_result = verify_provider_delivery(delivery, payload, payload_artifact_path=payload_path)
                self.assertTrue(path_result.ok, path_result.errors)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        result = verify_provider_delivery(delivery, payload)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("http-dispatch", delivery["mode"])
        self.assertEqual(202, delivery["response"]["status"])
        self.assertEqual(1, len(server.calls))


    def test_delivery_payload_tamper_is_rejected(self):
        pack = self._pack()
        payload = build_promotion_check_payload(
            pack,
            verify_proof_pack(pack),
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
        )
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            delivered_at="2026-07-04T00:00:00Z",
        )
        tampered_payload = copy.deepcopy(payload)
        tampered_payload["request"]["body"]["conclusion"] = "failure"

        result = verify_provider_delivery(delivery, tampered_payload)

        self.assertFalse(result.ok)
        self.assertTrue(any("payload_hash" in error or "body_hash" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
