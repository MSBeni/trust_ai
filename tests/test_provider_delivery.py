import copy
import http.server
import json
import os
import subprocess
import sys
import threading
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.cicd import build_promotion_check_payload, build_slack_approval_request
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
