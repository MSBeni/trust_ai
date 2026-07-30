import hashlib
import hmac
import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_webhook import (
    PROVIDER_WEBHOOK_ENTRY_TYPE,
    PROVIDER_WEBHOOK_SCHEMA,
    append_provider_webhook_receipt,
    build_provider_webhook_receipt,
    verify_provider_webhook_receipt,
)
from trustai.provider_webhook_store import load_provider_webhook_store
from trustai.server import serve


ROOT = Path(__file__).resolve().parents[1]


def _sha256_ref(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _github_signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _github_headers(secret: str, body: bytes) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _github_signature(secret, body),
        "X-GitHub-Delivery": "delivery-123",
        "X-GitHub-Event": "check_suite",
    }


class ProviderWebhookTests(unittest.TestCase):
    def test_github_webhook_receipt_verifies_and_appends_to_chain(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        headers = _github_headers(secret, raw_body)
        receipt = build_provider_webhook_receipt(
            "github",
            raw_body,
            headers,
            secret,
            received_at="2026-07-08T00:00:00Z",
        )

        result = verify_provider_webhook_receipt(receipt, raw_body, headers=headers, secret=secret)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_WEBHOOK_SCHEMA, receipt["schema"])
        self.assertEqual("github", receipt["provider"])
        self.assertEqual("check_suite", receipt["webhook"]["event"])
        self.assertEqual("delivery-123", receipt["webhook"]["delivery_id"])
        self.assertNotIn(secret, json.dumps(receipt, sort_keys=True))
        self.assertNotIn(headers["X-Hub-Signature-256"], json.dumps(receipt, sort_keys=True))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="webhook-test")
            entry = append_provider_webhook_receipt(chain, receipt, raw_body, headers=headers, secret=secret)

            self.assertEqual(PROVIDER_WEBHOOK_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_github_webhook_replays_payload_artifact_bytes(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        headers = _github_headers(secret, raw_body)

        with tempfile.TemporaryDirectory() as tmp_dir:
            body_path = Path(tmp_dir) / "github-webhook.json"
            body_path.write_bytes(raw_body)
            receipt = build_provider_webhook_receipt(
                "github",
                raw_body,
                headers,
                secret,
                received_at="2026-07-08T00:00:00Z",
                body_artifact_path=body_path,
            )
            result = verify_provider_webhook_receipt(receipt, raw_body, headers=headers, secret=secret, body_artifact_path=body_path)
            artifact_sha = _sha256_ref(body_path)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(artifact_sha, receipt["payload_artifact"]["sha256"])
        self.assertEqual(len(raw_body), receipt["payload_artifact"]["size_bytes"])

    def test_github_webhook_payload_artifact_path_is_checkout_relative_when_possible(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        headers = _github_headers(secret, raw_body)

        with tempfile.TemporaryDirectory(dir=ROOT) as tmp_dir:
            body_path = Path(tmp_dir) / "github-webhook.json"
            body_path.write_bytes(raw_body)
            receipt = build_provider_webhook_receipt(
                "github",
                raw_body,
                headers,
                secret,
                received_at="2026-07-08T00:00:00Z",
                body_artifact_path=body_path,
            )

            self.assertEqual(body_path.relative_to(ROOT).as_posix(), receipt["payload_artifact"]["path"])
            self.assertTrue(
                verify_provider_webhook_receipt(
                    receipt,
                    raw_body,
                    headers=headers,
                    secret=secret,
                    body_artifact_path=body_path,
                ).ok
            )

    def test_github_webhook_detects_payload_artifact_byte_tamper(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        equivalent_body = b'{\n  "action": "completed",\n  "check_suite": {\n    "id": 42\n  }\n}'
        secret = "github-webhook-secret"
        headers = _github_headers(secret, raw_body)

        with tempfile.TemporaryDirectory() as tmp_dir:
            body_path = Path(tmp_dir) / "github-webhook.json"
            body_path.write_bytes(raw_body)
            receipt = build_provider_webhook_receipt(
                "github",
                raw_body,
                headers,
                secret,
                received_at="2026-07-08T00:00:00Z",
                body_artifact_path=body_path,
            )
            body_path.write_bytes(equivalent_body)
            result = verify_provider_webhook_receipt(receipt, raw_body, headers=headers, secret=secret, body_artifact_path=body_path)

        self.assertFalse(result.ok)
        errors = "\n".join(result.errors)
        self.assertIn("payload_artifact", errors)
        self.assertIn("bytes", errors)

    def test_github_webhook_bad_signature_is_rejected(self):
        raw_body = b'{"action":"completed"}'
        secret = "github-webhook-secret"
        headers = _github_headers(secret, raw_body)
        headers["X-Hub-Signature-256"] = "sha256=" + "0" * 64

        with self.assertRaises(ValueError):
            build_provider_webhook_receipt("github", raw_body, headers, secret)

    def test_gitlab_webhook_receipt_verifies_without_leaking_token(self):
        raw_body = b'{"object_kind":"pipeline","object_attributes":{"id":99}}'
        secret = "gitlab-webhook-secret"
        headers = {
            "Content-Type": "application/json",
            "X-Gitlab-Token": secret,
            "X-Gitlab-Event": "Pipeline Hook",
            "X-Gitlab-Webhook-UUID": "gitlab-hook-123",
        }
        receipt = build_provider_webhook_receipt(
            "gitlab",
            raw_body,
            headers,
            secret,
            received_at="2026-07-08T01:00:00Z",
        )

        result = verify_provider_webhook_receipt(receipt, raw_body, headers=headers, secret=secret)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("gitlab", receipt["provider"])
        self.assertEqual("Pipeline Hook", receipt["webhook"]["event"])
        self.assertEqual("gitlab-shared-token", receipt["verification"]["method"])
        self.assertNotIn(secret, json.dumps(receipt, sort_keys=True))

    def test_server_provider_webhook_endpoint_appends_receipt(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        headers = _github_headers(secret, raw_body)
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            store_path = tmp / "provider-webhooks.json"
            server = serve(
                "127.0.0.1",
                0,
                str(state_path),
                "webhook-server",
                provider_webhook_store_path=str(store_path),
                github_webhook_secret=secret,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request("POST", "/v0/provider-webhooks/github", body=raw_body, headers=headers)
                response = conn.getresponse()
                response_body = json.loads(response.read().decode("utf-8"))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            updated_chain = EvidenceChain.load(state_path, tenant_id="webhook-server")
            entries = [entry for entry in updated_chain.entries if entry["entry_type"] == PROVIDER_WEBHOOK_ENTRY_TYPE]

            self.assertEqual(200, response.status, response_body)
            self.assertTrue(response_body["ok"])
            self.assertEqual("github", response_body["provider"])
            self.assertEqual("check_suite", response_body["event"])
            self.assertEqual(1, len(entries))
            self.assertEqual(response_body["webhook_entry_id"], entries[0]["entry_id"])
            self.assertTrue(updated_chain.verify_all().ok)

    def test_server_provider_webhook_endpoint_deduplicates_retries(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        headers = _github_headers(secret, raw_body)
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            store_path = tmp / "provider-webhooks.json"
            server = serve(
                "127.0.0.1",
                0,
                str(state_path),
                "webhook-server",
                provider_webhook_store_path=str(store_path),
                github_webhook_secret=secret,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request("POST", "/v0/provider-webhooks/github", body=raw_body, headers=headers)
                first_response = conn.getresponse()
                first_body = json.loads(first_response.read().decode("utf-8"))
                conn.request("POST", "/v0/provider-webhooks/github", body=raw_body, headers=headers)
                second_response = conn.getresponse()
                second_body = json.loads(second_response.read().decode("utf-8"))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            updated_chain = EvidenceChain.load(state_path, tenant_id="webhook-server")
            entries = [entry for entry in updated_chain.entries if entry["entry_type"] == PROVIDER_WEBHOOK_ENTRY_TYPE]
            store = load_provider_webhook_store(store_path)
            store_json = json.dumps(store, sort_keys=True)

            self.assertEqual(200, first_response.status, first_body)
            self.assertEqual(200, second_response.status, second_body)
            self.assertFalse(first_body["duplicate"])
            self.assertTrue(second_body["duplicate"])
            self.assertEqual(first_body["receipt_id"], second_body["receipt_id"])
            self.assertEqual(first_body["webhook_entry_id"], second_body["webhook_entry_id"])
            self.assertEqual(first_body["dedup_key"], second_body["dedup_key"])
            self.assertEqual(1, len(entries))
            self.assertEqual(1, len(store["webhooks"]))
            self.assertNotIn(secret, store_json)
            self.assertNotIn(headers["X-Hub-Signature-256"], store_json)
            self.assertTrue(updated_chain.verify_all().ok)
    def test_cli_provider_webhook_receipt_verifies(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        headers = _github_headers(secret, raw_body)
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            body_path = tmp / "github-webhook.json"
            receipt_path = tmp / "provider-webhook.json"
            body_path.write_bytes(raw_body)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common_headers = [
                "--header",
                f"Content-Type: {headers['Content-Type']}",
                "--header",
                f"X-Hub-Signature-256: {headers['X-Hub-Signature-256']}",
                "--header",
                f"X-GitHub-Delivery: {headers['X-GitHub-Delivery']}",
                "--header",
                f"X-GitHub-Event: {headers['X-GitHub-Event']}",
            ]
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-webhook",
                    "github",
                    str(body_path),
                    "--secret",
                    secret,
                    *common_headers,
                    "--received-at",
                    "2026-07-08T02:00:00Z",
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
                    "provider-webhook-verify",
                    str(receipt_path),
                    str(body_path),
                    "--secret",
                    secret,
                    *common_headers,
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            entry_path = tmp / "provider-webhook-entry.json"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-webhook-append",
                    str(receipt_path),
                    str(body_path),
                    "--secret",
                    secret,
                    *common_headers,
                    "--state",
                    str(tmp / "chain.json"),
                    "--tenant",
                    "provider-webhook-cli-test",
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
            result = verify_provider_webhook_receipt(
                receipt,
                raw_body,
                headers=headers,
                secret=secret,
                body_artifact_path=body_path,
            )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("github", receipt["provider"])
        self.assertEqual(hashlib.sha256(raw_body).hexdigest(), receipt["payload_artifact"]["sha256"])
        self.assertEqual(receipt["payload_artifact"]["sha256"], entry["payload"]["payload_artifact"]["sha256"])


if __name__ == "__main__":
    unittest.main()
