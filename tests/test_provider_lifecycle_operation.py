import copy
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
from trustai.provider_installation import build_provider_installation_manifest
from trustai.provider_lifecycle import build_provider_lifecycle_manifest, write_provider_lifecycle_manifest
from trustai.provider_lifecycle_operation import (
    PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE,
    PROVIDER_LIFECYCLE_OPERATION_SCHEMA,
    append_provider_lifecycle_operation_receipt,
    build_provider_lifecycle_operation_receipt,
    verify_provider_lifecycle_operation_receipt,
)
from trustai.server import serve


ROOT = Path(__file__).resolve().parents[1]


def _installation() -> dict:
    return build_provider_installation_manifest(
        provider="github",
        app_ref="github-app:trustai-local",
        installation_ref="github-installation:123456",
        tenant_ref="github-org:volelabs",
        owner="volelabs",
        repository="volelabs/trust_ai",
        mode="app-installation",
        app_url="https://github.com/apps/trustai-local",
        webhook_url="https://trustai.example/v0/provider-webhooks/github",
        callback_url="https://trustai.example/v0/provider-callbacks/github",
        permissions=["checks:write", "metadata:read"],
        events=["check_suite", "check_run"],
        secret_ref="env:GITHUB_WEBHOOK_SECRET",
        credential_ref="env:GITHUB_APP_PRIVATE_KEY",
        audit_log_ref="github:org-audit-log:volelabs",
        audit_log_scopes=["read:audit_log"],
        installed_at="2026-07-08T03:00:00Z",
    )


def _lifecycle() -> dict:
    return build_provider_lifecycle_manifest(
        provider_installation=_installation(),
        lifecycle_ref="lifecycle:github-app:trustai-local",
        oauth_callback_url="https://trustai.example/v0/provider-oauth/github/callback",
        authorization_ref="oauth:github:authorization:local",
        token_exchange_ref="oauth:github:token-exchange:local",
        token_store_ref="secret:provider-token-store/github",
        refresh_policy_ref="policy:provider-token-refresh",
        credential_rotation_ref="rotation:github-app-private-key:2026-07",
        revocation_endpoint="https://api.github.com/app/installations/123456/access_tokens",
        revocation_ref="revocation:github-installation:123456",
        uninstall_ref="uninstall:github-installation:123456",
        audit_log_stream_ref="github:audit-log-stream:volelabs",
        mode="byoc-reference",
        environment="test",
        generated_at="2026-07-08T04:30:00Z",
    )


def _operation(lifecycle: dict, **overrides) -> dict:
    values = {
        "lifecycle_manifest": lifecycle,
        "operation_kind": "token_exchange",
        "operation_ref": "oauth:github:token-exchange:local",
        "endpoint_url": "https://github.com/login/oauth/access_token",
        "credential_ref": "env:GITHUB_APP_CLIENT_SECRET",
        "token_ref": "secret:provider-token-store/github",
        "request_hash": "sha256:github-token-exchange-request",
        "response_status": 200,
        "response_hash": "sha256:github-token-exchange-response",
        "actor_ref": "oidc:trustai.example/provider-worker",
        "provider_event_ref": "github:oauth-token-exchange:local",
        "mode": "recorded-provider-response",
        "environment": "test",
        "recorded_at": "2026-07-08T04:31:00Z",
    }
    values.update(overrides)
    return build_provider_lifecycle_operation_receipt(**values)


class ProviderLifecycleOperationTests(unittest.TestCase):
    def test_provider_lifecycle_operation_receipt_verifies_and_appends(self):
        lifecycle = _lifecycle()
        receipt = _operation(lifecycle)

        result = verify_provider_lifecycle_operation_receipt(receipt, lifecycle_manifest=lifecycle)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_LIFECYCLE_OPERATION_SCHEMA, receipt["schema"])
        self.assertEqual("github", receipt["provider"])
        self.assertEqual("token_exchange", receipt["operation"]["kind"])
        self.assertTrue(receipt["credential"]["redacted"])
        self.assertTrue(receipt["token_store"]["redacted"])
        receipt_json = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("github-token-secret", receipt_json)
        self.assertNotIn("client-secret-value", receipt_json)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-lifecycle-operation-test")
            entry = append_provider_lifecycle_operation_receipt(chain, receipt, lifecycle_manifest=lifecycle)

            self.assertEqual(PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["operation_receipt_id"], entry["payload"]["operation_receipt_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_lifecycle_operation_rejects_non_https_endpoint(self):
        lifecycle = _lifecycle()
        receipt = _operation(lifecycle, endpoint_url="http://github.com/login/oauth/access_token")

        result = verify_provider_lifecycle_operation_receipt(receipt, lifecycle_manifest=lifecycle)

        self.assertFalse(result.ok)
        self.assertIn("provider lifecycle operation endpoint_url must use HTTPS", result.errors)

    def test_provider_lifecycle_operation_rejects_lifecycle_mismatch(self):
        lifecycle = _lifecycle()
        receipt = _operation(lifecycle, operation_ref="oauth:github:other-token-exchange")

        result = verify_provider_lifecycle_operation_receipt(receipt, lifecycle_manifest=lifecycle)

        self.assertFalse(result.ok)
        self.assertIn("provider lifecycle operation kind/ref is not declared by supplied lifecycle manifest", result.errors)

    def test_provider_lifecycle_operation_rejects_raw_credential(self):
        lifecycle = _lifecycle()
        receipt = _operation(lifecycle)
        tampered = copy.deepcopy(receipt)
        tampered["credential"] = "client-secret-value"

        result = verify_provider_lifecycle_operation_receipt(tampered, lifecycle_manifest=lifecycle)

        self.assertFalse(result.ok)
        self.assertTrue(any("redacted reference" in error for error in result.errors))

    def test_cli_provider_lifecycle_operation_round_trip(self):
        lifecycle = _lifecycle()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            lifecycle_path = tmp / "provider-lifecycle.json"
            receipt_path = tmp / "provider-lifecycle-operation.json"
            entry_path = tmp / "provider-lifecycle-operation-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_provider_lifecycle_manifest(lifecycle_path, lifecycle)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            lifecycle_arg = ["--lifecycle", str(lifecycle_path)]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-lifecycle-operation",
                    *lifecycle_arg,
                    "--operation-kind",
                    "token_exchange",
                    "--operation-ref",
                    "oauth:github:token-exchange:local",
                    "--provider-event-ref",
                    "github:oauth-token-exchange:local",
                    "--endpoint-url",
                    "https://github.com/login/oauth/access_token",
                    "--credential-ref",
                    "env:GITHUB_APP_CLIENT_SECRET",
                    "--token-ref",
                    "secret:provider-token-store/github",
                    "--request-hash",
                    "sha256:github-token-exchange-request",
                    "--response-status",
                    "200",
                    "--response-hash",
                    "sha256:github-token-exchange-response",
                    "--actor-ref",
                    "oidc:trustai.example/provider-worker",
                    "--mode",
                    "recorded-provider-response",
                    "--environment",
                    "test",
                    "--recorded-at",
                    "2026-07-08T04:31:00Z",
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
                    "provider-lifecycle-operation-verify",
                    str(receipt_path),
                    *lifecycle_arg,
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
                    "provider-lifecycle-operation-append",
                    str(receipt_path),
                    *lifecycle_arg,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-lifecycle-operation-cli",
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

        result = verify_provider_lifecycle_operation_receipt(receipt, lifecycle_manifest=lifecycle)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(receipt["operation_receipt_id"], entry["payload"]["operation_receipt_id"])



    def test_server_provider_lifecycle_operation_endpoint_appends_receipt(self):
        lifecycle = _lifecycle()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            server = serve(
                "127.0.0.1",
                0,
                str(state_path),
                "provider-lifecycle-operation-server",
                provider_lifecycle_operation_token="operation-token",
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            body = json.dumps(
                {
                    "lifecycle": lifecycle,
                    "operation_kind": "token_exchange",
                    "operation_ref": "oauth:github:token-exchange:local",
                    "provider_event_ref": "github:oauth-token-exchange:server",
                    "endpoint_url": "https://github.com/login/oauth/access_token",
                    "credential_ref": "env:GITHUB_APP_CLIENT_SECRET",
                    "token_ref": "secret:provider-token-store/github",
                    "request_body": {"code": "oauth-code-redacted", "redirect_uri": "https://trustai.example/v0/provider-oauth/github/callback"},
                    "response_status": 200,
                    "response_body": {"access_token": "redacted-by-hash", "scope": "metadata"},
                    "actor_ref": "oidc:trustai.example/provider-worker",
                    "mode": "recorded-provider-response",
                    "environment": "test",
                    "recorded_at": "2026-07-08T04:32:00Z",
                }
            ).encode("utf-8")
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request(
                    "POST",
                    "/v0/provider-lifecycle-operations",
                    body=body,
                    headers={"Content-Type": "application/json", "Authorization": "Bearer operation-token"},
                )
                response = conn.getresponse()
                response_body = json.loads(response.read().decode("utf-8"))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            updated_chain = EvidenceChain.load(state_path, tenant_id="provider-lifecycle-operation-server")
            entries = [entry for entry in updated_chain.entries if entry["entry_type"] == PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE]

            self.assertEqual(200, response.status, response_body)
            self.assertTrue(response_body["ok"])
            self.assertEqual(1, len(entries))
            self.assertEqual(response_body["operation_entry_id"], entries[0]["entry_id"])
            self.assertEqual(response_body["operation_receipt_id"], entries[0]["payload"]["operation_receipt_id"])
            self.assertTrue(response_body["receipt"]["operation"]["request_hash"].startswith("sha256:"))
            self.assertTrue(response_body["receipt"]["operation"]["response_hash"].startswith("sha256:"))
            self.assertTrue(updated_chain.verify_all().ok)

    def test_server_provider_lifecycle_operation_endpoint_requires_token(self):
        lifecycle = _lifecycle()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            server = serve(
                "127.0.0.1",
                0,
                str(state_path),
                "provider-lifecycle-operation-server",
                provider_lifecycle_operation_token="operation-token",
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            body = json.dumps({"lifecycle": lifecycle}).encode("utf-8")
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request("POST", "/v0/provider-lifecycle-operations", body=body, headers={"Content-Type": "application/json"})
                response = conn.getresponse()
                response_body = json.loads(response.read().decode("utf-8"))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            updated_chain = EvidenceChain.load(state_path, tenant_id="provider-lifecycle-operation-server")

            self.assertEqual(401, response.status, response_body)
            self.assertFalse(response_body["ok"])
            self.assertEqual([], updated_chain.entries)

if __name__ == "__main__":
    unittest.main()
