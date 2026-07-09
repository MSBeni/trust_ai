import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_audit import build_provider_audit_correlation, write_provider_audit_correlation
from trustai.provider_audit_stream import (
    PROVIDER_AUDIT_STREAM_ENTRY_TYPE,
    PROVIDER_AUDIT_STREAM_SCHEMA,
    append_provider_audit_stream_receipt,
    build_provider_audit_stream_receipt,
    verify_provider_audit_stream_receipt,
)
from trustai.provider_installation import build_provider_installation_manifest, write_provider_installation_manifest
from trustai.provider_lifecycle import build_provider_lifecycle_manifest, write_provider_lifecycle_manifest
from trustai.provider_webhook import build_provider_webhook_receipt


ROOT = Path(__file__).resolve().parents[1]
WEBHOOK_BODY = b'{"action":"completed","check_suite":{"id":42}}'
WEBHOOK_SECRET = "local-github-webhook-secret"


def _github_signature() -> str:
    return "sha256=" + hmac.new(WEBHOOK_SECRET.encode("utf-8"), WEBHOOK_BODY, hashlib.sha256).hexdigest()


def _audit_log() -> dict:
    return {
        "schema": "github.audit-log-export/2026-07",
        "provider": "github",
        "exported_at": "2026-07-08T02:05:00Z",
        "events": [
            {
                "provider": "github",
                "event": "check_suite",
                "delivery_id": "delivery-123",
                "payload_sha256": hashlib.sha256(WEBHOOK_BODY).hexdigest(),
                "occurred_at": "2026-07-08T02:00:01Z",
                "actor": "github-actions",
                "repository": "volelabs/trust_ai",
            }
        ],
    }


def _provider_installation() -> dict:
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
        events=["check_suite"],
        secret_ref="env:GITHUB_WEBHOOK_SECRET",
        credential_ref="env:GITHUB_APP_PRIVATE_KEY",
        audit_log_ref="github:org-audit-log:volelabs",
        audit_log_scopes=["read:audit_log"],
        installed_at="2026-07-08T03:00:00Z",
    )


def _provider_lifecycle(installation: dict) -> dict:
    return build_provider_lifecycle_manifest(
        provider_installation=installation,
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
        environment="local",
        generated_at="2026-07-08T04:30:00Z",
    )


def _correlation(audit_log: dict) -> dict:
    webhook = build_provider_webhook_receipt(
        "github",
        WEBHOOK_BODY,
        {
            "X-Hub-Signature-256": _github_signature(),
            "X-GitHub-Delivery": "delivery-123",
            "X-GitHub-Event": "check_suite",
        },
        WEBHOOK_SECRET,
        received_at="2026-07-08T02:00:00Z",
    )
    return build_provider_audit_correlation(
        audit_log,
        webhook_receipt=webhook,
        provider="github",
        audit_log_ref="github:audit-log:local",
        correlated_at="2026-07-08T02:06:00Z",
    )


class ProviderAuditStreamTests(unittest.TestCase):
    def test_audit_stream_receipt_verifies_and_appends_to_chain(self):
        audit_log = _audit_log()
        installation = _provider_installation()
        lifecycle = _provider_lifecycle(installation)
        correlation = _correlation(audit_log)

        receipt = build_provider_audit_stream_receipt(
            audit_log,
            provider="github",
            stream_ref="github:audit-log-stream:volelabs",
            audit_log_ref="github:audit-log:local-window-001",
            endpoint_url="https://api.github.com/orgs/volelabs/audit-log",
            credential_ref="env:GITHUB_AUDIT_LOG_TOKEN",
            request_hash="sha256:github-audit-log-request",
            response_status=200,
            response_hash="sha256:github-audit-log-response",
            actor_ref="oidc:trustai.example/provider-audit-worker",
            window_start="2026-07-08T02:00:00Z",
            window_end="2026-07-08T02:10:00Z",
            cursor_ref="github:audit-cursor:start",
            next_cursor_ref="github:audit-cursor:next",
            provider_installation=installation,
            lifecycle_manifest=lifecycle,
            correlation=correlation,
            mode="provider-audit-stream",
            environment="local",
            recorded_at="2026-07-08T02:11:00Z",
        )
        result = verify_provider_audit_stream_receipt(
            receipt,
            audit_log=audit_log,
            provider_installation=installation,
            lifecycle_manifest=lifecycle,
            correlation=correlation,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_AUDIT_STREAM_SCHEMA, receipt["schema"])
        self.assertEqual("github", receipt["provider"])
        self.assertEqual(1, receipt["audit_log"]["event_count"])
        self.assertEqual("env:GITHUB_AUDIT_LOG_TOKEN", receipt["credential"]["ref"])
        self.assertNotIn("local-github-webhook-secret", json.dumps(receipt, sort_keys=True))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-audit-stream-test")
            entry = append_provider_audit_stream_receipt(
                chain,
                receipt,
                audit_log=audit_log,
                provider_installation=installation,
                lifecycle_manifest=lifecycle,
                correlation=correlation,
            )
            self.assertEqual(PROVIDER_AUDIT_STREAM_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["stream_receipt_id"], entry["payload"]["stream_receipt_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_audit_stream_rejects_mismatched_audit_log(self):
        audit_log = _audit_log()
        receipt = build_provider_audit_stream_receipt(
            audit_log,
            provider="github",
            stream_ref="github:audit-log-stream:volelabs",
            endpoint_url="https://api.github.com/orgs/volelabs/audit-log",
            credential_ref="env:GITHUB_AUDIT_LOG_TOKEN",
            request_hash="sha256:github-audit-log-request",
            response_status=200,
            response_hash="sha256:github-audit-log-response",
            actor_ref="oidc:trustai.example/provider-audit-worker",
            window_start="2026-07-08T02:00:00Z",
            window_end="2026-07-08T02:10:00Z",
        )
        changed = _audit_log()
        changed["events"].append({"provider": "github", "event": "repo.change", "occurred_at": "2026-07-08T02:09:00Z"})
        result = verify_provider_audit_stream_receipt(receipt, audit_log=changed)

        self.assertFalse(result.ok)
        self.assertIn("provider audit stream audit log hash does not match supplied audit log", result.errors)

    def test_cli_provider_audit_stream_round_trip(self):
        audit_log = _audit_log()
        installation = _provider_installation()
        lifecycle = _provider_lifecycle(installation)
        correlation = _correlation(audit_log)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            audit_path = tmp / "github-audit-log.json"
            installation_path = tmp / "provider-installation.json"
            lifecycle_path = tmp / "provider-lifecycle.json"
            correlation_path = tmp / "provider-audit-correlation.json"
            receipt_path = tmp / "provider-audit-stream.json"
            entry_path = tmp / "provider-audit-stream-entry.json"
            state_path = tmp / "evidence-chain.json"
            audit_path.write_text(json.dumps(audit_log), encoding="utf-8")
            write_provider_installation_manifest(installation_path, installation)
            write_provider_lifecycle_manifest(lifecycle_path, lifecycle)
            write_provider_audit_correlation(correlation_path, correlation)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-audit-stream",
                    str(audit_path),
                    "--provider",
                    "github",
                    "--stream-ref",
                    "github:audit-log-stream:volelabs",
                    "--audit-log-ref",
                    "github:audit-log:local-window-001",
                    "--endpoint-url",
                    "https://api.github.com/orgs/volelabs/audit-log",
                    "--credential-ref",
                    "env:GITHUB_AUDIT_LOG_TOKEN",
                    "--request-hash",
                    "sha256:github-audit-log-request",
                    "--response-status",
                    "200",
                    "--response-hash",
                    "sha256:github-audit-log-response",
                    "--actor-ref",
                    "oidc:trustai.example/provider-audit-worker",
                    "--window-start",
                    "2026-07-08T02:00:00Z",
                    "--window-end",
                    "2026-07-08T02:10:00Z",
                    "--cursor-ref",
                    "github:audit-cursor:start",
                    "--next-cursor-ref",
                    "github:audit-cursor:next",
                    "--provider-installation",
                    str(installation_path),
                    "--lifecycle",
                    str(lifecycle_path),
                    "--correlation",
                    str(correlation_path),
                    "--mode",
                    "provider-audit-stream",
                    "--recorded-at",
                    "2026-07-08T02:11:00Z",
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
                    "provider-audit-stream-verify",
                    str(receipt_path),
                    "--audit-log",
                    str(audit_path),
                    "--provider-installation",
                    str(installation_path),
                    "--lifecycle",
                    str(lifecycle_path),
                    "--correlation",
                    str(correlation_path),
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
                    "provider-audit-stream-append",
                    str(receipt_path),
                    "--audit-log",
                    str(audit_path),
                    "--provider-installation",
                    str(installation_path),
                    "--lifecycle",
                    str(lifecycle_path),
                    "--correlation",
                    str(correlation_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-audit-stream-cli",
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

        result = verify_provider_audit_stream_receipt(
            receipt,
            audit_log=audit_log,
            provider_installation=installation,
            lifecycle_manifest=lifecycle,
            correlation=correlation,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(receipt["stream_receipt_id"], entry["payload"]["stream_receipt_id"])


if __name__ == "__main__":
    unittest.main()
