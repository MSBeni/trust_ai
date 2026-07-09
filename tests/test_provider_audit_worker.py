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
from trustai.provider_audit_stream import build_provider_audit_stream_receipt, write_provider_audit_stream_receipt
from trustai.provider_audit_worker import (
    PROVIDER_AUDIT_WORKER_ENTRY_TYPE,
    PROVIDER_AUDIT_WORKER_SCHEMA,
    append_provider_audit_worker_receipt,
    build_provider_audit_worker_receipt,
    verify_provider_audit_worker_receipt,
    write_provider_audit_worker_receipt,
)
from trustai.provider_installation import build_provider_installation_manifest
from trustai.provider_lifecycle import build_provider_lifecycle_manifest, write_provider_lifecycle_manifest
from trustai.provider_lifecycle_operation import build_provider_lifecycle_operation_receipt, write_provider_lifecycle_operation_receipt
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


def _lifecycle(installation: dict) -> dict:
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
        audit_log_ref="github:audit-log:local-window-001",
        correlated_at="2026-07-08T02:06:00Z",
    )


def _stream(audit_log: dict, installation: dict, lifecycle: dict, correlation: dict) -> dict:
    return build_provider_audit_stream_receipt(
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


def _lifecycle_operation(lifecycle: dict) -> dict:
    return build_provider_lifecycle_operation_receipt(
        lifecycle_manifest=lifecycle,
        operation_kind="audit_log_stream_binding",
        operation_ref="github:audit-log-stream:volelabs",
        endpoint_url="https://api.github.com/orgs/volelabs/audit-log",
        credential_ref="env:GITHUB_AUDIT_LOG_TOKEN",
        audit_log_ref="github:audit-log:local-window-001",
        request_hash="sha256:github-audit-log-request",
        response_status=200,
        response_hash="sha256:github-audit-log-response",
        actor_ref="oidc:trustai.example/provider-audit-worker",
        provider_event_ref="github:audit-log-stream:volelabs",
        mode="provider-audit-stream",
        environment="local",
        recorded_at="2026-07-08T02:10:30Z",
    )


def _worker(stream: dict, correlation: dict, lifecycle_operation: dict, lifecycle: dict, **overrides) -> dict:
    values = {
        "stream_receipts": [stream],
        "correlations": [correlation],
        "lifecycle_operation": lifecycle_operation,
        "lifecycle_manifest": lifecycle,
        "worker_ref": "worker:provider-audit/github",
        "run_ref": "worker-run:provider-audit/github/2026-07-08T02:00:00Z",
        "operation_kind": "stream_and_correlate",
        "actor_ref": "oidc:trustai.example/provider-audit-worker",
        "schedule_ref": "schedule:provider-audit/github/10m",
        "cadence_seconds": 600,
        "lease_ref": "lease:provider-audit/github/2026-07-08T02:00:00Z",
        "checkpoint_ref": "checkpoint:provider-audit/github",
        "checkpoint_hash": "sha256:provider-audit-checkpoint",
        "credential_ref": "env:GITHUB_AUDIT_LOG_TOKEN",
        "previous_cursor_ref": "github:audit-cursor:start",
        "next_cursor_ref": "github:audit-cursor:next",
        "attempt": 1,
        "max_attempts": 3,
        "next_run_at": "2026-07-08T02:20:00Z",
        "mode": "provider-authenticated-streamer",
        "environment": "local",
        "started_at": "2026-07-08T02:10:00Z",
        "completed_at": "2026-07-08T02:12:00Z",
    }
    values.update(overrides)
    return build_provider_audit_worker_receipt(**values)


class ProviderAuditWorkerTests(unittest.TestCase):
    def test_provider_audit_worker_verifies_and_appends_to_chain(self):
        audit_log = _audit_log()
        installation = _provider_installation()
        lifecycle = _lifecycle(installation)
        correlation = _correlation(audit_log)
        stream = _stream(audit_log, installation, lifecycle, correlation)
        lifecycle_operation = _lifecycle_operation(lifecycle)
        receipt = _worker(stream, correlation, lifecycle_operation, lifecycle)

        result = verify_provider_audit_worker_receipt(
            receipt,
            stream_receipts=[stream],
            correlations=[correlation],
            lifecycle_operation=lifecycle_operation,
            lifecycle_manifest=lifecycle,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_AUDIT_WORKER_SCHEMA, receipt["schema"])
        self.assertEqual("github", receipt["provider"])
        self.assertEqual("stream_and_correlate", receipt["worker"]["operation_kind"])
        self.assertEqual("env:GITHUB_AUDIT_LOG_TOKEN", receipt["credential"]["ref"])
        self.assertNotIn(WEBHOOK_SECRET, json.dumps(receipt, sort_keys=True))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-audit-worker-test")
            entry = append_provider_audit_worker_receipt(
                chain,
                receipt,
                stream_receipts=[stream],
                correlations=[correlation],
                lifecycle_operation=lifecycle_operation,
                lifecycle_manifest=lifecycle,
            )

            self.assertEqual(PROVIDER_AUDIT_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_audit_worker_rejects_correlation_for_different_stream_audit_log(self):
        audit_log = _audit_log()
        installation = _provider_installation()
        lifecycle = _lifecycle(installation)
        correlation = _correlation(audit_log)
        stream = _stream(audit_log, installation, lifecycle, correlation)
        lifecycle_operation = _lifecycle_operation(lifecycle)
        other_log = _audit_log()
        other_log["events"].append({"provider": "github", "event": "repo.change", "occurred_at": "2026-07-08T02:08:00Z"})
        other_correlation = _correlation(other_log)
        receipt = _worker(stream, other_correlation, lifecycle_operation, lifecycle)

        result = verify_provider_audit_worker_receipt(
            receipt,
            stream_receipts=[stream],
            correlations=[other_correlation],
            lifecycle_operation=lifecycle_operation,
            lifecycle_manifest=lifecycle,
        )

        self.assertFalse(result.ok)
        self.assertIn("provider audit worker correlation audit_log hash does not match any stream receipt audit_log hash", result.errors)

    def test_cli_provider_audit_worker_round_trip(self):
        audit_log = _audit_log()
        installation = _provider_installation()
        lifecycle = _lifecycle(installation)
        correlation = _correlation(audit_log)
        stream = _stream(audit_log, installation, lifecycle, correlation)
        lifecycle_operation = _lifecycle_operation(lifecycle)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            stream_path = tmp / "provider-audit-stream.json"
            correlation_path = tmp / "provider-audit-correlation.json"
            lifecycle_path = tmp / "provider-lifecycle.json"
            lifecycle_operation_path = tmp / "provider-lifecycle-operation.json"
            worker_path = tmp / "provider-audit-worker.json"
            entry_path = tmp / "provider-audit-worker-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_provider_audit_stream_receipt(stream_path, stream)
            write_provider_audit_correlation(correlation_path, correlation)
            write_provider_lifecycle_manifest(lifecycle_path, lifecycle)
            write_provider_lifecycle_operation_receipt(lifecycle_operation_path, lifecycle_operation)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common_sources = [
                "--stream-receipt",
                str(stream_path),
                "--correlation",
                str(correlation_path),
                "--lifecycle-operation",
                str(lifecycle_operation_path),
                "--lifecycle",
                str(lifecycle_path),
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-audit-worker",
                    *common_sources,
                    "--worker-ref",
                    "worker:provider-audit/github",
                    "--run-ref",
                    "worker-run:provider-audit/github/2026-07-08T02:00:00Z",
                    "--operation-kind",
                    "stream_and_correlate",
                    "--actor-ref",
                    "oidc:trustai.example/provider-audit-worker",
                    "--schedule-ref",
                    "schedule:provider-audit/github/10m",
                    "--cadence-seconds",
                    "600",
                    "--lease-ref",
                    "lease:provider-audit/github/2026-07-08T02:00:00Z",
                    "--checkpoint-ref",
                    "checkpoint:provider-audit/github",
                    "--checkpoint-hash",
                    "sha256:provider-audit-checkpoint",
                    "--credential-ref",
                    "env:GITHUB_AUDIT_LOG_TOKEN",
                    "--previous-cursor-ref",
                    "github:audit-cursor:start",
                    "--next-cursor-ref",
                    "github:audit-cursor:next",
                    "--next-run-at",
                    "2026-07-08T02:20:00Z",
                    "--mode",
                    "provider-authenticated-streamer",
                    "--started-at",
                    "2026-07-08T02:10:00Z",
                    "--completed-at",
                    "2026-07-08T02:12:00Z",
                    "--out",
                    str(worker_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-audit-worker-verify", str(worker_path), *common_sources],
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
                    "provider-audit-worker-append",
                    str(worker_path),
                    *common_sources,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-audit-worker-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(worker_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_provider_audit_worker_receipt(
            receipt,
            stream_receipts=[stream],
            correlations=[correlation],
            lifecycle_operation=lifecycle_operation,
            lifecycle_manifest=lifecycle,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])

