import copy
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.delivery import build_provider_delivery, write_provider_delivery
from trustai.provider_audit import build_provider_audit_correlation, write_provider_audit_correlation
from trustai.provider_audit_stream import build_provider_audit_stream_receipt, write_provider_audit_stream_receipt
from trustai.provider_callback_store import (
    PROVIDER_CALLBACK_STORE_ENTRY_TYPE,
    PROVIDER_CALLBACK_STORE_SCHEMA,
    append_provider_callback_store_manifest,
    build_provider_callback_store_manifest,
    verify_provider_callback_store_manifest,
    write_provider_callback_store_manifest,
)
from trustai.provider_installation import build_provider_installation_manifest, write_provider_installation_manifest
from trustai.provider_webhook import build_provider_webhook_receipt, write_provider_webhook_receipt


ROOT = Path(__file__).resolve().parents[1]


def _github_signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _github_headers(secret: str, body: bytes) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _github_signature(secret, body),
        "X-GitHub-Delivery": "delivery-123",
        "X-GitHub-Event": "check_suite",
    }


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


def _delivery() -> dict:
    payload = {
        "schema": "trustai.github-check-run-payload/0.1",
        "provider": "github",
        "pack_id": "pack-123",
        "contract_id": "contract-123",
        "contract_hash": "abc123",
        "request": {
            "method": "POST",
            "path": "/repos/volelabs/trust_ai/check-runs",
            "body": {"name": "TrustAI promotion gate", "status": "completed", "conclusion": "success"},
        },
    }
    payload["payload_hash"] = content_hash(without_keys(payload, "payload_hash"))
    return build_provider_delivery(
        payload,
        endpoint_base="https://api.github.com",
        credential_ref="env:GITHUB_TOKEN",
        mode="recorded-response",
        response_status=201,
        response_body={"id": 123},
        delivered_at="2026-07-08T02:02:00Z",
    )


def _webhook_and_audit(secret: str = "github-webhook-secret") -> tuple[dict, dict]:
    raw_body = b'{"action":"completed","check_suite":{"id":42}}'
    webhook = build_provider_webhook_receipt(
        "github",
        raw_body,
        _github_headers(secret, raw_body),
        secret,
        received_at="2026-07-08T02:00:00Z",
    )
    audit_log = {
        "schema": "github.audit-log-export/2026-07",
        "provider": "github",
        "exported_at": "2026-07-08T02:05:00Z",
        "events": [
            {
                "provider": "github",
                "event": "check_suite",
                "delivery_id": "delivery-123",
                "payload_sha256": hashlib.sha256(raw_body).hexdigest(),
                "occurred_at": "2026-07-08T02:00:01Z",
            }
        ],
    }
    audit = build_provider_audit_correlation(
        audit_log,
        webhook_receipt=webhook,
        provider="github",
        audit_log_ref="github:audit-log:local",
        correlated_at="2026-07-08T02:06:00Z",
    )
    return webhook, audit


def _audit_stream() -> dict:
    audit_log = {
        "schema": "github.audit-log-export/2026-07",
        "provider": "github",
        "exported_at": "2026-07-08T02:05:00Z",
        "events": [
            {
                "provider": "github",
                "event": "check_suite",
                "delivery_id": "delivery-123",
                "payload_sha256": "647e4cf2cef00a3d98232f20cbacabd7e092cf991a4311104fbf0354fe4d1bb3",
                "occurred_at": "2026-07-08T02:00:01Z",
            }
        ],
    }
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
        provider_installation=_installation(),
        mode="provider-audit-stream",
        recorded_at="2026-07-08T02:11:00Z",
    )


class ProviderCallbackStoreTests(unittest.TestCase):
    def test_callback_store_manifest_verifies_and_appends(self):
        secret = "github-webhook-secret"
        webhook, audit = _webhook_and_audit(secret)
        artifacts = [_installation(), webhook, _delivery(), audit, _audit_stream()]

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            db_path = tmp / "provider-callbacks.sqlite"
            manifest = build_provider_callback_store_manifest(
                db_path,
                source_artifacts=artifacts,
                generated_at="2026-07-08T04:00:00Z",
                retention_until="2033-07-08T00:00:00Z",
            )
            result = verify_provider_callback_store_manifest(
                manifest,
                db_path=db_path,
                source_artifacts=artifacts,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(PROVIDER_CALLBACK_STORE_SCHEMA, manifest["schema"])
            self.assertEqual(5, manifest["summary"]["operation_count"])
            self.assertEqual(1, manifest["summary"]["operation_type_counts"]["provider_installation"])
            self.assertEqual(1, manifest["summary"]["operation_type_counts"]["provider_webhook"])
            self.assertEqual(1, manifest["summary"]["operation_type_counts"]["provider_delivery"])
            self.assertEqual(1, manifest["summary"]["operation_type_counts"]["provider_audit_correlation"])
            self.assertEqual(1, manifest["summary"]["operation_type_counts"]["provider_audit_stream"])
            self.assertIn("idx_callback_operations_provider", {item["name"] for item in manifest["database"]["indexes"]})
            manifest_json = json.dumps(manifest, sort_keys=True)
            self.assertNotIn(secret, manifest_json)
            self.assertNotIn("env:GITHUB_TOKEN", manifest_json)
            self.assertNotIn("env:GITHUB_APP_PRIVATE_KEY", manifest_json)

            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="callback-store-test")
            entry = append_provider_callback_store_manifest(
                chain,
                manifest,
                db_path=db_path,
                source_artifacts=artifacts,
            )

            self.assertEqual(PROVIDER_CALLBACK_STORE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(manifest["store_manifest_id"], entry["payload"]["store_manifest_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_callback_store_manifest_rejects_db_index_tamper(self):
        webhook, audit = _webhook_and_audit()
        artifacts = [_installation(), webhook, audit]

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "provider-callbacks.sqlite"
            manifest = build_provider_callback_store_manifest(
                db_path,
                source_artifacts=artifacts,
                generated_at="2026-07-08T04:00:00Z",
            )
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("DROP INDEX idx_callback_operations_provider")
                conn.commit()
            finally:
                conn.close()

            result = verify_provider_callback_store_manifest(
                manifest,
                db_path=db_path,
                source_artifacts=artifacts,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("required index missing" in error or "indexes" in error for error in result.errors))

    def test_callback_store_manifest_requires_source_artifact_replay(self):
        webhook, audit = _webhook_and_audit()
        artifacts = [_installation(), webhook, audit]

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "provider-callbacks.sqlite"
            manifest = build_provider_callback_store_manifest(
                db_path,
                source_artifacts=artifacts,
                generated_at="2026-07-08T04:00:00Z",
            )

            result = verify_provider_callback_store_manifest(manifest, db_path=db_path)

            self.assertFalse(result.ok)
            self.assertTrue(any("source artifacts are required" in error for error in result.errors), result.errors)

    def test_callback_store_manifest_rejects_source_artifact_mismatch(self):
        webhook, audit = _webhook_and_audit()
        artifacts = [_installation(), webhook, audit]

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "provider-callbacks.sqlite"
            manifest = build_provider_callback_store_manifest(
                db_path,
                source_artifacts=artifacts,
                generated_at="2026-07-08T04:00:00Z",
            )
            tampered = copy.deepcopy(artifacts)
            tampered[0]["installation"]["repository"] = "volelabs/other"

            result = verify_provider_callback_store_manifest(
                manifest,
                db_path=db_path,
                source_artifacts=tampered,
            )

            self.assertFalse(result.ok)
            self.assertIn("provider callback store source artifact summaries do not match supplied artifacts", result.errors)

    def test_cli_provider_callback_store_round_trip(self):
        webhook, audit = _webhook_and_audit()
        installation = _installation()
        delivery = _delivery()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            installation_path = tmp / "provider-installation.json"
            webhook_path = tmp / "provider-webhook.json"
            delivery_path = tmp / "provider-delivery.json"
            audit_path = tmp / "provider-audit.json"
            audit_stream_path = tmp / "provider-audit-stream.json"
            manifest_path = tmp / "provider-callback-store.json"
            entry_path = tmp / "provider-callback-store-entry.json"
            db_path = tmp / "provider-callbacks.sqlite"
            state_path = tmp / "evidence-chain.json"
            write_provider_installation_manifest(installation_path, installation)
            write_provider_webhook_receipt(webhook_path, webhook)
            write_provider_delivery(delivery_path, delivery)
            write_provider_audit_correlation(audit_path, audit)
            write_provider_audit_stream_receipt(audit_stream_path, _audit_stream())
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            artifact_args = [
                "--artifact",
                str(installation_path),
                "--artifact",
                str(webhook_path),
                "--artifact",
                str(delivery_path),
                "--artifact",
                str(audit_path),
                "--artifact",
                str(audit_stream_path),
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-callback-store",
                    "--db",
                    str(db_path),
                    *artifact_args,
                    "--generated-at",
                    "2026-07-08T04:00:00Z",
                    "--retention-until",
                    "2033-07-08T00:00:00Z",
                    "--out",
                    str(manifest_path),
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
                    "provider-callback-store-verify",
                    str(manifest_path),
                    "--db",
                    str(db_path),
                    *artifact_args,
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
                    "provider-callback-store-append",
                    str(manifest_path),
                    "--db",
                    str(db_path),
                    *artifact_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-callback-store-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            result = verify_provider_callback_store_manifest(
                manifest,
                db_path=db_path,
                source_artifacts=[installation, webhook, delivery, audit, _audit_stream()],
            )
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(manifest["store_manifest_id"], entry["payload"]["store_manifest_id"])


if __name__ == "__main__":
    unittest.main()
