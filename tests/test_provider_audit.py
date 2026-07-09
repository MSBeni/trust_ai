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
from trustai.provider_audit import (
    PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE,
    PROVIDER_AUDIT_CORRELATION_SCHEMA,
    append_provider_audit_correlation,
    build_provider_audit_correlation,
    verify_provider_audit_correlation,
    write_provider_audit_correlation,
)
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


def _github_audit_log(body: bytes) -> dict:
    return {
        "schema": "github.audit-log-export/2026-07",
        "provider": "github",
        "exported_at": "2026-07-08T02:05:00Z",
        "events": [
            {
                "provider": "github",
                "event": "check_suite",
                "delivery_id": "delivery-123",
                "payload_sha256": hashlib.sha256(body).hexdigest(),
                "occurred_at": "2026-07-08T02:00:01Z",
                "actor": "github-actions",
                "repository": "volelabs/trust_ai",
            }
        ],
    }


class ProviderAuditCorrelationTests(unittest.TestCase):
    def test_webhook_audit_correlation_verifies_and_appends_to_chain(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        webhook = build_provider_webhook_receipt(
            "github",
            raw_body,
            _github_headers(secret, raw_body),
            secret,
            received_at="2026-07-08T02:00:00Z",
        )
        audit_log = _github_audit_log(raw_body)

        correlation = build_provider_audit_correlation(
            audit_log,
            webhook_receipt=webhook,
            provider="github",
            audit_log_ref="github:audit-log:local",
            correlated_at="2026-07-08T02:06:00Z",
        )
        result = verify_provider_audit_correlation(
            correlation,
            audit_log=audit_log,
            webhook_receipt=webhook,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_AUDIT_CORRELATION_SCHEMA, correlation["schema"])
        self.assertEqual("github", correlation["provider"])
        self.assertEqual(webhook["receipt_id"], correlation["source_receipts"][0]["source_id"])
        self.assertEqual(1, len(correlation["matches"]))
        self.assertEqual("payload_sha256", correlation["matches"][0]["criteria"][-1]["field"])
        self.assertNotIn(secret, json.dumps(correlation, sort_keys=True))
        self.assertNotIn(_github_headers(secret, raw_body)["X-Hub-Signature-256"], json.dumps(correlation, sort_keys=True))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-audit-test")
            entry = append_provider_audit_correlation(
                chain,
                correlation,
                audit_log=audit_log,
                webhook_receipt=webhook,
            )

            self.assertEqual(PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(correlation["correlation_id"], entry["payload"]["correlation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_webhook_audit_correlation_rejects_mismatched_audit_log(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        webhook = build_provider_webhook_receipt(
            "github",
            raw_body,
            _github_headers(secret, raw_body),
            secret,
            received_at="2026-07-08T02:00:00Z",
        )
        audit_log = _github_audit_log(raw_body)
        audit_log["events"][0]["payload_sha256"] = "0" * 64

        with self.assertRaises(ValueError):
            build_provider_audit_correlation(audit_log, webhook_receipt=webhook, provider="github")

    def test_cli_provider_audit_correlation_round_trip(self):
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        webhook = build_provider_webhook_receipt(
            "github",
            raw_body,
            _github_headers(secret, raw_body),
            secret,
            received_at="2026-07-08T02:00:00Z",
        )
        audit_log = _github_audit_log(raw_body)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            audit_path = tmp / "github-audit-log.json"
            webhook_path = tmp / "provider-webhook.json"
            correlation_path = tmp / "provider-audit-correlation.json"
            entry_path = tmp / "provider-audit-entry.json"
            state_path = tmp / "evidence-chain.json"
            audit_path.write_text(json.dumps(audit_log), encoding="utf-8")
            write_provider_webhook_receipt(webhook_path, webhook)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-audit-correlation",
                    str(audit_path),
                    "--webhook-receipt",
                    str(webhook_path),
                    "--provider",
                    "github",
                    "--audit-log-ref",
                    "github:audit-log:local",
                    "--correlated-at",
                    "2026-07-08T02:06:00Z",
                    "--out",
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
                    "provider-audit-verify",
                    str(correlation_path),
                    "--audit-log",
                    str(audit_path),
                    "--webhook-receipt",
                    str(webhook_path),
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
                    "provider-audit-append",
                    str(correlation_path),
                    "--audit-log",
                    str(audit_path),
                    "--webhook-receipt",
                    str(webhook_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-audit-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            correlation = json.loads(correlation_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_provider_audit_correlation(correlation, audit_log=audit_log, webhook_receipt=webhook)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(correlation["correlation_id"], entry["payload"]["correlation_id"])


if __name__ == "__main__":
    unittest.main()
