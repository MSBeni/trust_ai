import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.policy_backend_provider import (
    POLICY_BACKEND_PROVIDER_ENTRY_TYPE,
    POLICY_BACKEND_PROVIDER_SCHEMA,
    append_policy_backend_provider_receipt,
    build_policy_backend_provider_receipt,
    verify_policy_backend_provider_receipt,
)

from tests import test_policy_backend_worker as worker_fixtures


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class PolicyBackendProviderTests(unittest.TestCase):
    def _sources(self, tmp: Path) -> dict[str, object]:
        helper = worker_fixtures.PolicyBackendWorkerTests()
        sources = helper._source_dict(tmp)
        worker_receipt = helper._receipt(sources)
        sources["worker_receipt"] = worker_receipt
        sources["provider_export"] = self._provider_export(worker_receipt)
        return sources

    def _provider_export(self, worker_receipt: dict) -> dict:
        worker = worker_receipt["worker"]
        scheduler = worker_receipt["scheduler"]
        execution = worker_receipt["execution"]
        observability = worker_receipt["observability"]
        source = worker_receipt["source_enforcement"]
        run_ref = worker["run_ref"]
        return {
            "schema": "trustai.policy-backend-provider-export/0.1",
            "provider": "aws-scheduler-sqs-dynamodb-s3-cloudtrail-opa",
            "environment": "aitrade-prod",
            "export_ref": "provider-export:policy-backend/opa/action-123",
            "window_start": "2026-07-04T04:05:00Z",
            "window_end": "2026-07-04T04:06:00Z",
            "cursor_ref": "cursor:policy-backend/provider/before-action-123",
            "next_cursor_ref": "cursor:policy-backend/provider/after-action-123",
            "audit_log_ref": "audit-log:policy-backend/provider-export",
            "audit_log_root": "sha256:policy-backend-provider-export-audit-root",
            "scheduler_records": [
                {
                    "record_id": "scheduler:policy-backend/opa/action-123",
                    "worker_run_ref": run_ref,
                    "schedule_ref": scheduler["schedule_ref"],
                    "lease_ref": scheduler["lease_ref"],
                    "checkpoint_ref": scheduler["checkpoint_ref"],
                    "checkpoint_hash": scheduler["checkpoint_hash"],
                    "previous_cursor_ref": scheduler["previous_cursor_ref"],
                    "next_cursor_ref": scheduler["next_cursor_ref"],
                    "next_run_at": scheduler["next_run_at"],
                }
            ],
            "queue_records": [
                {
                    "record_id": "queue:policy-backend/opa/action-123",
                    "worker_run_ref": run_ref,
                    "queue_ref": execution["queue_ref"],
                    "queue_message_ref": execution["queue_message_ref"],
                    "queue_message_hash": execution["queue_message_hash"],
                    "dead_letter_queue_ref": execution["dead_letter_queue_ref"],
                    "ack_ref": "ack:policy-backend/opa/action-123",
                    "ack_hash": "sha256:policy-backend-provider-queue-ack",
                }
            ],
            "lease_records": [
                {
                    "record_id": "lease:policy-backend/opa/action-123",
                    "worker_run_ref": run_ref,
                    "lease_ref": scheduler["lease_ref"],
                    "checkpoint_ref": scheduler["checkpoint_ref"],
                    "checkpoint_hash": scheduler["checkpoint_hash"],
                    "previous_cursor_ref": scheduler["previous_cursor_ref"],
                    "next_cursor_ref": scheduler["next_cursor_ref"],
                    "owner_ref": worker["actor_ref"],
                    "expires_at": "2026-07-04T04:06:00Z",
                }
            ],
            "backend_records": [
                {
                    "record_id": "backend:policy-backend/opa/action-123",
                    "worker_run_ref": run_ref,
                    "backend_ref": execution["backend_ref"],
                    "engine": execution["engine"],
                    "endpoint_url": execution["endpoint_url"],
                    "bundle_ref": execution["bundle_ref"],
                    "bundle_hash": execution["bundle_hash"],
                    "backend_request_ref": execution["backend_request_ref"],
                    "request_hash": execution["request_hash"],
                    "response_status": execution["response_status"],
                    "response_hash": execution["response_hash"],
                    "response_accepted": execution["response_accepted"],
                    "decision_hash": source["decision_hash"],
                }
            ],
            "decision_log_records": [
                {
                    "record_id": "decision-log:policy-backend/opa/action-123",
                    "worker_run_ref": run_ref,
                    "decision_log_ref": observability["decision_log_ref"],
                    "decision_log_root": observability["decision_log_root"],
                    "decision_record_hash": observability["decision_record_hash"],
                    "decision_hash": source["decision_hash"],
                    "log_object_ref": "s3:policy-backend/decision-log/opa/action-123.json",
                    "log_object_hash": "sha256:policy-backend-provider-decision-log-object",
                }
            ],
            "audit_records": [
                {
                    "record_id": "audit:policy-backend/opa/action-123",
                    "worker_run_ref": run_ref,
                    "audit_log_ref": observability["audit_log_ref"],
                    "audit_log_root": observability["audit_log_root"],
                    "metrics_ref": observability["metrics_ref"],
                }
            ],
        }

    def _receipt(self, sources: dict[str, object], **overrides) -> dict:
        values = {
            "provider_export": sources["provider_export"],
            "worker_receipt": sources["worker_receipt"],
            "service_attestation": sources["attestation"],
            "enforcement_receipt": sources["enforcement"],
            "policy_pack": sources["policy"],
            "action": sources["action"],
            "proof_pack": sources["pack"],
            "decision": sources["policy_decision"],
            "policy_export": sources["policy_export"],
            "policy_engine_receipt": sources["engine_receipt"],
            "mode": "provider-export",
            "environment": "aitrade-prod",
            "provider": "aws-scheduler-sqs-dynamodb-s3-cloudtrail-opa",
            "endpoint_url": "https://provider.example/aitrade/policy-backend/exports",
            "credential_ref": "env:POLICY_BACKEND_PROVIDER_EXPORT_TOKEN",
            "request_hash": "sha256:policy-backend-provider-export-request",
            "response_status": 200,
            "response_hash": "sha256:policy-backend-provider-export-response",
            "actor_ref": "oidc:trustai.example/policy-backend-provider-exporter",
            "exported_at": "2026-07-04T04:06:00Z",
        }
        values.update(overrides)
        return build_policy_backend_provider_receipt(**values)

    def test_policy_backend_provider_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            result = verify_policy_backend_provider_receipt(
                receipt,
                provider_export=sources["provider_export"],
                worker_receipt=sources["worker_receipt"],
                service_attestation=sources["attestation"],
                enforcement_receipt=sources["enforcement"],
                policy_pack=sources["policy"],
                action=sources["action"],
                proof_pack=sources["pack"],
                decision=sources["policy_decision"],
                policy_export=sources["policy_export"],
                policy_engine_receipt=sources["engine_receipt"],
            )
            entry = append_policy_backend_provider_receipt(
                sources["chain"],
                receipt,
                provider_export=sources["provider_export"],
                worker_receipt=sources["worker_receipt"],
                service_attestation=sources["attestation"],
                enforcement_receipt=sources["enforcement"],
                policy_pack=sources["policy"],
                action=sources["action"],
                proof_pack=sources["pack"],
                decision=sources["policy_decision"],
                policy_export=sources["policy_export"],
                policy_engine_receipt=sources["engine_receipt"],
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_BACKEND_PROVIDER_SCHEMA, receipt["schema"])
            self.assertEqual("provider-export", receipt["mode"])
            self.assertEqual(receipt["worker_binding"]["worker_operation_id"], sources["worker_receipt"]["worker_operation_id"])
            self.assertEqual(POLICY_BACKEND_PROVIDER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["provider_receipt_id"], entry["payload"]["provider_receipt_id"])
            self.assertTrue(sources["chain"].verify_all().ok)

    def test_policy_backend_provider_requires_replay_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)

            missing_both = verify_policy_backend_provider_receipt(receipt)
            missing_worker = verify_policy_backend_provider_receipt(
                receipt,
                provider_export=sources["provider_export"],
            )
            missing_export = verify_policy_backend_provider_receipt(
                receipt,
                worker_receipt=sources["worker_receipt"],
                service_attestation=sources["attestation"],
                enforcement_receipt=sources["enforcement"],
                policy_pack=sources["policy"],
                action=sources["action"],
                proof_pack=sources["pack"],
                decision=sources["policy_decision"],
                policy_export=sources["policy_export"],
                policy_engine_receipt=sources["engine_receipt"],
            )

            self.assertFalse(missing_both.ok)
            self.assertTrue(any("worker artifact is required" in error for error in missing_both.errors), missing_both.errors)
            self.assertTrue(any("export artifact is required" in error for error in missing_both.errors), missing_both.errors)
            self.assertFalse(missing_worker.ok)
            self.assertTrue(any("worker artifact is required" in error for error in missing_worker.errors), missing_worker.errors)
            self.assertFalse(missing_export.ok)
            self.assertTrue(any("export artifact is required" in error for error in missing_export.errors), missing_export.errors)

    def test_policy_backend_provider_rejects_provider_export_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            tampered = copy.deepcopy(sources["provider_export"])
            tampered["backend_records"][0]["response_hash"] = "sha256:other-policy-backend-response"

            result = verify_policy_backend_provider_receipt(
                receipt,
                provider_export=tampered,
                worker_receipt=sources["worker_receipt"],
                service_attestation=sources["attestation"],
                enforcement_receipt=sources["enforcement"],
                policy_pack=sources["policy"],
                action=sources["action"],
                proof_pack=sources["pack"],
                decision=sources["policy_decision"],
                policy_export=sources["policy_export"],
                policy_engine_receipt=sources["engine_receipt"],
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("provider export hash does not match" in error for error in result.errors), result.errors)
            self.assertTrue(any("backend record response_hash does not match" in error for error in result.errors), result.errors)

    def test_policy_backend_provider_rejects_raw_credential(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            receipt["credential"] = "raw-provider-token"

            result = verify_policy_backend_provider_receipt(
                receipt,
                provider_export=sources["provider_export"],
                worker_receipt=sources["worker_receipt"],
                service_attestation=sources["attestation"],
                enforcement_receipt=sources["enforcement"],
                policy_pack=sources["policy"],
                action=sources["action"],
                proof_pack=sources["pack"],
                decision=sources["policy_decision"],
                policy_export=sources["policy_export"],
                policy_engine_receipt=sources["engine_receipt"],
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("credential must be a redacted reference" in error for error in result.errors), result.errors)
            self.assertTrue(any("secret-like field" in error for error in result.errors), result.errors)

    def test_cli_policy_backend_provider_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            receipt_path = tmp / "policy-backend-provider-export.json"
            entry_path = tmp / "policy-backend-provider-export-entry.json"
            state_path = tmp / "chain-provider.json"
            provider_export_path = tmp / "provider-export.json"
            worker_path = tmp / "worker.json"
            attestation_path = tmp / "attestation.json"
            enforcement_path = tmp / "enforcement.json"
            pack_path = tmp / "pack.json"
            decision_path = tmp / "decision.json"
            export_path = tmp / "policy-export.json"
            engine_receipt_path = tmp / "engine-receipt.json"

            for path, value in (
                (provider_export_path, sources["provider_export"]),
                (worker_path, sources["worker_receipt"]),
                (attestation_path, sources["attestation"]),
                (enforcement_path, sources["enforcement"]),
                (pack_path, sources["pack"]),
                (decision_path, sources["policy_decision"]),
                (export_path, sources["policy_export"]),
                (engine_receipt_path, sources["engine_receipt"]),
            ):
                _write_json(path, value)

            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            common = [
                str(provider_export_path),
                str(worker_path),
                str(attestation_path),
                str(enforcement_path),
                str(worker_fixtures.POLICY),
                str(worker_fixtures.ACTION),
                "--pack",
                str(pack_path),
                "--decision",
                str(decision_path),
                "--export",
                str(export_path),
                "--policy-engine-receipt",
                str(engine_receipt_path),
            ]
            provider_args = [
                "--mode",
                "provider-export",
                "--environment",
                "aitrade-prod",
                "--provider",
                "aws-scheduler-sqs-dynamodb-s3-cloudtrail-opa",
                "--endpoint-url",
                "https://provider.example/aitrade/policy-backend/exports",
                "--credential-ref",
                "env:POLICY_BACKEND_PROVIDER_EXPORT_TOKEN",
                "--request-hash",
                "sha256:policy-backend-provider-export-request",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:policy-backend-provider-export-response",
                "--actor-ref",
                "oidc:trustai.example/policy-backend-provider-exporter",
                "--exported-at",
                "2026-07-04T04:06:00Z",
            ]

            subprocess.run([sys.executable, "-m", "trustai", "policy-backend-provider-export", *common, *provider_args, "--out", str(receipt_path)], cwd=worker_fixtures.ROOT, env=env, check=True)
            subprocess.run([sys.executable, "-m", "trustai", "policy-backend-provider-export-verify", str(receipt_path), *common], cwd=worker_fixtures.ROOT, env=env, check=True)
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-provider-export-append",
                    str(receipt_path),
                    *common,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-provider-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=worker_fixtures.ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(receipt_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
