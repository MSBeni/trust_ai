import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.framework_runtime_service_authority_recorded_export import (
    write_framework_runtime_service_authority_recorded_export,
)
from trustai.framework_runtime_service_authority_recorded_export_provider import (
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_SCHEMA,
    append_framework_runtime_service_authority_recorded_export_provider_receipt,
    build_framework_runtime_service_authority_recorded_export_provider_receipt,
    verify_framework_runtime_service_authority_recorded_export_provider_receipt,
)
from trustai.framework_runtime_service_authority_recorded_export_worker import (
    write_framework_runtime_service_authority_recorded_export_worker_receipt,
)

from tests import test_framework_runtime_service_authority_recorded_export_worker as worker_fixtures


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class FrameworkRuntimeServiceAuthorityRecordedExportProviderTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = worker_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportWorkerTests()
        return helper._receipt(tmp)

    def _provider_export(self, recorded_export_worker: dict) -> dict:
        worker = recorded_export_worker["worker"]
        scheduler = recorded_export_worker["scheduler"]
        execution = recorded_export_worker["execution"]
        observability = recorded_export_worker["observability"]
        run_ref = worker["run_ref"]
        return {
            "schema": "trustai.framework-runtime-service-authority-recorded-export-provider-export/0.1",
            "provider": "redpanda-s3-postgres-recorded-export",
            "environment": "aitrade-prod",
            "export_ref": "provider-export:framework-runtime-service-authority-recorded-export/lg-trace-001",
            "window_start": "2026-07-09T01:13:00Z",
            "window_end": "2026-07-09T01:15:00Z",
            "cursor_ref": "cursor:framework-runtime-service-authority-recorded-export-provider/before-lg-trace-001",
            "next_cursor_ref": "cursor:framework-runtime-service-authority-recorded-export-provider/after-lg-trace-001",
            "audit_log_ref": "audit-log:framework-runtime-service-authority-recorded-export/provider-exports",
            "audit_log_root": "sha256:framework-runtime-service-authority-recorded-export-provider-audit-root",
            "scheduler_records": [
                {
                    "record_id": "scheduler:framework-runtime-service-authority-recorded-export/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "schedule_ref": scheduler["schedule_ref"],
                    "lease_ref": scheduler["lease_ref"],
                    "checkpoint_ref": scheduler["checkpoint_ref"],
                    "checkpoint_hash": scheduler["checkpoint_hash"],
                    "previous_cursor_ref": scheduler["previous_cursor_ref"],
                    "next_cursor_ref": scheduler["next_cursor_ref"],
                }
            ],
            "queue_records": [
                {
                    "record_id": "queue:framework-runtime-service-authority-recorded-export/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "queue_ref": execution["queue_ref"],
                    "queue_message_ref": execution["queue_message_ref"],
                    "queue_message_hash": execution["queue_message_hash"],
                    "dead_letter_queue_ref": execution["dead_letter_queue_ref"],
                    "ack_ref": "ack:framework-runtime-service-authority-recorded-export/lg-trace-001",
                    "ack_hash": "sha256:framework-runtime-service-authority-recorded-export-provider-queue-ack",
                }
            ],
            "request_records": [
                {
                    "record_id": "request:framework-runtime-service-authority-recorded-export/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "recorded_export_ref": execution["recorded_export_ref"],
                    "request_hash": execution["request_hash"],
                    "response_status": execution["response_status"],
                    "response_hash": execution["response_hash"],
                    "artifact_root": execution["artifact_root"],
                    "artifact_content_root": execution["artifact_content_root"],
                }
            ],
            "storage_records": [
                {
                    "backend": "s3-object-lock",
                    "kind": "recorded_export_object",
                    "record_id": "worm:framework-runtime-service-authority-recorded-export/lg-trace-001",
                    "ref": execution["recorded_export_storage_ref"],
                    "hash": execution["recorded_export_storage_hash"],
                    "worker_run_ref": run_ref,
                },
                {
                    "backend": "s3-object-lock",
                    "kind": "artifact_archive",
                    "record_id": "worm:framework-runtime-service-authority-recorded-export/archive-lg-trace-001",
                    "ref": execution["artifact_archive_ref"],
                    "hash": execution["artifact_archive_hash"],
                    "worker_run_ref": run_ref,
                },
                {
                    "backend": "s3-object-lock",
                    "kind": "artifact_manifest",
                    "record_id": "worm:framework-runtime-service-authority-recorded-export/manifest-lg-trace-001",
                    "ref": execution["artifact_manifest_ref"],
                    "hash": execution["artifact_manifest_hash"],
                    "worker_run_ref": run_ref,
                },
                {
                    "backend": "s3-object-lock",
                    "kind": "storage_write_record",
                    "record_id": "storage-write:framework-runtime-service-authority-recorded-export/lg-trace-001",
                    "ref": execution["storage_write_ref"],
                    "hash": execution["storage_write_hash"],
                    "worker_run_ref": run_ref,
                },
            ],
            "audit_records": [
                {
                    "record_id": "audit:framework-runtime-service-authority-recorded-export/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "audit_log_ref": observability["audit_log_ref"],
                    "audit_log_root": observability["audit_log_root"],
                    "metrics_ref": observability["metrics_ref"],
                }
            ],
        }

    def _receipt(self, tmp: Path):
        (
            recorded_export_worker,
            recorded_export,
            paths,
            authority_attestation,
            authority_provider_receipt,
            authority_provider_export,
            authority_worker,
            authority_dossier,
            service_provider_receipt,
            service_provider_export,
            service_worker,
            service,
            storage_receipt,
            storage_export,
            worker,
            runtime_audit,
            audit_export,
            operation,
            trace,
            release,
            matrix,
        ) = self._sources(tmp)
        provider_export = self._provider_export(recorded_export_worker)
        receipt = build_framework_runtime_service_authority_recorded_export_provider_receipt(
            provider_export,
            recorded_export_worker,
            recorded_export,
            authority_attestation=authority_attestation,
            authority_provider_receipt=authority_provider_receipt,
            authority_provider_export=authority_provider_export,
            authority_worker=authority_worker,
            authority_dossier=authority_dossier,
            service_provider_receipt=service_provider_receipt,
            service_provider_export=service_provider_export,
            service_worker=service_worker,
            service_attestation=service,
            storage_receipt=storage_receipt,
            storage_export=storage_export,
            worker=worker,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            artifact_paths=paths,
            root=ROOT,
            mode="provider-export",
            environment="aitrade-prod",
            provider="redpanda-s3-postgres-recorded-export",
            endpoint_url="https://storage.example/aitrade/framework-runtime/service-authority-recorded-export-provider-export",
            credential_ref="env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_TOKEN",
            request_hash="sha256:framework-runtime-service-authority-recorded-export-provider-request",
            response_status=200,
            response_hash="sha256:framework-runtime-service-authority-recorded-export-provider-response",
            actor_ref="oidc:trustai.example/framework-runtime-service-authority-recorded-export-provider-worker",
            exported_at="2026-07-09T01:15:00Z",
            require_fresh=True,
        )
        return (
            receipt,
            provider_export,
            recorded_export_worker,
            recorded_export,
            paths,
            authority_attestation,
            authority_provider_receipt,
            authority_provider_export,
            authority_worker,
            authority_dossier,
            service_provider_receipt,
            service_provider_export,
            service_worker,
            service,
            storage_receipt,
            storage_export,
            worker,
            runtime_audit,
            audit_export,
            operation,
            trace,
            release,
            matrix,
        )

    def test_framework_runtime_service_authority_recorded_export_provider_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            values = self._receipt(tmp)
            (
                receipt,
                provider_export,
                recorded_export_worker,
                recorded_export,
                paths,
                authority_attestation,
                authority_provider_receipt,
                authority_provider_export,
                authority_worker,
                authority_dossier,
                service_provider_receipt,
                service_provider_export,
                service_worker,
                service,
                storage_receipt,
                storage_export,
                worker,
                runtime_audit,
                audit_export,
                operation,
                trace,
                release,
                matrix,
            ) = values
            result = verify_framework_runtime_service_authority_recorded_export_provider_receipt(
                receipt,
                provider_export=provider_export,
                recorded_export_worker=recorded_export_worker,
                recorded_export=recorded_export,
                authority_attestation=authority_attestation,
                authority_provider_receipt=authority_provider_receipt,
                authority_provider_export=authority_provider_export,
                authority_worker=authority_worker,
                authority_dossier=authority_dossier,
                service_provider_receipt=service_provider_receipt,
                service_provider_export=service_provider_export,
                service_worker=service_worker,
                service_attestation=service,
                storage_receipt=storage_receipt,
                storage_export=storage_export,
                worker=worker,
                runtime_audit=runtime_audit,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace,
                release=release,
                matrix=matrix,
                artifact_paths=paths,
                root=ROOT,
            )
            chain = EvidenceChain.load(
                tmp / "chain.json",
                tenant_id="framework-runtime-service-authority-recorded-export-provider-test",
            )
            entry = append_framework_runtime_service_authority_recorded_export_provider_receipt(
                chain,
                receipt,
                provider_export=provider_export,
                recorded_export_worker=recorded_export_worker,
                recorded_export=recorded_export,
                authority_attestation=authority_attestation,
                authority_provider_receipt=authority_provider_receipt,
                authority_provider_export=authority_provider_export,
                authority_worker=authority_worker,
                authority_dossier=authority_dossier,
                service_provider_receipt=service_provider_receipt,
                service_provider_export=service_provider_export,
                service_worker=service_worker,
                service_attestation=service,
                storage_receipt=storage_receipt,
                storage_export=storage_export,
                worker=worker,
                runtime_audit=runtime_audit,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace,
                release=release,
                matrix=matrix,
                artifact_paths=paths,
                root=ROOT,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_SCHEMA, receipt["schema"])
            self.assertTrue(result.warnings)
            self.assertEqual(recorded_export_worker["worker_operation_id"], receipt["recorded_export_worker_binding"]["worker_operation_id"])
            self.assertEqual(4, len(receipt["matched_storage_records"]))
            self.assertEqual("env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_TOKEN", receipt["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["provider_receipt_id"], entry["payload"]["provider_receipt_id"])
            self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_authority_recorded_export_provider_detects_export_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
                provider_export,
                recorded_export_worker,
                recorded_export,
                paths,
                authority_attestation,
                authority_provider_receipt,
                authority_provider_export,
                authority_worker,
                authority_dossier,
                service_provider_receipt,
                service_provider_export,
                service_worker,
                service,
                storage_receipt,
                storage_export,
                worker,
                runtime_audit,
                audit_export,
                operation,
                trace,
                release,
                matrix,
            ) = self._receipt(tmp)
            tampered_export = copy.deepcopy(provider_export)
            tampered_export["request_records"][0]["response_hash"] = "sha256:wrong-response"

            result = verify_framework_runtime_service_authority_recorded_export_provider_receipt(
                receipt,
                provider_export=tampered_export,
                recorded_export_worker=recorded_export_worker,
                recorded_export=recorded_export,
                authority_attestation=authority_attestation,
                authority_provider_receipt=authority_provider_receipt,
                authority_provider_export=authority_provider_export,
                authority_worker=authority_worker,
                authority_dossier=authority_dossier,
                service_provider_receipt=service_provider_receipt,
                service_provider_export=service_provider_export,
                service_worker=service_worker,
                service_attestation=service,
                storage_receipt=storage_receipt,
                storage_export=storage_export,
                worker=worker,
                runtime_audit=runtime_audit,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace,
                release=release,
                matrix=matrix,
                artifact_paths=paths,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("export hash does not match" in error for error in result.errors))
            self.assertTrue(any("request" in error for error in result.errors))

    def test_framework_runtime_service_authority_recorded_export_provider_detects_worker_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
                provider_export,
                recorded_export_worker,
                recorded_export,
                paths,
                authority_attestation,
                authority_provider_receipt,
                authority_provider_export,
                authority_worker,
                authority_dossier,
                service_provider_receipt,
                service_provider_export,
                service_worker,
                service,
                storage_receipt,
                storage_export,
                worker,
                runtime_audit,
                audit_export,
                operation,
                trace,
                release,
                matrix,
            ) = self._receipt(tmp)
            tampered_worker = copy.deepcopy(recorded_export_worker)
            tampered_worker["execution"]["response_hash"] = "sha256:changed-response"

            result = verify_framework_runtime_service_authority_recorded_export_provider_receipt(
                receipt,
                provider_export=provider_export,
                recorded_export_worker=tampered_worker,
                recorded_export=recorded_export,
                authority_attestation=authority_attestation,
                authority_provider_receipt=authority_provider_receipt,
                authority_provider_export=authority_provider_export,
                authority_worker=authority_worker,
                authority_dossier=authority_dossier,
                service_provider_receipt=service_provider_receipt,
                service_provider_export=service_provider_export,
                service_worker=service_worker,
                service_attestation=service,
                storage_receipt=storage_receipt,
                storage_export=storage_export,
                worker=worker,
                runtime_audit=runtime_audit,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace,
                release=release,
                matrix=matrix,
                artifact_paths=paths,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("recorded_export_worker_binding does not match" in error for error in result.errors))
            self.assertTrue(any("worker source" in error for error in result.errors))

    def test_framework_runtime_service_authority_recorded_export_provider_rejects_raw_credential(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
                provider_export,
                recorded_export_worker,
                recorded_export,
                paths,
                authority_attestation,
                authority_provider_receipt,
                authority_provider_export,
                authority_worker,
                authority_dossier,
                service_provider_receipt,
                service_provider_export,
                service_worker,
                service,
                storage_receipt,
                storage_export,
                worker,
                runtime_audit,
                audit_export,
                operation,
                trace,
                release,
                matrix,
            ) = self._receipt(tmp)
            tampered = copy.deepcopy(receipt)
            tampered["credential"] = "plain-provider-secret"

            result = verify_framework_runtime_service_authority_recorded_export_provider_receipt(
                tampered,
                provider_export=provider_export,
                recorded_export_worker=recorded_export_worker,
                recorded_export=recorded_export,
                authority_attestation=authority_attestation,
                authority_provider_receipt=authority_provider_receipt,
                authority_provider_export=authority_provider_export,
                authority_worker=authority_worker,
                authority_dossier=authority_dossier,
                service_provider_receipt=service_provider_receipt,
                service_provider_export=service_provider_export,
                service_worker=service_worker,
                service_attestation=service,
                storage_receipt=storage_receipt,
                storage_export=storage_export,
                worker=worker,
                runtime_audit=runtime_audit,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace,
                release=release,
                matrix=matrix,
                artifact_paths=paths,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertIn(
                "framework runtime service authority recorded export provider credential must be a redacted reference",
                result.errors,
            )
            self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_authority_recorded_export_provider_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                recorded_export_worker,
                recorded_export,
                paths,
                *_,
            ) = self._sources(tmp)
            provider_export = self._provider_export(recorded_export_worker)
            provider_export_path = tmp / "framework-runtime-service-authority-recorded-export-provider-export.json"
            recorded_export_worker_path = tmp / "framework-runtime-service-authority-recorded-export-worker.json"
            recorded_export_path = tmp / "framework-runtime-service-authority-recorded-export.json"
            receipt_path = tmp / "framework-runtime-service-authority-recorded-export-provider.json"
            entry_path = tmp / "framework-runtime-service-authority-recorded-export-provider-entry.json"
            state_path = tmp / "evidence-chain.json"
            _write_json(provider_export_path, provider_export)
            write_framework_runtime_service_authority_recorded_export_worker_receipt(recorded_export_worker_path, recorded_export_worker)
            write_framework_runtime_service_authority_recorded_export(recorded_export_path, recorded_export)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = worker_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportWorkerTests()._source_args(paths)

            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-recorded-export-provider",
                    str(provider_export_path),
                    str(recorded_export_worker_path),
                    str(recorded_export_path),
                ]
                + source_args
                + [
                    "--root",
                    str(ROOT),
                    "--mode",
                    "provider-export",
                    "--environment",
                    "aitrade-prod",
                    "--provider",
                    "redpanda-s3-postgres-recorded-export",
                    "--endpoint-url",
                    "https://storage.example/aitrade/framework-runtime/service-authority-recorded-export-provider-export",
                    "--credential-ref",
                    "env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_TOKEN",
                    "--request-hash",
                    "sha256:framework-runtime-service-authority-recorded-export-provider-request",
                    "--response-status",
                    "200",
                    "--response-hash",
                    "sha256:framework-runtime-service-authority-recorded-export-provider-response",
                    "--actor-ref",
                    "oidc:trustai.example/framework-runtime-service-authority-recorded-export-provider-worker",
                    "--exported-at",
                    "2026-07-09T01:15:00Z",
                    "--require-fresh",
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
                base
                + [
                    "framework-runtime-service-authority-recorded-export-provider-verify",
                    str(receipt_path),
                    "--recorded-export-provider-export",
                    str(provider_export_path),
                    "--recorded-export-worker",
                    str(recorded_export_worker_path),
                    "--recorded-export",
                    str(recorded_export_path),
                ]
                + source_args
                + ["--root", str(ROOT)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-recorded-export-provider-append",
                    str(receipt_path),
                    str(provider_export_path),
                    str(recorded_export_worker_path),
                    str(recorded_export_path),
                ]
                + source_args
                + [
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-service-authority-recorded-export-provider-cli",
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

        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_SCHEMA, receipt["schema"])
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["provider_receipt_id"], entry["payload"]["provider_receipt_id"])


if __name__ == "__main__":
    unittest.main()
