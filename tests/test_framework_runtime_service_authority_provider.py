import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.crypto import sign_value
from trustai.framework_adapter_matrix import write_framework_adapter_matrix
from trustai.framework_hook_operation import write_framework_hook_operation
from trustai.framework_hook_release import write_framework_hook_release
from trustai.framework_runtime_audit import write_framework_runtime_audit_receipt
from trustai.framework_runtime_service import write_framework_runtime_service_attestation
from trustai.framework_runtime_service_authority import write_framework_runtime_service_authority_dossier
from trustai.framework_runtime_service_authority_provider import (
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_SCHEMA,
    append_framework_runtime_service_authority_provider_receipt,
    build_framework_runtime_service_authority_provider_receipt,
    verify_framework_runtime_service_authority_provider_receipt,
)
from trustai.framework_runtime_service_authority_worker import write_framework_runtime_service_authority_worker_receipt
from trustai.framework_runtime_service_provider import write_framework_runtime_service_provider_receipt
from trustai.framework_runtime_service_worker import write_framework_runtime_service_worker_receipt
from trustai.framework_runtime_storage import write_framework_runtime_storage_receipt
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_service_authority_worker as authority_worker_fixtures


ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"
STORAGE_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-storage-export.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class FrameworkRuntimeServiceAuthorityProviderTests(unittest.TestCase):
    def _sources(self):
        helper = authority_worker_fixtures.FrameworkRuntimeServiceAuthorityWorkerTests()
        return helper._receipt()

    def _provider_export(self, authority_worker: dict) -> dict:
        worker = authority_worker["worker"]
        scheduler = authority_worker["scheduler"]
        execution = authority_worker["execution"]
        observability = authority_worker["observability"]
        run_ref = worker["run_ref"]
        return {
            "schema": "trustai.framework-runtime-service-authority-provider-export/0.1",
            "provider": "redpanda-s3-postgres-authority",
            "environment": "aitrade-prod",
            "export_ref": "provider-export:framework-runtime-service-authority/lg-trace-001",
            "window_start": "2026-07-09T01:04:00Z",
            "window_end": "2026-07-09T01:06:00Z",
            "cursor_ref": "cursor:framework-runtime-service-authority-provider/before-lg-trace-001",
            "next_cursor_ref": "cursor:framework-runtime-service-authority-provider/after-lg-trace-001",
            "audit_log_ref": "audit-log:framework-runtime-service-authority/provider-exports",
            "audit_log_root": "sha256:framework-runtime-service-authority-provider-export-audit-root",
            "scheduler_records": [
                {
                    "record_id": "scheduler:framework-runtime-service-authority/lg-trace-001",
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
                    "record_id": "queue:framework-runtime-service-authority/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "queue_ref": execution["queue_ref"],
                    "queue_message_ref": execution["queue_message_ref"],
                    "queue_message_hash": execution["queue_message_hash"],
                    "dead_letter_queue_ref": execution["dead_letter_queue_ref"],
                    "ack_ref": "ack:framework-runtime-service-authority/lg-trace-001",
                    "ack_hash": "sha256:framework-runtime-service-authority-provider-queue-ack",
                }
            ],
            "request_records": [
                {
                    "record_id": "request:framework-runtime-service-authority/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "authority_request_ref": execution["authority_request_ref"],
                    "request_hash": execution["request_hash"],
                    "response_status": execution["response_status"],
                    "response_hash": execution["response_hash"],
                    "authority_evidence_root": execution["authority_evidence_root"],
                    "missing_requirement_root": execution["missing_requirement_root"],
                }
            ],
            "storage_records": [
                {
                    "backend": "s3-object-lock",
                    "kind": "dossier_object",
                    "record_id": "worm:framework-runtime-service-authority/lg-trace-001",
                    "ref": execution["dossier_storage_ref"],
                    "hash": execution["dossier_storage_hash"],
                    "worker_run_ref": run_ref,
                },
                {
                    "backend": "s3-object-lock",
                    "kind": "report_object",
                    "record_id": "worm:framework-runtime-service-authority/report-lg-trace-001",
                    "ref": execution["report_storage_ref"],
                    "hash": execution["report_storage_hash"],
                    "worker_run_ref": run_ref,
                },
            ],
            "audit_records": [
                {
                    "record_id": "audit:framework-runtime-service-authority/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "audit_log_ref": observability["audit_log_ref"],
                    "audit_log_root": observability["audit_log_root"],
                    "metrics_ref": observability["metrics_ref"],
                }
            ],
        }

    def _receipt(self):
        (
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
        ) = self._sources()
        authority_provider_export = self._provider_export(authority_worker)
        receipt = build_framework_runtime_service_authority_provider_receipt(
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
            root=ROOT,
            mode="provider-export",
            environment="aitrade-prod",
            provider="redpanda-s3-postgres-authority",
            endpoint_url="https://storage.example/aitrade/framework-runtime/service-authority-provider-export",
            credential_ref="env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_TOKEN",
            request_hash="sha256:framework-runtime-service-authority-provider-request",
            response_status=200,
            response_hash="sha256:framework-runtime-service-authority-provider-response",
            actor_ref="oidc:trustai.example/framework-runtime-service-authority-provider-worker",
            exported_at="2026-07-09T01:06:00Z",
            require_fresh=True,
        )
        return (
            receipt,
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

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "provider_receipt_id", "signatures")
        provider_receipt_id = content_hash(body)
        receipt["provider_receipt_id"] = provider_receipt_id
        receipt["signatures"] = [
            sign_value({"provider_receipt_id": provider_receipt_id, "framework_runtime_service_authority_provider": body})
        ]

    def test_framework_runtime_service_authority_provider_verifies_and_appends(self):
        (
            receipt,
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
        ) = self._receipt()
        result = verify_framework_runtime_service_authority_provider_receipt(
            receipt,
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
            root=ROOT,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-service-authority-provider-test")
            entry = append_framework_runtime_service_authority_provider_receipt(
                chain,
                receipt,
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
                root=ROOT,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_SCHEMA, receipt["schema"])
            self.assertTrue(result.warnings)
            self.assertEqual(authority_worker["worker_operation_id"], receipt["authority_worker_binding"]["worker_operation_id"])
            self.assertEqual(2, len(receipt["matched_storage_records"]))
            self.assertEqual("env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_TOKEN", receipt["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["provider_receipt_id"], entry["payload"]["provider_receipt_id"])
            self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_authority_provider_detects_export_tamper(self):
        (
            receipt,
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
        ) = self._receipt()
        tampered_export = copy.deepcopy(authority_provider_export)
        tampered_export["request_records"][0]["response_hash"] = "sha256:wrong-response"

        result = verify_framework_runtime_service_authority_provider_receipt(
            receipt,
            authority_provider_export=tampered_export,
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
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("export hash does not match" in error for error in result.errors))
        self.assertTrue(any("request" in error for error in result.errors))

    def test_framework_runtime_service_authority_provider_detects_worker_tamper(self):
        (
            receipt,
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
        ) = self._receipt()
        tampered_worker = copy.deepcopy(authority_worker)
        tampered_worker["execution"]["response_hash"] = "sha256:changed-response"

        result = verify_framework_runtime_service_authority_provider_receipt(
            receipt,
            authority_provider_export=authority_provider_export,
            authority_worker=tampered_worker,
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
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("authority_worker_binding does not match" in error for error in result.errors))
        self.assertTrue(any("worker source" in error for error in result.errors))

    def test_framework_runtime_service_authority_provider_requires_complete_bindings_without_sources(self):
        receipt, *_ = self._receipt()
        cases = [
            (("authority_worker_binding",), "worker_ref", "binding.worker_ref is required"),
            (("authority_worker_binding",), "previous_cursor_ref", "binding.previous_cursor_ref is required"),
            (("authority_worker_binding",), "request_hash", "binding.request_hash is required"),
            (("authority_worker_binding",), "response_status", "binding.response_status is required"),
            (("provider_export",), "cursor_ref", "provider_export.cursor_ref is required"),
            (("provider_export",), "request_record_count", "provider_export.request_record_count is required"),
        ]
        for parent_path, field, expected_error in cases:
            with self.subTest(field=field):
                tampered = copy.deepcopy(receipt)
                target = tampered
                for part in parent_path:
                    target = target[part]
                target.pop(field)
                self._resign_receipt(tampered)

                result = verify_framework_runtime_service_authority_provider_receipt(tampered)

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_framework_runtime_service_authority_provider_requires_replay_artifacts_without_sources(self):
        receipt, authority_provider_export, authority_worker, *_ = self._receipt()

        missing_all = verify_framework_runtime_service_authority_provider_receipt(receipt)
        missing_provider_export = verify_framework_runtime_service_authority_provider_receipt(
            receipt,
            authority_worker=authority_worker,
        )
        missing_authority_worker = verify_framework_runtime_service_authority_provider_receipt(
            receipt,
            authority_provider_export=authority_provider_export,
        )

        self.assertFalse(missing_all.ok)
        self.assertIn(
            "framework runtime service authority provider worker artifact is required for verification",
            missing_all.errors,
        )
        self.assertIn(
            "framework runtime service authority provider export artifact is required for verification",
            missing_all.errors,
        )
        self.assertFalse(missing_provider_export.ok)
        self.assertIn(
            "framework runtime service authority provider export artifact is required for verification",
            missing_provider_export.errors,
        )
        self.assertFalse(missing_authority_worker.ok)
        self.assertIn(
            "framework runtime service authority provider worker artifact is required for verification",
            missing_authority_worker.errors,
        )

    def test_framework_runtime_service_authority_provider_rejects_raw_credential(self):
        (
            receipt,
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
        ) = self._receipt()
        tampered = copy.deepcopy(receipt)
        tampered["credential"] = "plain-provider-secret"

        result = verify_framework_runtime_service_authority_provider_receipt(
            tampered,
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
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("framework runtime service authority provider credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_authority_provider_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
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
            ) = self._sources()
            authority_provider_export = self._provider_export(authority_worker)
            authority_provider_export_path = tmp / "framework-runtime-service-authority-provider-export.json"
            authority_worker_path = tmp / "framework-runtime-service-authority-worker.json"
            authority_dossier_path = tmp / "framework-runtime-service-authority.json"
            provider_receipt_path = tmp / "framework-runtime-service-provider.json"
            provider_export_path = tmp / "framework-runtime-service-provider-export.json"
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            operation_path = tmp / "framework-hook-operation.json"
            runtime_audit_path = tmp / "framework-runtime-audit.json"
            worker_path = tmp / "framework-runtime-worker.json"
            storage_receipt_path = tmp / "framework-runtime-storage.json"
            service_path = tmp / "framework-runtime-service.json"
            service_worker_path = tmp / "framework-runtime-service-worker.json"
            receipt_path = tmp / "framework-runtime-service-authority-provider.json"
            entry_path = tmp / "framework-runtime-service-authority-provider-entry.json"
            state_path = tmp / "evidence-chain.json"
            _write_json(authority_provider_export_path, authority_provider_export)
            write_framework_runtime_service_authority_worker_receipt(authority_worker_path, authority_worker)
            write_framework_runtime_service_authority_dossier(authority_dossier_path, authority_dossier)
            write_framework_runtime_service_provider_receipt(provider_receipt_path, service_provider_receipt)
            _write_json(provider_export_path, service_provider_export)
            write_framework_adapter_matrix(matrix_path, matrix)
            write_framework_hook_release(release_path, release)
            write_framework_hook_operation(operation_path, operation)
            write_framework_runtime_audit_receipt(runtime_audit_path, runtime_audit)
            write_framework_runtime_worker_receipt(worker_path, worker)
            write_framework_runtime_storage_receipt(storage_receipt_path, storage_receipt)
            write_framework_runtime_service_attestation(service_path, service)
            write_framework_runtime_service_worker_receipt(service_worker_path, service_worker)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
                "--authority-worker",
                str(authority_worker_path),
                "--authority-dossier",
                str(authority_dossier_path),
                "--provider-receipt",
                str(provider_receipt_path),
                "--provider-export",
                str(provider_export_path),
                "--service-worker",
                str(service_worker_path),
                "--service-attestation",
                str(service_path),
                "--storage-receipt",
                str(storage_receipt_path),
                "--storage-export",
                str(STORAGE_EXPORT_FIXTURE),
                "--worker",
                str(worker_path),
                "--runtime-audit",
                str(runtime_audit_path),
                "--audit-export",
                str(AUDIT_EXPORT_FIXTURE),
                "--operation",
                str(operation_path),
                "--trace",
                str(TRACE_FIXTURE),
                "--release",
                str(release_path),
                "--matrix",
                str(matrix_path),
                "--root",
                str(ROOT),
            ]

            subprocess.run(
                base
                + ["framework-runtime-service-authority-provider", str(authority_provider_export_path)]
                + source_args
                + [
                    "--mode",
                    "provider-export",
                    "--environment",
                    "aitrade-prod",
                    "--provider",
                    "redpanda-s3-postgres-authority",
                    "--endpoint-url",
                    "https://storage.example/aitrade/framework-runtime/service-authority-provider-export",
                    "--credential-ref",
                    "env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_TOKEN",
                    "--request-hash",
                    "sha256:framework-runtime-service-authority-provider-request",
                    "--response-status",
                    "200",
                    "--response-hash",
                    "sha256:framework-runtime-service-authority-provider-response",
                    "--actor-ref",
                    "oidc:trustai.example/framework-runtime-service-authority-provider-worker",
                    "--exported-at",
                    "2026-07-09T01:06:00Z",
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
                    "framework-runtime-service-authority-provider-verify",
                    str(receipt_path),
                    "--authority-provider-export",
                    str(authority_provider_export_path),
                ]
                + source_args,
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-provider-append",
                    str(receipt_path),
                    "--authority-provider-export",
                    str(authority_provider_export_path),
                ]
                + source_args
                + [
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-service-authority-provider-cli",
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

        result = verify_framework_runtime_service_authority_provider_receipt(
            receipt,
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
            root=ROOT,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_PROVIDER_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["provider_receipt_id"], entry["payload"]["provider_receipt_id"])


if __name__ == "__main__":
    unittest.main()
