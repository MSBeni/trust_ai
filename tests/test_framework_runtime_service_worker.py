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
from trustai.framework_runtime_service_worker import (
    FRAMEWORK_RUNTIME_SERVICE_WORKER_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_WORKER_SCHEMA,
    append_framework_runtime_service_worker_receipt,
    build_framework_runtime_service_worker_receipt,
    verify_framework_runtime_service_worker_receipt,
)
from trustai.framework_runtime_storage import write_framework_runtime_storage_receipt
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_service as service_fixtures


ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"
STORAGE_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-storage-export.json"


class FrameworkRuntimeServiceWorkerTests(unittest.TestCase):
    def _sources(self) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict, dict, dict]:
        helper = service_fixtures.FrameworkRuntimeServiceTests()
        return helper._attestation()

    def _kwargs(self) -> dict:
        return {
            "root": ROOT,
            "mode": "hosted-worker",
            "environment": "aitrade-prod",
            "worker_ref": "worker:framework-runtime/service-reconciler",
            "run_ref": "worker-run:framework-runtime/service/2026-07-09T00:44:10Z",
            "operation_kind": "storage_export_reconcile",
            "actor_ref": "oidc:trustai.example/framework-runtime-service-worker",
            "schedule_ref": "schedule:framework-runtime/langgraph/continuous",
            "cadence_seconds": 30,
            "lease_ref": "lease:framework-runtime/service/2026-07-09T00:44:10Z",
            "checkpoint_ref": "checkpoint:framework-runtime/service/aitrade",
            "checkpoint_hash": "sha256:framework-runtime-service-worker-checkpoint",
            "previous_cursor_ref": "cursor:framework-runtime/service/before-lg-trace-001",
            "next_cursor_ref": "cursor:framework-runtime/service/after-lg-trace-001",
            "attempt": 1,
            "max_attempts": 3,
            "queue_ref": "queue:framework-runtime/work",
            "queue_message_ref": "queue-message:framework-runtime/service/lg-trace-001",
            "queue_message_hash": "sha256:framework-runtime-service-worker-queue-message",
            "dead_letter_queue_ref": "queue:framework-runtime/dlq",
            "runtime_worker_ref": "worker:framework-runtime/langgraph",
            "stream_message_ref": "stream-message:framework-runtime/lg-trace-001",
            "stream_message_hash": "sha256:framework-runtime-worker-stream-message",
            "storage_object_ref": "worm:framework-runtime/aitrade/lg-trace-001.json",
            "storage_object_hash": "sha256:framework-runtime-worker-storage-object",
            "clickhouse_batch_ref": "clickhouse:trustai/framework_runtime/batch/lg-trace-001",
            "clickhouse_batch_hash": "sha256:framework-runtime-worker-clickhouse-batch",
            "postgres_index_ref": "postgres:trustai/framework_runtime/lg-trace-001",
            "postgres_index_hash": "sha256:framework-runtime-worker-postgres-index",
            "control_index_ref": "control-index:framework-runtime/lg-trace-001",
            "control_index_hash": "sha256:framework-runtime-worker-control-index",
            "request_hash": "sha256:framework-runtime-service-worker-request",
            "response_status": 202,
            "response_hash": "sha256:framework-runtime-service-worker-response",
            "metrics_ref": "metrics:framework-runtime/service-workers",
            "audit_log_ref": "audit-log:framework-runtime/service-workers",
            "audit_log_root": "sha256:framework-runtime-service-worker-audit-root",
            "retention_until": "2033-07-09T00:00:00Z",
            "credential_ref": "env:FRAMEWORK_RUNTIME_SERVICE_WORKER_TOKEN",
            "evidence_refs": ["evidence:framework-runtime/service-worker"],
            "started_at": "2026-07-09T00:44:10Z",
            "completed_at": "2026-07-09T00:44:12Z",
            "next_run_at": "2026-07-09T00:44:40Z",
        }

    def _receipt(self) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict, dict, dict, dict]:
        service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._sources()
        receipt = build_framework_runtime_service_worker_receipt(
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
            **self._kwargs(),
        )
        return receipt, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "worker_operation_id", "signatures")
        worker_operation_id = content_hash(body)
        receipt["worker_operation_id"] = worker_operation_id
        receipt["signatures"] = [
            sign_value({"worker_operation_id": worker_operation_id, "framework_runtime_service_worker": body})
        ]

    def test_framework_runtime_service_worker_verifies_and_appends(self):
        receipt, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        result = verify_framework_runtime_service_worker_receipt(
            receipt,
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
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-service-worker-test")
            entry = append_framework_runtime_service_worker_receipt(
                chain,
                receipt,
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
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_WORKER_SCHEMA, receipt["schema"])
            self.assertEqual(service["attestation_id"], receipt["service"]["attestation_id"])
            self.assertEqual(storage_receipt["storage_receipt_id"], receipt["source"]["storage_receipt_id"])
            self.assertEqual("env:FRAMEWORK_RUNTIME_SERVICE_WORKER_TOKEN", receipt["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertEqual({"worker-recorded": 7}, entry["payload"]["control_status_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_worker_detects_service_tamper(self):
        receipt, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered_service = copy.deepcopy(service)
        tampered_service["service"]["service_image_digest"] = "sha256:changed-service-image"

        result = verify_framework_runtime_service_worker_receipt(
            receipt,
            service_attestation=tampered_service,
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
        self.assertTrue(any("framework-runtime-service-attestation" in error for error in result.errors))
        self.assertTrue(any("service.attestation_hash" in error for error in result.errors))

    def test_framework_runtime_service_worker_detects_storage_source_tamper(self):
        receipt, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered_export = copy.deepcopy(storage_export)
        tampered_export["storage_records"][0]["storage_hash"] = "sha256:changed-storage"

        result = verify_framework_runtime_service_worker_receipt(
            receipt,
            service_attestation=service,
            storage_receipt=storage_receipt,
            storage_export=tampered_export,
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
        self.assertTrue(any("service source" in error for error in result.errors))
        self.assertTrue(any("framework-runtime-storage-export" in error for error in result.errors))

    def test_framework_runtime_service_worker_requires_complete_summaries_without_sources(self):
        receipt, *_ = self._receipt()
        cases = [
            ("missing_service_key", "service.service_image_digest is required"),
            ("missing_source_key", "source.provider_export_hash is required"),
            ("missing_source_artifact", "source_artifacts missing: framework-runtime-storage-export"),
        ]
        for case_name, expected_error in cases:
            with self.subTest(case=case_name):
                tampered = copy.deepcopy(receipt)
                if case_name == "missing_service_key":
                    tampered["service"].pop("service_image_digest")
                elif case_name == "missing_source_key":
                    tampered["source"].pop("provider_export_hash")
                else:
                    tampered["source_artifacts"] = [
                        artifact
                        for artifact in tampered["source_artifacts"]
                        if artifact.get("type") != "framework-runtime-storage-export"
                    ]
                self._resign_receipt(tampered)

                result = verify_framework_runtime_service_worker_receipt(tampered)

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_framework_runtime_service_worker_rejects_raw_credential(self):
        receipt, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered = copy.deepcopy(receipt)
        tampered["credential"] = "plain-worker-secret"

        result = verify_framework_runtime_service_worker_receipt(
            tampered,
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
        self.assertIn("framework runtime service worker credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))
    def test_cli_framework_runtime_service_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._sources()
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            operation_path = tmp / "framework-hook-operation.json"
            runtime_audit_path = tmp / "framework-runtime-audit.json"
            worker_path = tmp / "framework-runtime-worker.json"
            storage_receipt_path = tmp / "framework-runtime-storage.json"
            service_path = tmp / "framework-runtime-service.json"
            receipt_path = tmp / "framework-runtime-service-worker.json"
            entry_path = tmp / "framework-runtime-service-worker-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_adapter_matrix(matrix_path, matrix)
            write_framework_hook_release(release_path, release)
            write_framework_hook_operation(operation_path, operation)
            write_framework_runtime_audit_receipt(runtime_audit_path, runtime_audit)
            write_framework_runtime_worker_receipt(worker_path, worker)
            write_framework_runtime_storage_receipt(storage_receipt_path, storage_receipt)
            write_framework_runtime_service_attestation(service_path, service)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
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
            worker_args = [
                "--mode",
                "hosted-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:framework-runtime/service-reconciler",
                "--run-ref",
                "worker-run:framework-runtime/service/2026-07-09T00:44:10Z",
                "--operation-kind",
                "storage_export_reconcile",
                "--actor-ref",
                "oidc:trustai.example/framework-runtime-service-worker",
                "--schedule-ref",
                "schedule:framework-runtime/langgraph/continuous",
                "--cadence-seconds",
                "30",
                "--lease-ref",
                "lease:framework-runtime/service/2026-07-09T00:44:10Z",
                "--checkpoint-ref",
                "checkpoint:framework-runtime/service/aitrade",
                "--checkpoint-hash",
                "sha256:framework-runtime-service-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:framework-runtime/service/before-lg-trace-001",
                "--next-cursor-ref",
                "cursor:framework-runtime/service/after-lg-trace-001",
                "--queue-ref",
                "queue:framework-runtime/work",
                "--queue-message-ref",
                "queue-message:framework-runtime/service/lg-trace-001",
                "--queue-message-hash",
                "sha256:framework-runtime-service-worker-queue-message",
                "--dead-letter-queue-ref",
                "queue:framework-runtime/dlq",
                "--runtime-worker-ref",
                "worker:framework-runtime/langgraph",
                "--stream-message-ref",
                "stream-message:framework-runtime/lg-trace-001",
                "--stream-message-hash",
                "sha256:framework-runtime-worker-stream-message",
                "--storage-object-ref",
                "worm:framework-runtime/aitrade/lg-trace-001.json",
                "--storage-object-hash",
                "sha256:framework-runtime-worker-storage-object",
                "--clickhouse-batch-ref",
                "clickhouse:trustai/framework_runtime/batch/lg-trace-001",
                "--clickhouse-batch-hash",
                "sha256:framework-runtime-worker-clickhouse-batch",
                "--postgres-index-ref",
                "postgres:trustai/framework_runtime/lg-trace-001",
                "--postgres-index-hash",
                "sha256:framework-runtime-worker-postgres-index",
                "--control-index-ref",
                "control-index:framework-runtime/lg-trace-001",
                "--control-index-hash",
                "sha256:framework-runtime-worker-control-index",
                "--request-hash",
                "sha256:framework-runtime-service-worker-request",
                "--response-status",
                "202",
                "--response-hash",
                "sha256:framework-runtime-service-worker-response",
                "--metrics-ref",
                "metrics:framework-runtime/service-workers",
                "--audit-log-ref",
                "audit-log:framework-runtime/service-workers",
                "--audit-log-root",
                "sha256:framework-runtime-service-worker-audit-root",
                "--retention-until",
                "2033-07-09T00:00:00Z",
                "--credential-ref",
                "env:FRAMEWORK_RUNTIME_SERVICE_WORKER_TOKEN",
                "--evidence-ref",
                "evidence:framework-runtime/service-worker",
                "--started-at",
                "2026-07-09T00:44:10Z",
                "--completed-at",
                "2026-07-09T00:44:12Z",
                "--next-run-at",
                "2026-07-09T00:44:40Z",
            ]

            subprocess.run(
                base + ["framework-runtime-service-worker"] + source_args + worker_args + ["--out", str(receipt_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["framework-runtime-service-worker-verify", str(receipt_path)] + source_args,
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + ["framework-runtime-service-worker-append", str(receipt_path)]
                + source_args
                + ["--state", str(state_path), "--tenant", "framework-runtime-service-worker-cli", "--out", str(entry_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_runtime_service_worker_receipt(
            receipt,
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
        self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])


if __name__ == "__main__":
    unittest.main()