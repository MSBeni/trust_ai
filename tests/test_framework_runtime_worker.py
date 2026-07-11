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
from trustai.framework_adapter_matrix import (
    build_framework_adapter_matrix,
    load_framework_adapter_matrix_source,
    write_framework_adapter_matrix,
)
from trustai.framework_hook_operation import (
    build_framework_hook_operation,
    load_framework_trace_payload,
    write_framework_hook_operation,
)
from trustai.framework_hook_release import (
    build_framework_hook_release,
    load_framework_hook_release_source,
    write_framework_hook_release,
)
from trustai.framework_runtime_audit import (
    build_framework_runtime_audit_receipt,
    load_framework_runtime_audit_export,
    write_framework_runtime_audit_receipt,
)
from trustai.framework_runtime_worker import (
    FRAMEWORK_RUNTIME_WORKER_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_WORKER_SCHEMA,
    append_framework_runtime_worker_receipt,
    build_framework_runtime_worker_receipt,
    verify_framework_runtime_worker_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
MATRIX_SOURCE = ROOT / "examples" / "aitrade" / "framework-adapter-matrix.json"
HOOK_SOURCE = ROOT / "examples" / "aitrade" / "framework-hook-release.json"
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"


class FrameworkRuntimeWorkerTests(unittest.TestCase):
    def _matrix(self) -> dict:
        return build_framework_adapter_matrix(
            load_framework_adapter_matrix_source(MATRIX_SOURCE),
            root=ROOT,
            issued_at="2026-07-09T00:00:00Z",
        )

    def _release(self, matrix: dict) -> dict:
        return build_framework_hook_release(
            load_framework_hook_release_source(HOOK_SOURCE),
            matrix,
            root=ROOT,
            released_at="2026-07-09T00:30:00Z",
        )

    def _operation(self) -> tuple[dict, dict, dict, dict]:
        matrix = self._matrix()
        release = self._release(matrix)
        trace = load_framework_trace_payload(TRACE_FIXTURE)
        operation = build_framework_hook_operation(
            trace,
            release,
            matrix,
            framework="langgraph",
            trace_id="lg-trace-001",
            root=ROOT,
            mode="collector-observed",
            environment="aitrade-prod",
            operation_ref="framework-hook-operation:aitrade/langgraph/lg-trace-001",
            runtime_instance_ref="runtime:aitrade/langgraph/prod-worker-1",
            runtime_process_ref="pid:4242",
            collector_service_ref="collector:trustai/otel-prod",
            collector_worker_ref="worker-run:collector/framework-hook/lg-trace-001",
            stream_message_ref="stream-message:collector/framework-hook/lg-trace-001",
            audit_log_ref="audit-log:framework-hooks/aitrade",
            audit_log_root="sha256:framework-hook-operation-audit-root",
            actor_ref="oidc:trustai.example/framework-hook-runtime",
            credential_ref="env:FRAMEWORK_HOOK_TOKEN",
            evidence_refs=["evidence:framework-hook/lg-trace-001"],
            captured_at="2026-07-09T00:40:00Z",
        )
        return operation, trace, release, matrix

    def _runtime_audit(self) -> tuple[dict, dict, dict, dict, dict, dict]:
        operation, trace, release, matrix = self._operation()
        audit_export = load_framework_runtime_audit_export(AUDIT_EXPORT_FIXTURE)
        runtime_audit = build_framework_runtime_audit_receipt(
            audit_export,
            operation,
            trace,
            release,
            matrix,
            root=ROOT,
            mode="provider-export",
            environment="aitrade-prod",
            provider="langgraph-runtime",
            endpoint_url="https://runtime.example/aitrade/audit/framework-hooks",
            credential_ref="env:LANGGRAPH_RUNTIME_AUDIT_TOKEN",
            request_hash="sha256:framework-runtime-audit-request",
            response_status=200,
            response_hash="sha256:framework-runtime-audit-response",
            actor_ref="oidc:trustai.example/framework-runtime-audit-worker",
            exported_at="2026-07-09T00:42:00Z",
        )
        return runtime_audit, audit_export, operation, trace, release, matrix

    def _worker(self) -> tuple[dict, dict, dict, dict, dict, dict, dict]:
        runtime_audit, audit_export, operation, trace, release, matrix = self._runtime_audit()
        worker = build_framework_runtime_worker_receipt(
            runtime_audit,
            audit_export,
            operation,
            trace,
            release,
            matrix,
            root=ROOT,
            mode="runtime-worker",
            environment="aitrade-prod",
            worker_ref="worker:framework-runtime/langgraph",
            run_ref="worker-run:framework-runtime/langgraph/lg-trace-001/2026-07-09T00:42:05Z",
            operation_kind="audit_export_reconcile",
            actor_ref="oidc:trustai.example/framework-runtime-worker",
            schedule_ref="schedule:framework-runtime/langgraph/continuous",
            cadence_seconds=30,
            lease_ref="lease:framework-runtime/langgraph/2026-07-09T00:42:05Z",
            checkpoint_ref="checkpoint:framework-runtime/langgraph/aitrade",
            checkpoint_hash="sha256:framework-runtime-worker-checkpoint",
            previous_cursor_ref="cursor:framework-runtime-audit/before-lg-trace-001",
            next_cursor_ref="cursor:framework-runtime-worker/after-lg-trace-001",
            next_run_at="2026-07-09T00:42:35Z",
            stream_ref="redpanda:trustai/framework-runtime",
            stream_topic="trustai.framework.runtime.audit",
            partition_ref="redpanda:trustai/framework-runtime/0",
            offset_start=4200,
            offset_end=4201,
            stream_message_ref="stream-message:framework-runtime/lg-trace-001",
            stream_message_hash="sha256:framework-runtime-worker-stream-message",
            stream_dlq_ref="redpanda:trustai/framework-runtime-dlq",
            storage_object_ref="worm:framework-runtime/aitrade/lg-trace-001.json",
            storage_object_hash="sha256:framework-runtime-worker-storage-object",
            clickhouse_batch_ref="clickhouse:trustai/framework_runtime/batch/lg-trace-001",
            clickhouse_batch_hash="sha256:framework-runtime-worker-clickhouse-batch",
            clickhouse_rows_written=2,
            postgres_index_ref="postgres:trustai/framework_runtime/lg-trace-001",
            postgres_index_hash="sha256:framework-runtime-worker-postgres-index",
            postgres_rows_written=1,
            control_index_ref="control-index:framework-runtime/lg-trace-001",
            control_index_hash="sha256:framework-runtime-worker-control-index",
            metrics_ref="metrics:framework-runtime/workers",
            audit_log_ref="audit-log:framework-runtime/workers",
            audit_log_root="sha256:framework-runtime-worker-audit-root",
            retention_until="2033-07-09T00:00:00Z",
            credential_ref="env:FRAMEWORK_RUNTIME_WORKER_TOKEN",
            evidence_refs=["evidence:framework-runtime/worker/lg-trace-001"],
            started_at="2026-07-09T00:42:03Z",
            completed_at="2026-07-09T00:42:05Z",
        )
        return worker, runtime_audit, audit_export, operation, trace, release, matrix

    def _resign_worker(self, worker: dict) -> None:
        body = without_keys(worker, "worker_operation_id", "signatures")
        worker_operation_id = content_hash(body)
        worker["worker_operation_id"] = worker_operation_id
        worker["signatures"] = [
            sign_value({"worker_operation_id": worker_operation_id, "framework_runtime_worker": body})
        ]

    def test_framework_runtime_worker_verifies_and_appends(self):
        worker, runtime_audit, audit_export, operation, trace, release, matrix = self._worker()
        result = verify_framework_runtime_worker_receipt(
            worker,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-worker-test")
            entry = append_framework_runtime_worker_receipt(
                chain,
                worker,
                runtime_audit=runtime_audit,
                audit_export=audit_export,
                operation=operation,
                trace_payload=trace,
                release=release,
                matrix=matrix,
                root=ROOT,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_RUNTIME_WORKER_SCHEMA, worker["schema"])
            self.assertEqual(runtime_audit["runtime_audit_id"], worker["source"]["runtime_audit_id"])
            self.assertEqual("runtime:aitrade/langgraph/prod-worker-1", worker["runtime"]["runtime_instance_ref"])
            self.assertEqual("env:FRAMEWORK_RUNTIME_WORKER_TOKEN", worker["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(worker["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertEqual({"passed": 7}, entry["payload"]["control_status_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_worker_detects_runtime_audit_source_tamper(self):
        worker, runtime_audit, audit_export, operation, trace, release, matrix = self._worker()
        tampered_export = copy.deepcopy(audit_export)
        tampered_export["events"][0]["runtime_instance_ref"] = "runtime:wrong"

        result = verify_framework_runtime_worker_receipt(
            worker,
            runtime_audit=runtime_audit,
            audit_export=tampered_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("runtime audit invalid" in error for error in result.errors))

    def test_framework_runtime_worker_detects_source_binding_tamper(self):
        worker, runtime_audit, audit_export, operation, trace, release, matrix = self._worker()
        tampered = copy.deepcopy(worker)
        tampered["source"]["trace_id"] = "wrong-trace"

        result = verify_framework_runtime_worker_receipt(
            tampered,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("worker_operation_id" in error for error in result.errors))
        self.assertTrue(any("source binding does not match" in error for error in result.errors))

    def test_framework_runtime_worker_rejects_raw_credential(self):
        worker, runtime_audit, audit_export, operation, trace, release, matrix = self._worker()
        tampered = copy.deepcopy(worker)
        tampered["credential"] = "plain-secret"

        result = verify_framework_runtime_worker_receipt(
            tampered,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("framework runtime worker credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_framework_runtime_worker_requires_source_replay_artifacts_without_sources(self):
        worker, *_ = self._worker()

        result = verify_framework_runtime_worker_receipt(worker)

        self.assertFalse(result.ok)
        self.assertTrue(any("source artifacts are required for verification" in error for error in result.errors), result.errors)

    def test_framework_runtime_worker_requires_complete_signed_source_summary(self):
        worker, *_ = self._worker()
        cases = [
            ("missing_source_key", "source.runtime_process_ref is required"),
            ("missing_required_source_value", "source.trace_roots is required"),
            ("invalid_trace_roots_type", "source.trace_roots must be an array"),
        ]
        for case_name, expected_error in cases:
            with self.subTest(case=case_name):
                tampered = copy.deepcopy(worker)
                if case_name == "missing_source_key":
                    tampered["source"].pop("runtime_process_ref")
                elif case_name == "missing_required_source_value":
                    tampered["source"]["trace_roots"] = []
                else:
                    tampered["source"]["trace_roots"] = "not-a-list"
                self._resign_worker(tampered)

                result = verify_framework_runtime_worker_receipt(tampered)

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_cli_framework_runtime_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            runtime_audit, audit_export, operation, trace, release, matrix = self._runtime_audit()
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            operation_path = tmp / "framework-hook-operation.json"
            runtime_audit_path = tmp / "framework-runtime-audit.json"
            worker_path = tmp / "framework-runtime-worker.json"
            entry_path = tmp / "framework-runtime-worker-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_adapter_matrix(matrix_path, matrix)
            write_framework_hook_release(release_path, release)
            write_framework_hook_operation(operation_path, operation)
            write_framework_runtime_audit_receipt(runtime_audit_path, runtime_audit)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
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
                "runtime-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:framework-runtime/langgraph",
                "--run-ref",
                "worker-run:framework-runtime/langgraph/lg-trace-001/2026-07-09T00:42:05Z",
                "--operation-kind",
                "audit_export_reconcile",
                "--actor-ref",
                "oidc:trustai.example/framework-runtime-worker",
                "--schedule-ref",
                "schedule:framework-runtime/langgraph/continuous",
                "--cadence-seconds",
                "30",
                "--lease-ref",
                "lease:framework-runtime/langgraph/2026-07-09T00:42:05Z",
                "--checkpoint-ref",
                "checkpoint:framework-runtime/langgraph/aitrade",
                "--checkpoint-hash",
                "sha256:framework-runtime-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:framework-runtime-audit/before-lg-trace-001",
                "--next-cursor-ref",
                "cursor:framework-runtime-worker/after-lg-trace-001",
                "--next-run-at",
                "2026-07-09T00:42:35Z",
                "--stream-ref",
                "redpanda:trustai/framework-runtime",
                "--stream-topic",
                "trustai.framework.runtime.audit",
                "--partition-ref",
                "redpanda:trustai/framework-runtime/0",
                "--offset-start",
                "4200",
                "--offset-end",
                "4201",
                "--stream-message-ref",
                "stream-message:framework-runtime/lg-trace-001",
                "--stream-message-hash",
                "sha256:framework-runtime-worker-stream-message",
                "--stream-dlq-ref",
                "redpanda:trustai/framework-runtime-dlq",
                "--storage-object-ref",
                "worm:framework-runtime/aitrade/lg-trace-001.json",
                "--storage-object-hash",
                "sha256:framework-runtime-worker-storage-object",
                "--clickhouse-batch-ref",
                "clickhouse:trustai/framework_runtime/batch/lg-trace-001",
                "--clickhouse-batch-hash",
                "sha256:framework-runtime-worker-clickhouse-batch",
                "--clickhouse-rows-written",
                "2",
                "--postgres-index-ref",
                "postgres:trustai/framework_runtime/lg-trace-001",
                "--postgres-index-hash",
                "sha256:framework-runtime-worker-postgres-index",
                "--postgres-rows-written",
                "1",
                "--control-index-ref",
                "control-index:framework-runtime/lg-trace-001",
                "--control-index-hash",
                "sha256:framework-runtime-worker-control-index",
                "--metrics-ref",
                "metrics:framework-runtime/workers",
                "--audit-log-ref",
                "audit-log:framework-runtime/workers",
                "--audit-log-root",
                "sha256:framework-runtime-worker-audit-root",
                "--retention-until",
                "2033-07-09T00:00:00Z",
                "--credential-ref",
                "env:FRAMEWORK_RUNTIME_WORKER_TOKEN",
                "--evidence-ref",
                "evidence:framework-runtime/worker/lg-trace-001",
                "--started-at",
                "2026-07-09T00:42:03Z",
                "--completed-at",
                "2026-07-09T00:42:05Z",
            ]

            subprocess.run(
                base + ["framework-runtime-worker"] + source_args + worker_args + ["--out", str(worker_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["framework-runtime-worker-verify", str(worker_path)] + source_args,
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + ["framework-runtime-worker-append", str(worker_path)]
                + source_args
                + ["--state", str(state_path), "--tenant", "framework-runtime-worker-cli", "--out", str(entry_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            worker = json.loads(worker_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_runtime_worker_receipt(
            worker,
            runtime_audit=runtime_audit,
            audit_export=audit_export,
            operation=operation,
            trace_payload=trace,
            release=release,
            matrix=matrix,
            root=ROOT,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(worker["worker_operation_id"], entry["payload"]["worker_operation_id"])


if __name__ == "__main__":
    unittest.main()
