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
from trustai.framework_runtime_service_provider import (
    FRAMEWORK_RUNTIME_SERVICE_PROVIDER_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_PROVIDER_SCHEMA,
    append_framework_runtime_service_provider_receipt,
    build_framework_runtime_service_provider_receipt,
    verify_framework_runtime_service_provider_receipt,
)
from trustai.framework_runtime_service_worker import write_framework_runtime_service_worker_receipt
from trustai.framework_runtime_storage import write_framework_runtime_storage_receipt
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_service_worker as service_worker_fixtures


ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"
STORAGE_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-storage-export.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class FrameworkRuntimeServiceProviderTests(unittest.TestCase):
    def _sources(self) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict, dict, dict, dict, dict]:
        helper = service_worker_fixtures.FrameworkRuntimeServiceWorkerTests()
        service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = helper._receipt()
        provider_export = self._provider_export(service_worker)
        return provider_export, service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix

    def _provider_export(self, service_worker: dict) -> dict:
        service = service_worker["service"]
        worker = service_worker["worker"]
        scheduler = service_worker["scheduler"]
        execution = service_worker["execution"]
        observability = service_worker["observability"]
        run_ref = worker["run_ref"]
        return {
            "schema": "trustai.framework-runtime-service-provider-export/0.1",
            "provider": "redpanda-clickhouse-postgres-kms",
            "environment": "aitrade-prod",
            "export_ref": "provider-export:framework-runtime-service/lg-trace-001",
            "window_start": "2026-07-09T00:44:00Z",
            "window_end": "2026-07-09T00:45:00Z",
            "cursor_ref": "cursor:framework-runtime-service-provider/before-lg-trace-001",
            "next_cursor_ref": "cursor:framework-runtime-service-provider/after-lg-trace-001",
            "audit_log_ref": "audit-log:framework-runtime/provider-exports",
            "audit_log_root": "sha256:framework-runtime-service-provider-export-audit-root",
            "scheduler_records": [
                {
                    "record_id": "scheduler:framework-runtime-service/lg-trace-001",
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
                    "record_id": "queue:framework-runtime-service/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "queue_ref": execution["queue_ref"],
                    "queue_message_ref": execution["queue_message_ref"],
                    "queue_message_hash": execution["queue_message_hash"],
                    "dead_letter_queue_ref": execution["dead_letter_queue_ref"],
                    "ack_ref": "ack:framework-runtime-service/lg-trace-001",
                    "ack_hash": "sha256:framework-runtime-service-provider-queue-ack",
                }
            ],
            "kms_records": [
                {
                    "record_id": "kms:framework-runtime-service/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "kms_key_ref": service["kms_key_ref"],
                    "operation_ref": "kms-operation:framework-runtime-service/lg-trace-001",
                    "request_hash": execution["request_hash"],
                    "response_hash": execution["response_hash"],
                    "decision": "allowed",
                    "hsm_attestation_hash": "sha256:framework-runtime-service-provider-kms-hsm",
                }
            ],
            "stream_records": [
                {
                    "record_id": "stream:framework-runtime-service/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "stream_ref": service["stream_ref"],
                    "stream_topic": service["stream_topic"],
                    "stream_message_ref": execution["stream_message_ref"],
                    "stream_message_hash": execution["stream_message_hash"],
                    "partition_ref": "redpanda:trustai/framework-runtime/0",
                    "offset_start": 4300,
                    "offset_end": 4301,
                }
            ],
            "storage_records": [
                {
                    "backend": "s3-object-lock",
                    "kind": "worm_object",
                    "record_id": "worm:framework-runtime-service/lg-trace-001",
                    "ref": execution["storage_object_ref"],
                    "hash": execution["storage_object_hash"],
                    "worker_run_ref": run_ref,
                },
                {
                    "backend": "clickhouse",
                    "kind": "clickhouse_batch",
                    "record_id": "clickhouse:framework-runtime-service/lg-trace-001",
                    "ref": execution["clickhouse_batch_ref"],
                    "hash": execution["clickhouse_batch_hash"],
                    "row_count": 2,
                    "worker_run_ref": run_ref,
                },
                {
                    "backend": "postgres",
                    "kind": "postgres_index",
                    "record_id": "postgres:framework-runtime-service/lg-trace-001",
                    "ref": execution["postgres_index_ref"],
                    "hash": execution["postgres_index_hash"],
                    "row_count": 1,
                    "worker_run_ref": run_ref,
                },
                {
                    "backend": "postgres",
                    "kind": "control_index",
                    "record_id": "control-index:framework-runtime-service/lg-trace-001",
                    "ref": execution["control_index_ref"],
                    "hash": execution["control_index_hash"],
                    "worker_run_ref": run_ref,
                },
            ],
            "audit_records": [
                {
                    "record_id": "audit:framework-runtime-service/lg-trace-001",
                    "worker_run_ref": run_ref,
                    "audit_log_ref": observability["audit_log_ref"],
                    "audit_log_root": observability["audit_log_root"],
                    "metrics_ref": observability["metrics_ref"],
                }
            ],
        }

    def _receipt(self) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict, dict, dict, dict, dict, dict]:
        provider_export, service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._sources()
        receipt = build_framework_runtime_service_provider_receipt(
            provider_export,
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
            provider="redpanda-clickhouse-postgres-kms",
            endpoint_url="https://storage.example/aitrade/framework-runtime/service-provider-export",
            credential_ref="env:FRAMEWORK_RUNTIME_SERVICE_PROVIDER_TOKEN",
            request_hash="sha256:framework-runtime-service-provider-request",
            response_status=200,
            response_hash="sha256:framework-runtime-service-provider-response",
            actor_ref="oidc:trustai.example/framework-runtime-service-provider-worker",
            exported_at="2026-07-09T00:45:00Z",
        )
        return receipt, provider_export, service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "provider_receipt_id", "signatures")
        provider_receipt_id = content_hash(body)
        receipt["provider_receipt_id"] = provider_receipt_id
        receipt["signatures"] = [sign_value({"provider_receipt_id": provider_receipt_id, "framework_runtime_service_provider": body})]

    def test_framework_runtime_service_provider_verifies_and_appends(self):
        receipt, provider_export, service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        result = verify_framework_runtime_service_provider_receipt(
            receipt,
            provider_export=provider_export,
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
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-service-provider-test")
            entry = append_framework_runtime_service_provider_receipt(
                chain,
                receipt,
                provider_export=provider_export,
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
            self.assertTrue(result.warnings)
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_PROVIDER_SCHEMA, receipt["schema"])
            self.assertEqual(service_worker["worker_operation_id"], receipt["service_worker_binding"]["worker_operation_id"])
            self.assertEqual(4, len(receipt["matched_storage_records"]))
            self.assertEqual("env:FRAMEWORK_RUNTIME_SERVICE_PROVIDER_TOKEN", receipt["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_PROVIDER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["provider_receipt_id"], entry["payload"]["provider_receipt_id"])
            self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_provider_detects_export_tamper(self):
        receipt, provider_export, service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered_export = copy.deepcopy(provider_export)
        tampered_export["queue_records"][0]["queue_message_hash"] = "sha256:wrong-queue"

        result = verify_framework_runtime_service_provider_receipt(
            receipt,
            provider_export=tampered_export,
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
        self.assertTrue(any("queue" in error for error in result.errors))

    def test_framework_runtime_service_provider_detects_worker_tamper(self):
        receipt, provider_export, service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered_worker = copy.deepcopy(service_worker)
        tampered_worker["execution"]["response_hash"] = "sha256:changed-response"

        result = verify_framework_runtime_service_provider_receipt(
            receipt,
            provider_export=provider_export,
            service_worker=tampered_worker,
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
        self.assertTrue(any("service_worker_binding does not match" in error for error in result.errors))
        self.assertTrue(any("worker source" in error for error in result.errors))

    def test_framework_runtime_service_provider_requires_complete_binding_without_sources(self):
        receipt, *_ = self._receipt()
        cases = [
            (("service_worker_binding",), "worker_ref", "binding.worker_ref is required"),
            (("service_worker_binding",), "dead_letter_queue_ref", "binding.dead_letter_queue_ref is required"),
            (("service_worker_binding",), "request_hash", "binding.request_hash is required"),
            (("provider_export",), "cursor_ref", "provider_export.cursor_ref is required"),
            (("provider_export",), "scheduler_record_count", "provider_export.scheduler_record_count is required"),
        ]
        for parent_path, field, expected_error in cases:
            with self.subTest(field=field):
                tampered = copy.deepcopy(receipt)
                target = tampered
                for part in parent_path:
                    target = target[part]
                target.pop(field)
                self._resign_receipt(tampered)

                result = verify_framework_runtime_service_provider_receipt(tampered)

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_framework_runtime_service_provider_requires_replay_artifacts_without_sources(self):
        receipt, provider_export, service_worker, *_ = self._receipt()

        missing_all = verify_framework_runtime_service_provider_receipt(receipt)
        missing_provider_export = verify_framework_runtime_service_provider_receipt(
            receipt,
            service_worker=service_worker,
        )
        missing_service_worker = verify_framework_runtime_service_provider_receipt(
            receipt,
            provider_export=provider_export,
        )

        self.assertFalse(missing_all.ok)
        self.assertIn(
            "framework runtime service provider service worker artifact is required for verification",
            missing_all.errors,
        )
        self.assertIn(
            "framework runtime service provider export artifact is required for verification",
            missing_all.errors,
        )
        self.assertFalse(missing_provider_export.ok)
        self.assertIn(
            "framework runtime service provider export artifact is required for verification",
            missing_provider_export.errors,
        )
        self.assertFalse(missing_service_worker.ok)
        self.assertIn(
            "framework runtime service provider service worker artifact is required for verification",
            missing_service_worker.errors,
        )

    def test_framework_runtime_service_provider_rejects_raw_credential(self):
        receipt, provider_export, service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._receipt()
        tampered = copy.deepcopy(receipt)
        tampered["credential"] = "plain-provider-secret"

        result = verify_framework_runtime_service_provider_receipt(
            tampered,
            provider_export=provider_export,
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
        self.assertIn("framework runtime service provider credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_provider_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            provider_export, service_worker, service, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._sources()
            provider_export_path = tmp / "framework-runtime-service-provider-export.json"
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            operation_path = tmp / "framework-hook-operation.json"
            runtime_audit_path = tmp / "framework-runtime-audit.json"
            worker_path = tmp / "framework-runtime-worker.json"
            storage_receipt_path = tmp / "framework-runtime-storage.json"
            service_path = tmp / "framework-runtime-service.json"
            service_worker_path = tmp / "framework-runtime-service-worker.json"
            receipt_path = tmp / "framework-runtime-service-provider.json"
            entry_path = tmp / "framework-runtime-service-provider-entry.json"
            state_path = tmp / "evidence-chain.json"
            _write_json(provider_export_path, provider_export)
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
                + ["framework-runtime-service-provider", str(provider_export_path)]
                + source_args
                + [
                    "--mode",
                    "provider-export",
                    "--environment",
                    "aitrade-prod",
                    "--provider",
                    "redpanda-clickhouse-postgres-kms",
                    "--endpoint-url",
                    "https://storage.example/aitrade/framework-runtime/service-provider-export",
                    "--credential-ref",
                    "env:FRAMEWORK_RUNTIME_SERVICE_PROVIDER_TOKEN",
                    "--request-hash",
                    "sha256:framework-runtime-service-provider-request",
                    "--response-status",
                    "200",
                    "--response-hash",
                    "sha256:framework-runtime-service-provider-response",
                    "--actor-ref",
                    "oidc:trustai.example/framework-runtime-service-provider-worker",
                    "--exported-at",
                    "2026-07-09T00:45:00Z",
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
                base + ["framework-runtime-service-provider-verify", str(receipt_path), "--provider-export", str(provider_export_path)] + source_args,
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + ["framework-runtime-service-provider-append", str(receipt_path), "--provider-export", str(provider_export_path)]
                + source_args
                + ["--state", str(state_path), "--tenant", "framework-runtime-service-provider-cli", "--out", str(entry_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_runtime_service_provider_receipt(
            receipt,
            provider_export=provider_export,
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
        self.assertEqual(receipt["provider_receipt_id"], entry["payload"]["provider_receipt_id"])


if __name__ == "__main__":
    unittest.main()