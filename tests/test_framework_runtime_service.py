import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.framework_adapter_matrix import write_framework_adapter_matrix
from trustai.framework_hook_operation import write_framework_hook_operation
from trustai.framework_hook_release import write_framework_hook_release
from trustai.framework_runtime_audit import write_framework_runtime_audit_receipt
from trustai.framework_runtime_service import (
    FRAMEWORK_RUNTIME_SERVICE_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_SCHEMA,
    append_framework_runtime_service_attestation,
    build_framework_runtime_service_attestation,
    verify_framework_runtime_service_attestation,
)
from trustai.framework_runtime_storage import write_framework_runtime_storage_receipt
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_storage as storage_fixtures


ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"
STORAGE_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-storage-export.json"


class FrameworkRuntimeServiceTests(unittest.TestCase):
    def _sources(self) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict, dict]:
        helper = storage_fixtures.FrameworkRuntimeStorageTests()
        return helper._receipt()

    def _kwargs(self) -> dict:
        return {
            "root": ROOT,
            "mode": "hosted-runtime-service",
            "environment": "aitrade-prod",
            "service_ref": "service:framework-runtime/aitrade",
            "service_version": "0.1.0",
            "service_image": "ghcr.io/trustai/framework-runtime:0.1.0",
            "service_image_digest": "sha256:framework-runtime-service-image",
            "service_binary_hash": "sha256:framework-runtime-service-binary",
            "replicas_min": 3,
            "replicas_max": 9,
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "runtime_worker_ref": "worker:framework-runtime/langgraph",
            "scheduler_ref": "schedule:framework-runtime/langgraph/continuous",
            "schedule_cadence_seconds": 30,
            "queue_ref": "queue:framework-runtime/work",
            "dead_letter_queue_ref": "queue:framework-runtime/dlq",
            "lease_store_ref": "postgres:framework-runtime/leases",
            "lease_store_hash": "sha256:framework-runtime-service-lease-store",
            "checkpoint_store_ref": "postgres:framework-runtime/checkpoints",
            "checkpoint_store_hash": "sha256:framework-runtime-service-checkpoint-store",
            "cursor_store_ref": "postgres:framework-runtime/cursors",
            "idempotency_store_ref": "postgres:framework-runtime/idempotency",
            "retry_policy_ref": "policy:framework-runtime/retry-v0.1",
            "max_concurrency": 64,
            "stream_backend": "redpanda",
            "stream_ref": "redpanda:trustai/framework-runtime",
            "stream_topic": "trustai.framework.runtime.audit",
            "stream_dlq_ref": "redpanda:trustai/framework-runtime-dlq",
            "worm_store_ref": "s3-object-lock:trustai-framework-runtime/aitrade",
            "object_lock_policy_ref": "policy:framework-runtime/object-lock-7y",
            "clickhouse_ref": "clickhouse:trustai/framework_runtime",
            "clickhouse_schema_hash": "sha256:framework-runtime-service-clickhouse-schema",
            "clickhouse_backup_ref": "backup:clickhouse/framework-runtime/daily",
            "postgres_ref": "postgres:trustai/framework_runtime",
            "postgres_schema_hash": "sha256:framework-runtime-service-postgres-schema",
            "postgres_backup_ref": "backup:postgres/framework-runtime/daily",
            "mtls_policy_ref": "policy:framework-runtime/mtls-v0.1",
            "auth_policy_ref": "policy:framework-runtime/authz-v0.1",
            "tenant_isolation_ref": "tenant-isolation:framework-runtime/aitrade",
            "admission_policy_ref": "policy:framework-runtime/admission-v0.1",
            "rate_limit_policy_ref": "rate-limit:framework-runtime/tenant",
            "network_policy_ref": "netpol:framework-runtime/deny-by-default",
            "egress_policy_ref": "egress:framework-runtime/storage-only",
            "secret_store_ref": "vault:framework-runtime/secrets",
            "kms_key_ref": "kms:framework-runtime/customer-data",
            "metrics_ref": "metrics:framework-runtime/service",
            "alert_policy_ref": "alert:framework-runtime/service",
            "audit_log_ref": "audit-log:framework-runtime/service",
            "audit_log_root": "sha256:framework-runtime-service-audit-root",
            "access_log_ref": "access-log:framework-runtime/service",
            "access_log_root": "sha256:framework-runtime-service-access-root",
            "retention_until": "2033-07-09T00:00:00Z",
            "actor_ref": "oidc:trustai.example/framework-runtime-operator",
            "credential_ref": "env:FRAMEWORK_RUNTIME_SERVICE_TOKEN",
            "evidence_refs": ["evidence:framework-runtime/service"],
            "attested_at": "2026-07-09T00:44:00Z",
        }

    def _attestation(self) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict, dict, dict]:
        storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._sources()
        attestation = build_framework_runtime_service_attestation(
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
        return attestation, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix

    def test_framework_runtime_service_verifies_and_appends(self):
        attestation, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._attestation()
        result = verify_framework_runtime_service_attestation(
            attestation,
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
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-service-test")
            entry = append_framework_runtime_service_attestation(
                chain,
                attestation,
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
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_SCHEMA, attestation["schema"])
            self.assertEqual(storage_receipt["storage_receipt_id"], attestation["source"]["storage_receipt_id"])
            self.assertEqual("service:framework-runtime/aitrade", attestation["service"]["service_ref"])
            self.assertEqual("env:FRAMEWORK_RUNTIME_SERVICE_TOKEN", attestation["operation_actor"]["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertEqual({"passed": 7}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_detects_storage_source_tamper(self):
        attestation, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._attestation()
        tampered_export = copy.deepcopy(storage_export)
        tampered_export["stream_records"][0]["stream_message_hash"] = "sha256:wrong"

        result = verify_framework_runtime_service_attestation(
            attestation,
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
        self.assertTrue(any("storage source invalid" in error for error in result.errors))
        self.assertTrue(any("source_artifacts do not match" in error for error in result.errors))

    def test_framework_runtime_service_detects_service_binding_tamper(self):
        attestation, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._attestation()
        tampered = copy.deepcopy(attestation)
        tampered["service"]["service_image_digest"] = "not-a-sha256-ref"

        result = verify_framework_runtime_service_attestation(
            tampered,
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
        self.assertTrue(any("attestation_id does not match" in error for error in result.errors))
        self.assertTrue(any("service_image_digest must be a sha256 reference" in error for error in result.errors))

    def test_framework_runtime_service_rejects_raw_credential(self):
        attestation, storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._attestation()
        tampered = copy.deepcopy(attestation)
        tampered["operation_actor"]["credential"] = "plain-secret"

        result = verify_framework_runtime_service_attestation(
            tampered,
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
        self.assertIn("framework runtime service credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            storage_receipt, storage_export, worker, runtime_audit, audit_export, operation, trace, release, matrix = self._sources()
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            operation_path = tmp / "framework-hook-operation.json"
            runtime_audit_path = tmp / "framework-runtime-audit.json"
            worker_path = tmp / "framework-runtime-worker.json"
            storage_receipt_path = tmp / "framework-runtime-storage.json"
            attestation_path = tmp / "framework-runtime-service.json"
            entry_path = tmp / "framework-runtime-service-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_adapter_matrix(matrix_path, matrix)
            write_framework_hook_release(release_path, release)
            write_framework_hook_operation(operation_path, operation)
            write_framework_runtime_audit_receipt(runtime_audit_path, runtime_audit)
            write_framework_runtime_worker_receipt(worker_path, worker)
            write_framework_runtime_storage_receipt(storage_receipt_path, storage_receipt)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
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
            service_args = [
                "--mode",
                "hosted-runtime-service",
                "--environment",
                "aitrade-prod",
                "--service-ref",
                "service:framework-runtime/aitrade",
                "--service-version",
                "0.1.0",
                "--service-image",
                "ghcr.io/trustai/framework-runtime:0.1.0",
                "--service-image-digest",
                "sha256:framework-runtime-service-image",
                "--service-binary-hash",
                "sha256:framework-runtime-service-binary",
                "--replicas-min",
                "3",
                "--replicas-max",
                "9",
                "--availability-zone",
                "us-east-1a",
                "--availability-zone",
                "us-east-1b",
                "--availability-zone",
                "us-east-1c",
                "--runtime-worker-ref",
                "worker:framework-runtime/langgraph",
                "--scheduler-ref",
                "schedule:framework-runtime/langgraph/continuous",
                "--schedule-cadence-seconds",
                "30",
                "--queue-ref",
                "queue:framework-runtime/work",
                "--dead-letter-queue-ref",
                "queue:framework-runtime/dlq",
                "--lease-store-ref",
                "postgres:framework-runtime/leases",
                "--lease-store-hash",
                "sha256:framework-runtime-service-lease-store",
                "--checkpoint-store-ref",
                "postgres:framework-runtime/checkpoints",
                "--checkpoint-store-hash",
                "sha256:framework-runtime-service-checkpoint-store",
                "--cursor-store-ref",
                "postgres:framework-runtime/cursors",
                "--idempotency-store-ref",
                "postgres:framework-runtime/idempotency",
                "--retry-policy-ref",
                "policy:framework-runtime/retry-v0.1",
                "--max-concurrency",
                "64",
                "--stream-backend",
                "redpanda",
                "--stream-ref",
                "redpanda:trustai/framework-runtime",
                "--stream-topic",
                "trustai.framework.runtime.audit",
                "--stream-dlq-ref",
                "redpanda:trustai/framework-runtime-dlq",
                "--worm-store-ref",
                "s3-object-lock:trustai-framework-runtime/aitrade",
                "--object-lock-policy-ref",
                "policy:framework-runtime/object-lock-7y",
                "--clickhouse-ref",
                "clickhouse:trustai/framework_runtime",
                "--clickhouse-schema-hash",
                "sha256:framework-runtime-service-clickhouse-schema",
                "--clickhouse-backup-ref",
                "backup:clickhouse/framework-runtime/daily",
                "--postgres-ref",
                "postgres:trustai/framework_runtime",
                "--postgres-schema-hash",
                "sha256:framework-runtime-service-postgres-schema",
                "--postgres-backup-ref",
                "backup:postgres/framework-runtime/daily",
                "--mtls-policy-ref",
                "policy:framework-runtime/mtls-v0.1",
                "--auth-policy-ref",
                "policy:framework-runtime/authz-v0.1",
                "--tenant-isolation-ref",
                "tenant-isolation:framework-runtime/aitrade",
                "--admission-policy-ref",
                "policy:framework-runtime/admission-v0.1",
                "--rate-limit-policy-ref",
                "rate-limit:framework-runtime/tenant",
                "--network-policy-ref",
                "netpol:framework-runtime/deny-by-default",
                "--egress-policy-ref",
                "egress:framework-runtime/storage-only",
                "--secret-store-ref",
                "vault:framework-runtime/secrets",
                "--kms-key-ref",
                "kms:framework-runtime/customer-data",
                "--metrics-ref",
                "metrics:framework-runtime/service",
                "--alert-policy-ref",
                "alert:framework-runtime/service",
                "--audit-log-ref",
                "audit-log:framework-runtime/service",
                "--audit-log-root",
                "sha256:framework-runtime-service-audit-root",
                "--access-log-ref",
                "access-log:framework-runtime/service",
                "--access-log-root",
                "sha256:framework-runtime-service-access-root",
                "--retention-until",
                "2033-07-09T00:00:00Z",
                "--actor-ref",
                "oidc:trustai.example/framework-runtime-operator",
                "--credential-ref",
                "env:FRAMEWORK_RUNTIME_SERVICE_TOKEN",
                "--evidence-ref",
                "evidence:framework-runtime/service",
                "--attested-at",
                "2026-07-09T00:44:00Z",
                "--out",
                str(attestation_path),
            ]

            subprocess.run(
                base + ["framework-runtime-service"] + source_args + service_args,
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["framework-runtime-service-verify", str(attestation_path)] + source_args,
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + ["framework-runtime-service-append", str(attestation_path)]
                + source_args
                + ["--state", str(state_path), "--tenant", "framework-runtime-service-cli", "--out", str(entry_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_runtime_service_attestation(
            attestation,
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
        self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])


if __name__ == "__main__":
    unittest.main()