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
from trustai.framework_runtime_service_authority_worker import (
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_SCHEMA,
    append_framework_runtime_service_authority_worker_receipt,
    build_framework_runtime_service_authority_worker_receipt,
    verify_framework_runtime_service_authority_worker_receipt,
)
from trustai.framework_runtime_service_provider import write_framework_runtime_service_provider_receipt
from trustai.framework_runtime_service_worker import write_framework_runtime_service_worker_receipt
from trustai.framework_runtime_storage import write_framework_runtime_storage_receipt
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_service_authority as authority_fixtures


ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"
STORAGE_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-storage-export.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class FrameworkRuntimeServiceAuthorityWorkerTests(unittest.TestCase):
    def _sources(self):
        helper = authority_fixtures.FrameworkRuntimeServiceAuthorityTests()
        return helper._dossier()

    def _receipt(self):
        (
            dossier,
            provider_receipt,
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
        ) = self._sources()
        receipt = build_framework_runtime_service_authority_worker_receipt(
            dossier,
            provider_receipt=provider_receipt,
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
            mode="scheduled-worker",
            environment="aitrade-prod",
            worker_ref="worker:framework-runtime-service-authority/refresher",
            run_ref="worker-run:framework-runtime-service-authority/lg-trace-001",
            operation_kind="authority_evidence_refresh",
            actor_ref="oidc:trustai.example/framework-runtime-authority-worker",
            schedule_ref="schedule:framework-runtime-service-authority/5m",
            cadence_seconds=300,
            lease_ref="lease:framework-runtime-service-authority/lg-trace-001",
            checkpoint_ref="checkpoint:framework-runtime-service-authority",
            checkpoint_hash="sha256:framework-runtime-service-authority-worker-checkpoint",
            previous_cursor_ref="cursor:framework-runtime-service-authority/before-lg-trace-001",
            next_cursor_ref="cursor:framework-runtime-service-authority/after-lg-trace-001",
            queue_ref="queue:framework-runtime-service-authority",
            queue_message_ref="queue-message:framework-runtime-service-authority/lg-trace-001",
            queue_message_hash="sha256:framework-runtime-service-authority-worker-queue-message",
            dead_letter_queue_ref="queue:framework-runtime-service-authority-dlq",
            authority_request_ref="authority-request:framework-runtime-service/lg-trace-001",
            dossier_storage_ref="worm:framework-runtime-service-authority/lg-trace-001",
            dossier_storage_hash=content_hash(dossier),
            report_storage_ref="worm:framework-runtime-service-authority/report-lg-trace-001",
            report_storage_hash="sha256:framework-runtime-service-authority-worker-report",
            request_hash="sha256:framework-runtime-service-authority-worker-request",
            response_status=200,
            response_hash="sha256:framework-runtime-service-authority-worker-response",
            metrics_ref="metrics:framework-runtime-service-authority/workers",
            audit_log_ref="audit-log:framework-runtime-service-authority/workers",
            audit_log_root="sha256:framework-runtime-service-authority-worker-audit-root",
            retention_until="2033-07-09T01:05:00Z",
            credential_ref="env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_TOKEN",
            evidence_refs=["evidence:framework-runtime-service-authority/worker"],
            require_fresh=True,
            started_at="2026-07-09T01:04:00Z",
            completed_at="2026-07-09T01:05:00Z",
            next_run_at="2026-07-09T01:10:00Z",
        )
        return (
            receipt,
            dossier,
            provider_receipt,
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
        )

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "worker_operation_id", "signatures")
        worker_operation_id = content_hash(body)
        receipt["worker_operation_id"] = worker_operation_id
        receipt["signatures"] = [
            sign_value({"worker_operation_id": worker_operation_id, "framework_runtime_service_authority_worker": body})
        ]

    def test_framework_runtime_service_authority_worker_verifies_and_appends(self):
        (
            receipt,
            dossier,
            provider_receipt,
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
        ) = self._receipt()
        result = verify_framework_runtime_service_authority_worker_receipt(
            receipt,
            authority_dossier=dossier,
            provider_receipt=provider_receipt,
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
            require_fresh=True,
            now="2026-07-09T01:05:00Z",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-service-authority-worker-test")
            entry = append_framework_runtime_service_authority_worker_receipt(
                chain,
                receipt,
                authority_dossier=dossier,
                provider_receipt=provider_receipt,
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
                require_fresh=True,
                now="2026-07-09T01:05:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_SCHEMA, receipt["schema"])
            self.assertTrue(result.warnings)
            self.assertEqual(dossier["dossier_id"], receipt["authority"]["dossier_id"])
            self.assertEqual(content_hash(dossier), receipt["execution"]["dossier_storage_hash"])
            self.assertEqual({"deferred": 1, "passed": 5}, entry["payload"]["control_status_summary"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_authority_worker_detects_dossier_tamper(self):
        (
            receipt,
            dossier,
            provider_receipt,
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
        ) = self._receipt()
        tampered_dossier = copy.deepcopy(dossier)
        tampered_dossier["summary"]["covered_requirement_count"] = 99

        result = verify_framework_runtime_service_authority_worker_receipt(
            receipt,
            authority_dossier=tampered_dossier,
            provider_receipt=provider_receipt,
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
            require_fresh=True,
            now="2026-07-09T01:05:00Z",
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("authority binding does not match" in error for error in result.errors))
        self.assertTrue(any("dossier_storage_hash" in error for error in result.errors))

    def test_framework_runtime_service_authority_worker_requires_complete_summaries_without_sources(self):
        receipt, *_ = self._receipt()
        cases = [
            ("missing_authority_key", "authority.producer_ref is required"),
            ("nonpositive_evidence_count", "authority.authority_evidence_count must be positive"),
            ("missing_source_artifact", "source_artifacts missing: framework-runtime-service-provider-export"),
        ]
        for case_name, expected_error in cases:
            with self.subTest(case=case_name):
                tampered = copy.deepcopy(receipt)
                if case_name == "missing_authority_key":
                    tampered["authority"].pop("producer_ref")
                elif case_name == "nonpositive_evidence_count":
                    tampered["authority"]["authority_evidence_count"] = 0
                else:
                    tampered["source_artifacts"] = [
                        artifact
                        for artifact in tampered["source_artifacts"]
                        if artifact.get("kind") != "framework-runtime-service-provider-export"
                    ]
                self._resign_receipt(tampered)

                result = verify_framework_runtime_service_authority_worker_receipt(
                    tampered,
                    now="2026-07-09T01:05:00Z",
                )

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_framework_runtime_service_authority_worker_rejects_raw_credential(self):
        (
            receipt,
            dossier,
            provider_receipt,
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
        ) = self._receipt()
        tampered = copy.deepcopy(receipt)
        tampered["credential"] = "plain-worker-secret"

        result = verify_framework_runtime_service_authority_worker_receipt(
            tampered,
            authority_dossier=dossier,
            provider_receipt=provider_receipt,
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
            require_fresh=True,
            now="2026-07-09T01:05:00Z",
        )

        self.assertFalse(result.ok)
        self.assertIn("framework runtime service authority worker credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_authority_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                dossier,
                provider_receipt,
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
            ) = self._sources()
            dossier_path = tmp / "framework-runtime-service-authority.json"
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
            receipt_path = tmp / "framework-runtime-service-authority-worker.json"
            entry_path = tmp / "framework-runtime-service-authority-worker-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_runtime_service_authority_dossier(dossier_path, dossier)
            write_framework_runtime_service_provider_receipt(provider_receipt_path, provider_receipt)
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
            worker_args = [
                "--mode",
                "scheduled-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:framework-runtime-service-authority/refresher",
                "--run-ref",
                "worker-run:framework-runtime-service-authority/lg-trace-001",
                "--operation-kind",
                "authority_evidence_refresh",
                "--actor-ref",
                "oidc:trustai.example/framework-runtime-authority-worker",
                "--schedule-ref",
                "schedule:framework-runtime-service-authority/5m",
                "--cadence-seconds",
                "300",
                "--lease-ref",
                "lease:framework-runtime-service-authority/lg-trace-001",
                "--checkpoint-ref",
                "checkpoint:framework-runtime-service-authority",
                "--checkpoint-hash",
                "sha256:framework-runtime-service-authority-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:framework-runtime-service-authority/before-lg-trace-001",
                "--next-cursor-ref",
                "cursor:framework-runtime-service-authority/after-lg-trace-001",
                "--queue-ref",
                "queue:framework-runtime-service-authority",
                "--queue-message-ref",
                "queue-message:framework-runtime-service-authority/lg-trace-001",
                "--queue-message-hash",
                "sha256:framework-runtime-service-authority-worker-queue-message",
                "--dead-letter-queue-ref",
                "queue:framework-runtime-service-authority-dlq",
                "--authority-request-ref",
                "authority-request:framework-runtime-service/lg-trace-001",
                "--dossier-storage-ref",
                "worm:framework-runtime-service-authority/lg-trace-001",
                "--dossier-storage-hash",
                content_hash(dossier),
                "--report-storage-ref",
                "worm:framework-runtime-service-authority/report-lg-trace-001",
                "--report-storage-hash",
                "sha256:framework-runtime-service-authority-worker-report",
                "--request-hash",
                "sha256:framework-runtime-service-authority-worker-request",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:framework-runtime-service-authority-worker-response",
                "--metrics-ref",
                "metrics:framework-runtime-service-authority/workers",
                "--audit-log-ref",
                "audit-log:framework-runtime-service-authority/workers",
                "--audit-log-root",
                "sha256:framework-runtime-service-authority-worker-audit-root",
                "--retention-until",
                "2033-07-09T01:05:00Z",
                "--credential-ref",
                "env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_TOKEN",
                "--evidence-ref",
                "evidence:framework-runtime-service-authority/worker",
                "--require-fresh",
                "--started-at",
                "2026-07-09T01:04:00Z",
                "--completed-at",
                "2026-07-09T01:05:00Z",
                "--next-run-at",
                "2026-07-09T01:10:00Z",
                "--now",
                "2026-07-09T01:05:00Z",
            ]

            subprocess.run(
                base
                + ["framework-runtime-service-authority-worker", str(dossier_path)]
                + source_args
                + worker_args
                + ["--out", str(receipt_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-worker-verify",
                    str(receipt_path),
                    "--authority-dossier",
                    str(dossier_path),
                ]
                + source_args
                + ["--require-fresh", "--now", "2026-07-09T01:05:00Z"],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-worker-append",
                    str(receipt_path),
                    "--authority-dossier",
                    str(dossier_path),
                ]
                + source_args
                + [
                    "--require-fresh",
                    "--now",
                    "2026-07-09T01:05:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-service-authority-worker-cli",
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

        result = verify_framework_runtime_service_authority_worker_receipt(
            receipt,
            authority_dossier=dossier,
            provider_receipt=provider_receipt,
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
            require_fresh=True,
            now="2026-07-09T01:05:00Z",
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_WORKER_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])


if __name__ == "__main__":
    unittest.main()
