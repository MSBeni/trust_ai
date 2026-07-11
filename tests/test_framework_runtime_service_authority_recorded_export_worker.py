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
from trustai.framework_runtime_service_authority_recorded_export import (
    write_framework_runtime_service_authority_recorded_export,
)
from trustai.framework_runtime_service_authority_recorded_export_worker import (
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_SCHEMA,
    append_framework_runtime_service_authority_recorded_export_worker_receipt,
    build_framework_runtime_service_authority_recorded_export_worker_receipt,
    verify_framework_runtime_service_authority_recorded_export_worker_receipt,
)

from tests import test_framework_runtime_service_authority_recorded_export as recorded_export_fixtures


ROOT = Path(__file__).resolve().parents[1]


class FrameworkRuntimeServiceAuthorityRecordedExportWorkerTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = recorded_export_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportTests()
        return helper._recorded_export(tmp)

    def _receipt(self, tmp: Path):
        (
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
        receipt = build_framework_runtime_service_authority_recorded_export_worker_receipt(
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
            mode="hosted-worker",
            environment="aitrade-prod",
            worker_ref="worker:framework-runtime-service-authority-recorded-export",
            run_ref="worker-run:framework-runtime-service-authority-recorded-export/lg-trace-001",
            operation_kind="recorded_export_capture",
            actor_ref="oidc:trustai.example/framework-runtime-authority-recorded-export-worker",
            schedule_ref="schedule:framework-runtime-service-authority-recorded-export/5m",
            cadence_seconds=300,
            lease_ref="lease:framework-runtime-service-authority-recorded-export/lg-trace-001",
            checkpoint_ref="checkpoint:framework-runtime-service-authority-recorded-export",
            checkpoint_hash="sha256:framework-runtime-service-authority-recorded-export-worker-checkpoint",
            previous_cursor_ref="cursor:framework-runtime-service-authority-recorded-export/before-lg-trace-001",
            next_cursor_ref="cursor:framework-runtime-service-authority-recorded-export/after-lg-trace-001",
            queue_ref="queue:framework-runtime-service-authority-recorded-export",
            queue_message_ref="queue-message:framework-runtime-service-authority-recorded-export/lg-trace-001",
            queue_message_hash="sha256:framework-runtime-service-authority-recorded-export-worker-queue-message",
            dead_letter_queue_ref="queue:framework-runtime-service-authority-recorded-export-dlq",
            recorded_export_ref="recorded-export:framework-runtime-service-authority/lg-trace-001",
            recorded_export_storage_ref="worm:framework-runtime-service-authority-recorded-export/lg-trace-001",
            recorded_export_storage_hash=content_hash(recorded_export),
            artifact_archive_ref="worm:framework-runtime-service-authority-recorded-export/archive-lg-trace-001",
            artifact_archive_hash="sha256:framework-runtime-service-authority-recorded-export-archive",
            artifact_manifest_ref="worm:framework-runtime-service-authority-recorded-export/manifest-lg-trace-001",
            artifact_manifest_hash=content_hash(recorded_export["recorded_artifacts"]),
            storage_write_ref="storage-write:framework-runtime-service-authority-recorded-export/lg-trace-001",
            storage_write_hash="sha256:framework-runtime-service-authority-recorded-export-storage-write",
            request_hash="sha256:framework-runtime-service-authority-recorded-export-worker-request",
            response_status=200,
            response_hash="sha256:framework-runtime-service-authority-recorded-export-worker-response",
            metrics_ref="metrics:framework-runtime-service-authority-recorded-export/workers",
            audit_log_ref="audit-log:framework-runtime-service-authority-recorded-export/workers",
            audit_log_root="sha256:framework-runtime-service-authority-recorded-export-worker-audit-root",
            retention_until="2033-07-09T01:20:00Z",
            credential_ref="env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_TOKEN",
            evidence_refs=["evidence:framework-runtime-service-authority/recorded-export-worker"],
            require_fresh=True,
            started_at="2026-07-09T01:13:00Z",
            completed_at="2026-07-09T01:14:00Z",
            next_run_at="2026-07-09T01:19:00Z",
        )
        return (
            receipt,
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

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "worker_operation_id", "signatures")
        worker_operation_id = content_hash(body)
        receipt["worker_operation_id"] = worker_operation_id
        receipt["signatures"] = [
            sign_value(
                {
                    "worker_operation_id": worker_operation_id,
                    "framework_runtime_service_authority_recorded_export_worker": body,
                }
            )
        ]

    def test_framework_runtime_service_authority_recorded_export_worker_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
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
            result = verify_framework_runtime_service_authority_recorded_export_worker_receipt(
                receipt,
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
                require_fresh=True,
                now="2026-07-09T01:14:00Z",
            )
            chain = EvidenceChain.load(
                tmp / "chain.json",
                tenant_id="framework-runtime-service-authority-recorded-export-worker-test",
            )
            entry = append_framework_runtime_service_authority_recorded_export_worker_receipt(
                chain,
                receipt,
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
                require_fresh=True,
                now="2026-07-09T01:14:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_SCHEMA, receipt["schema"])
            self.assertTrue(result.warnings)
            self.assertEqual(recorded_export["recorded_export_id"], receipt["recorded_export"]["recorded_export_id"])
            self.assertEqual(content_hash(recorded_export), receipt["execution"]["recorded_export_storage_hash"])
            self.assertEqual({"passed": 6}, entry["payload"]["control_status_summary"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_authority_recorded_export_worker_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
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
            tampered = copy.deepcopy(recorded_export)
            tampered["recorded_artifacts"]["artifact_count"] = 999

            result = verify_framework_runtime_service_authority_recorded_export_worker_receipt(
                receipt,
                recorded_export=tampered,
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
                require_fresh=True,
                now="2026-07-09T01:14:00Z",
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("recorded export binding does not match" in error for error in result.errors))
            self.assertTrue(any("recorded_export_storage_hash" in error for error in result.errors))
            self.assertTrue(any("source:" in error for error in result.errors))

    def test_framework_runtime_service_authority_recorded_export_worker_detects_storage_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
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
            tampered["execution"]["recorded_export_storage_hash"] = "sha256:wrong-recorded-export"

            result = verify_framework_runtime_service_authority_recorded_export_worker_receipt(
                tampered,
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
                require_fresh=True,
                now="2026-07-09T01:14:00Z",
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("recorded_export_storage_hash" in error for error in result.errors))

    def test_framework_runtime_service_authority_recorded_export_worker_requires_complete_summaries_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            receipt = self._receipt(Path(tmp_dir))[0]
        cases = [
            ("missing_binding_key", "recorded_export.artifact_content_root is required"),
            ("nonpositive_artifact_count", "recorded_export.artifact_count must be positive"),
            (
                "missing_source_artifact",
                "source_artifacts missing: framework-runtime-service-provider-export",
            ),
        ]
        for case_name, expected_error in cases:
            with self.subTest(case=case_name):
                tampered = copy.deepcopy(receipt)
                if case_name == "missing_binding_key":
                    tampered["recorded_export"].pop("artifact_content_root")
                elif case_name == "nonpositive_artifact_count":
                    tampered["recorded_export"]["artifact_count"] = 0
                else:
                    tampered["source_artifacts"] = [
                        artifact
                        for artifact in tampered["source_artifacts"]
                        if artifact.get("kind") != "framework-runtime-service-provider-export"
                    ]
                self._resign_receipt(tampered)

                result = verify_framework_runtime_service_authority_recorded_export_worker_receipt(
                    tampered,
                    now="2026-07-09T01:14:00Z",
                )

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_framework_runtime_service_authority_recorded_export_worker_rejects_raw_credential(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
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
            tampered["credential"] = "raw-secret-token"

            result = verify_framework_runtime_service_authority_recorded_export_worker_receipt(
                tampered,
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
                require_fresh=True,
                now="2026-07-09T01:14:00Z",
            )

            self.assertFalse(result.ok)
            self.assertIn(
                "framework runtime service authority recorded export worker credential must be a redacted reference",
                result.errors,
            )
            self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_authority_recorded_export_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                recorded_export,
                paths,
                *_,
            ) = self._sources(tmp)
            recorded_export_path = tmp / "framework-runtime-service-authority-recorded-export.json"
            receipt_path = tmp / "framework-runtime-service-authority-recorded-export-worker.json"
            entry_path = tmp / "framework-runtime-service-authority-recorded-export-worker-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_runtime_service_authority_recorded_export(recorded_export_path, recorded_export)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = self._source_args(paths)
            worker_args = [
                "--mode",
                "hosted-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:framework-runtime-service-authority-recorded-export",
                "--run-ref",
                "worker-run:framework-runtime-service-authority-recorded-export/lg-trace-001",
                "--operation-kind",
                "recorded_export_capture",
                "--actor-ref",
                "oidc:trustai.example/framework-runtime-authority-recorded-export-worker",
                "--schedule-ref",
                "schedule:framework-runtime-service-authority-recorded-export/5m",
                "--cadence-seconds",
                "300",
                "--lease-ref",
                "lease:framework-runtime-service-authority-recorded-export/lg-trace-001",
                "--checkpoint-ref",
                "checkpoint:framework-runtime-service-authority-recorded-export",
                "--checkpoint-hash",
                "sha256:framework-runtime-service-authority-recorded-export-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:framework-runtime-service-authority-recorded-export/before-lg-trace-001",
                "--next-cursor-ref",
                "cursor:framework-runtime-service-authority-recorded-export/after-lg-trace-001",
                "--queue-ref",
                "queue:framework-runtime-service-authority-recorded-export",
                "--queue-message-ref",
                "queue-message:framework-runtime-service-authority-recorded-export/lg-trace-001",
                "--queue-message-hash",
                "sha256:framework-runtime-service-authority-recorded-export-worker-queue-message",
                "--dead-letter-queue-ref",
                "queue:framework-runtime-service-authority-recorded-export-dlq",
                "--recorded-export-ref",
                "recorded-export:framework-runtime-service-authority/lg-trace-001",
                "--recorded-export-storage-ref",
                "worm:framework-runtime-service-authority-recorded-export/lg-trace-001",
                "--recorded-export-storage-hash",
                content_hash(recorded_export),
                "--artifact-archive-ref",
                "worm:framework-runtime-service-authority-recorded-export/archive-lg-trace-001",
                "--artifact-archive-hash",
                "sha256:framework-runtime-service-authority-recorded-export-archive",
                "--artifact-manifest-ref",
                "worm:framework-runtime-service-authority-recorded-export/manifest-lg-trace-001",
                "--artifact-manifest-hash",
                content_hash(recorded_export["recorded_artifacts"]),
                "--storage-write-ref",
                "storage-write:framework-runtime-service-authority-recorded-export/lg-trace-001",
                "--storage-write-hash",
                "sha256:framework-runtime-service-authority-recorded-export-storage-write",
                "--request-hash",
                "sha256:framework-runtime-service-authority-recorded-export-worker-request",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:framework-runtime-service-authority-recorded-export-worker-response",
                "--metrics-ref",
                "metrics:framework-runtime-service-authority-recorded-export/workers",
                "--audit-log-ref",
                "audit-log:framework-runtime-service-authority-recorded-export/workers",
                "--audit-log-root",
                "sha256:framework-runtime-service-authority-recorded-export-worker-audit-root",
                "--retention-until",
                "2033-07-09T01:20:00Z",
                "--credential-ref",
                "env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_TOKEN",
                "--evidence-ref",
                "evidence:framework-runtime-service-authority/recorded-export-worker",
                "--require-fresh",
                "--started-at",
                "2026-07-09T01:13:00Z",
                "--completed-at",
                "2026-07-09T01:14:00Z",
                "--next-run-at",
                "2026-07-09T01:19:00Z",
            ]

            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-recorded-export-worker",
                    str(recorded_export_path),
                ]
                + source_args
                + worker_args
                + ["--root", str(ROOT), "--out", str(receipt_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-recorded-export-worker-verify",
                    str(receipt_path),
                    "--recorded-export",
                    str(recorded_export_path),
                ]
                + source_args
                + ["--root", str(ROOT), "--require-fresh", "--now", "2026-07-09T01:14:00Z"],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-recorded-export-worker-append",
                    str(receipt_path),
                    str(recorded_export_path),
                ]
                + source_args
                + [
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T01:14:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-service-authority-recorded-export-worker-cli",
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

        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_SCHEMA, receipt["schema"])
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_WORKER_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])

    def _source_args(self, paths: dict[str, Path]) -> list[str]:
        return [
            "--authority-attestation",
            str(paths["authority_attestation"]),
            "--authority-provider-receipt",
            str(paths["authority_provider_receipt"]),
            "--authority-provider-export",
            str(paths["authority_provider_export"]),
            "--authority-worker",
            str(paths["authority_worker"]),
            "--authority-dossier",
            str(paths["authority_dossier"]),
            "--provider-receipt",
            str(paths["service_provider_receipt"]),
            "--provider-export",
            str(paths["service_provider_export"]),
            "--service-worker",
            str(paths["service_worker"]),
            "--service-attestation",
            str(paths["service_attestation"]),
            "--storage-receipt",
            str(paths["storage_receipt"]),
            "--storage-export",
            str(paths["storage_export"]),
            "--worker",
            str(paths["runtime_worker"]),
            "--runtime-audit",
            str(paths["runtime_audit"]),
            "--audit-export",
            str(paths["audit_export"]),
            "--operation",
            str(paths["hook_operation"]),
            "--trace",
            str(paths["trace_payload"]),
            "--release",
            str(paths["hook_release"]),
            "--matrix",
            str(paths["adapter_matrix"]),
        ]


if __name__ == "__main__":
    unittest.main()
