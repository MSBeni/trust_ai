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
from trustai.framework_runtime_service import write_framework_runtime_service_attestation
from trustai.framework_runtime_service_authority import write_framework_runtime_service_authority_dossier
from trustai.framework_runtime_service_authority_attestation import write_framework_runtime_service_authority_attestation
from trustai.framework_runtime_service_authority_provider import write_framework_runtime_service_authority_provider_receipt
from trustai.framework_runtime_service_authority_recorded_export import (
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_SCHEMA,
    RECORDED_EXPORT_ARTIFACTS,
    append_framework_runtime_service_authority_recorded_export,
    build_framework_runtime_service_authority_recorded_export,
    verify_framework_runtime_service_authority_recorded_export,
)
from trustai.framework_runtime_service_authority_worker import write_framework_runtime_service_authority_worker_receipt
from trustai.framework_runtime_service_provider import write_framework_runtime_service_provider_receipt
from trustai.framework_runtime_service_worker import write_framework_runtime_service_worker_receipt
from trustai.framework_runtime_storage import write_framework_runtime_storage_receipt
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_service_authority_attestation as authority_attestation_fixtures


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class FrameworkRuntimeServiceAuthorityRecordedExportTests(unittest.TestCase):
    def _sources(self):
        helper = authority_attestation_fixtures.FrameworkRuntimeServiceAuthorityAttestationTests()
        return helper._attestation()

    def _write_sources(self, tmp: Path, values: tuple) -> dict[str, Path]:
        (
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
        paths = {
            "authority_attestation": tmp / "framework-runtime-service-authority-attestation.json",
            "authority_provider_receipt": tmp / "framework-runtime-service-authority-provider.json",
            "authority_provider_export": tmp / "framework-runtime-service-authority-provider-export.json",
            "authority_worker": tmp / "framework-runtime-service-authority-worker.json",
            "authority_dossier": tmp / "framework-runtime-service-authority.json",
            "service_provider_receipt": tmp / "framework-runtime-service-provider.json",
            "service_provider_export": tmp / "framework-runtime-service-provider-export.json",
            "service_worker": tmp / "framework-runtime-service-worker.json",
            "service_attestation": tmp / "framework-runtime-service.json",
            "storage_receipt": tmp / "framework-runtime-storage.json",
            "storage_export": tmp / "framework-runtime-storage-export.json",
            "runtime_worker": tmp / "framework-runtime-worker.json",
            "runtime_audit": tmp / "framework-runtime-audit.json",
            "audit_export": tmp / "framework-runtime-audit-export.json",
            "hook_operation": tmp / "framework-hook-operation.json",
            "trace_payload": tmp / "framework-traces.json",
            "hook_release": tmp / "framework-hook-release.json",
            "adapter_matrix": tmp / "framework-adapter-matrix.json",
        }
        write_framework_runtime_service_authority_attestation(paths["authority_attestation"], authority_attestation)
        write_framework_runtime_service_authority_provider_receipt(paths["authority_provider_receipt"], authority_provider_receipt)
        _write_json(paths["authority_provider_export"], authority_provider_export)
        write_framework_runtime_service_authority_worker_receipt(paths["authority_worker"], authority_worker)
        write_framework_runtime_service_authority_dossier(paths["authority_dossier"], authority_dossier)
        write_framework_runtime_service_provider_receipt(paths["service_provider_receipt"], service_provider_receipt)
        _write_json(paths["service_provider_export"], service_provider_export)
        write_framework_runtime_service_worker_receipt(paths["service_worker"], service_worker)
        write_framework_runtime_service_attestation(paths["service_attestation"], service)
        write_framework_runtime_storage_receipt(paths["storage_receipt"], storage_receipt)
        _write_json(paths["storage_export"], storage_export)
        write_framework_runtime_worker_receipt(paths["runtime_worker"], worker)
        write_framework_runtime_audit_receipt(paths["runtime_audit"], runtime_audit)
        _write_json(paths["audit_export"], audit_export)
        write_framework_hook_operation(paths["hook_operation"], operation)
        _write_json(paths["trace_payload"], trace)
        write_framework_hook_release(paths["hook_release"], release)
        write_framework_adapter_matrix(paths["adapter_matrix"], matrix)
        return paths

    def _recorded_export(self, tmp: Path):
        values = self._sources()
        paths = self._write_sources(tmp, values)
        (
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
        receipt = build_framework_runtime_service_authority_recorded_export(
            authority_attestation,
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
            mode="provider-recorded-export",
            environment="aitrade-prod",
            recorder_ref="worker:framework-runtime-service-authority-recorded-export",
            storage_backend="s3-object-lock",
            retention_ref="retention:framework-runtime-service-authority-recorded-export/7y",
            retention_until="2033-07-09T01:12:00Z",
            credential_ref="env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_TOKEN",
            recorded_at="2026-07-09T01:12:00Z",
            require_fresh=True,
        )
        return (receipt, paths, *values)

    def test_framework_runtime_service_authority_recorded_export_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
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
            ) = self._recorded_export(tmp)
            result = verify_framework_runtime_service_authority_recorded_export(
                receipt,
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
                now="2026-07-09T01:12:00Z",
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="framework-runtime-service-authority-recorded-export-test")
            entry = append_framework_runtime_service_authority_recorded_export(
                chain,
                receipt,
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
                now="2026-07-09T01:12:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_SCHEMA, receipt["schema"])
            self.assertTrue(result.warnings)
            self.assertEqual(len(RECORDED_EXPORT_ARTIFACTS), receipt["recorded_artifacts"]["artifact_count"])
            self.assertEqual("env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_TOKEN", receipt["recorder"]["credential"]["ref"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["recorded_export_id"], entry["payload"]["recorded_export_id"])
            self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_authority_recorded_export_detects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
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
            ) = self._recorded_export(tmp)
            tampered_export = copy.deepcopy(authority_provider_export)
            tampered_export["request_records"][0]["response_hash"] = "sha256:tampered-recorded-export"
            _write_json(paths["authority_provider_export"], tampered_export)

            result = verify_framework_runtime_service_authority_recorded_export(
                receipt,
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
            self.assertTrue(any("artifact replay failed" in error for error in result.errors))
            self.assertTrue(any("content hash does not match" in error for error in result.errors))

    def test_framework_runtime_service_authority_recorded_export_detects_attestation_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
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
            ) = self._recorded_export(tmp)
            tampered_attestation = copy.deepcopy(authority_attestation)
            tampered_attestation["issuer"] = "Changed authority"
            write_framework_runtime_service_authority_attestation(paths["authority_attestation"], tampered_attestation)

            result = verify_framework_runtime_service_authority_recorded_export(
                receipt,
                authority_attestation=tampered_attestation,
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
            self.assertTrue(any("source binding does not match" in error for error in result.errors))
            self.assertTrue(any("attestation source" in error for error in result.errors))

    def test_framework_runtime_service_authority_recorded_export_rejects_raw_credential(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
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
            ) = self._recorded_export(tmp)
            tampered = copy.deepcopy(receipt)
            tampered["recorder"]["credential"] = "plain-recorded-export-secret"

            result = verify_framework_runtime_service_authority_recorded_export(
                tampered,
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
            self.assertIn("framework runtime service authority recorded export credential must be a redacted reference", result.errors)
            self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_authority_recorded_export_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            values = self._sources()
            paths = self._write_sources(tmp, values)
            receipt_path = tmp / "framework-runtime-service-authority-recorded-export.json"
            entry_path = tmp / "framework-runtime-service-authority-recorded-export-entry.json"
            state_path = tmp / "evidence-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
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
                "--root",
                str(ROOT),
            ]

            subprocess.run(
                base
                + ["framework-runtime-service-authority-recorded-export", str(paths["authority_attestation"])]
                + source_args
                + [
                    "--mode",
                    "provider-recorded-export",
                    "--environment",
                    "aitrade-prod",
                    "--recorder-ref",
                    "worker:framework-runtime-service-authority-recorded-export",
                    "--storage-backend",
                    "s3-object-lock",
                    "--retention-ref",
                    "retention:framework-runtime-service-authority-recorded-export/7y",
                    "--retention-until",
                    "2033-07-09T01:12:00Z",
                    "--credential-ref",
                    "env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_TOKEN",
                    "--recorded-at",
                    "2026-07-09T01:12:00Z",
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
                    "framework-runtime-service-authority-recorded-export-verify",
                    str(receipt_path),
                    "--authority-attestation",
                    str(paths["authority_attestation"]),
                ]
                + source_args
                + ["--require-fresh", "--now", "2026-07-09T01:12:00Z"],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-recorded-export-append",
                    str(receipt_path),
                    "--authority-attestation",
                    str(paths["authority_attestation"]),
                ]
                + source_args
                + [
                    "--require-fresh",
                    "--now",
                    "2026-07-09T01:12:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-service-authority-recorded-export-cli",
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

        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_SCHEMA, receipt["schema"])
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["recorded_export_id"], entry["payload"]["recorded_export_id"])


if __name__ == "__main__":
    unittest.main()
