import base64
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
    RECORDED_EXPORT_ARTIFACTS,
    write_framework_runtime_service_authority_recorded_export,
)
from trustai.framework_runtime_service_authority_recorded_export_provider import (
    write_framework_runtime_service_authority_recorded_export_provider_receipt,
)
from trustai.framework_runtime_service_authority_recorded_export_provider_bundle import (
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_SCHEMA,
    append_framework_runtime_service_authority_recorded_export_provider_bundle,
    build_framework_runtime_service_authority_recorded_export_provider_bundle,
    verify_framework_runtime_service_authority_recorded_export_provider_bundle,
)
from trustai.framework_runtime_service_authority_recorded_export_worker import (
    write_framework_runtime_service_authority_recorded_export_worker_receipt,
)

from tests import test_framework_runtime_service_authority_recorded_export_provider as provider_fixtures
from tests import test_framework_runtime_service_authority_recorded_export_worker as worker_fixtures


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = provider_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportProviderTests()
        return helper._receipt(tmp)

    def _bundle(self, tmp: Path):
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
        ) = self._sources(tmp)
        bundle = build_framework_runtime_service_authority_recorded_export_provider_bundle(
            receipt,
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
            mode="offline-review",
            environment="aitrade-prod",
            reviewer_ref="oidc:auditor.example/framework-runtime-reviewer",
            generated_at="2026-07-09T01:16:00Z",
        )
        return bundle, receipt, provider_export, recorded_export_worker, recorded_export, paths

    def test_framework_runtime_service_authority_recorded_export_provider_bundle_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, receipt, provider_export, recorded_export_worker, recorded_export, _ = self._bundle(tmp)
            result = verify_framework_runtime_service_authority_recorded_export_provider_bundle(bundle)
            chain = EvidenceChain(tmp / "evidence-chain.json", tenant_id="framework-runtime-service-authority-recorded-export-provider-bundle")
            entry = append_framework_runtime_service_authority_recorded_export_provider_bundle(chain, bundle)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_SCHEMA, bundle["schema"])
        self.assertEqual(len(RECORDED_EXPORT_ARTIFACTS), bundle["summary"]["source_artifact_count"])
        self.assertEqual(receipt["provider_receipt_id"], bundle["source"]["provider_receipt_id"])
        self.assertEqual(provider_export["export_ref"], bundle["source"]["provider_export_ref"])
        self.assertEqual(recorded_export_worker["worker_operation_id"], bundle["source"]["recorded_export_worker_operation_id"])
        self.assertEqual(recorded_export["recorded_export_id"], bundle["source"]["recorded_export_id"])
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
        self.assertEqual({"passed": 3}, entry["payload"]["control_summary"])

    def test_framework_runtime_service_authority_recorded_export_provider_bundle_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["provider_export"]["request_records"][0]["response_hash"] = "sha256:tampered-response"
            result = verify_framework_runtime_service_authority_recorded_export_provider_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("bundle_id" in error for error in result.errors))
        self.assertTrue(any("source replay" in error for error in result.errors))

    def test_framework_runtime_service_authority_recorded_export_provider_bundle_detects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["source_artifacts"][0]["content_b64"] = base64.b64encode(b"{}").decode("ascii")
            result = verify_framework_runtime_service_authority_recorded_export_provider_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("source artifact sha256 mismatch" in error for error in result.errors))
        self.assertTrue(any("source artifact does not match embedded source" in error for error in result.errors))

    def test_framework_runtime_service_authority_recorded_export_provider_bundle_rejects_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["provider_receipt"]["credential"] = "plain-provider-secret"
            result = verify_framework_runtime_service_authority_recorded_export_provider_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_authority_recorded_export_provider_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
                receipt,
                provider_export,
                recorded_export_worker,
                recorded_export,
                paths,
                *_,
            ) = self._sources(tmp)
            receipt_path = tmp / "framework-runtime-service-authority-recorded-export-provider.json"
            provider_export_path = tmp / "framework-runtime-service-authority-recorded-export-provider-export.json"
            recorded_export_worker_path = tmp / "framework-runtime-service-authority-recorded-export-worker.json"
            recorded_export_path = tmp / "framework-runtime-service-authority-recorded-export.json"
            bundle_path = tmp / "framework-runtime-service-authority-recorded-export-provider-bundle.json"
            entry_path = tmp / "framework-runtime-service-authority-recorded-export-provider-bundle-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_runtime_service_authority_recorded_export_provider_receipt(receipt_path, receipt)
            _write_json(provider_export_path, provider_export)
            write_framework_runtime_service_authority_recorded_export_worker_receipt(recorded_export_worker_path, recorded_export_worker)
            write_framework_runtime_service_authority_recorded_export(recorded_export_path, recorded_export)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = worker_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportWorkerTests()._source_args(paths)

            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-recorded-export-provider-bundle",
                    str(receipt_path),
                    str(provider_export_path),
                    str(recorded_export_worker_path),
                    str(recorded_export_path),
                ]
                + source_args
                + [
                    "--root",
                    str(ROOT),
                    "--mode",
                    "offline-review",
                    "--environment",
                    "aitrade-prod",
                    "--reviewer-ref",
                    "oidc:auditor.example/framework-runtime-reviewer",
                    "--generated-at",
                    "2026-07-09T01:16:00Z",
                    "--out",
                    str(bundle_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["framework-runtime-service-authority-recorded-export-provider-bundle-verify", str(bundle_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-recorded-export-provider-bundle-append",
                    str(bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-service-authority-recorded-export-provider-bundle-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_SCHEMA, bundle["schema"])
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])


if __name__ == "__main__":
    unittest.main()
