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
from trustai.framework_runtime_service_authority_attestation import (
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_SCHEMA,
    append_framework_runtime_service_authority_attestation,
    build_framework_runtime_service_authority_attestation,
    verify_framework_runtime_service_authority_attestation,
)
from trustai.framework_runtime_service_authority_provider import write_framework_runtime_service_authority_provider_receipt
from trustai.framework_runtime_service_authority_worker import write_framework_runtime_service_authority_worker_receipt
from trustai.framework_runtime_service_provider import write_framework_runtime_service_provider_receipt
from trustai.framework_runtime_service_worker import write_framework_runtime_service_worker_receipt
from trustai.framework_runtime_storage import write_framework_runtime_storage_receipt
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_service_authority_provider as authority_provider_fixtures


ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"
STORAGE_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-storage-export.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class FrameworkRuntimeServiceAuthorityAttestationTests(unittest.TestCase):
    def _sources(self):
        helper = authority_provider_fixtures.FrameworkRuntimeServiceAuthorityProviderTests()
        return helper._receipt()

    def _attestation_evidence(self) -> list[dict]:
        return [
            {
                "evidence_kind": "authority-review",
                "evidence_ref": "authority-review:framework-runtime-service/lg-trace-001",
                "evidence_hash": "sha256:framework-runtime-service-authority-review",
                "description": "Production authority reviewer accepted the provider export evidence set.",
                "issuer": "TrustAI authority desk",
                "subject": "aitrade-prod framework runtime service authority",
                "source_uri": "https://audit.example/authority-review/framework-runtime-service/lg-trace-001",
                "issued_at": "2026-07-09T01:08:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
            {
                "evidence_kind": "provider-export",
                "evidence_ref": "provider-export:framework-runtime-service-authority/lg-trace-001",
                "evidence_hash": "sha256:framework-runtime-service-authority-provider-export-review",
                "description": "Provider export custody record for the authority worker evidence.",
                "issuer": "Example Provider",
                "subject": "redpanda-s3-postgres-authority export lg-trace-001",
                "source_uri": "https://provider.example/audit/framework-runtime-service-authority/lg-trace-001",
                "issued_at": "2026-07-09T01:07:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
        ]

    def _attestation(self, *, attestation_evidence: list[dict] | None = None):
        (
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
        ) = self._sources()
        attestation = build_framework_runtime_service_authority_attestation(
            authority_provider_receipt,
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
            mode="provider-attestation",
            environment="aitrade-prod",
            issuer="TrustAI production authority",
            subject_ref="authority:framework-runtime-service/aitrade-prod",
            attester_ref="oidc:trustai.example/framework-runtime-authority-attester",
            statement_ref="authority-attestation:framework-runtime-service/lg-trace-001",
            credential_ref="env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_TOKEN",
            attestation_evidence=attestation_evidence if attestation_evidence is not None else self._attestation_evidence(),
            issued_at="2026-07-09T01:10:00Z",
            expires_at="2027-07-09T01:10:00Z",
            require_fresh=True,
        )
        return (
            attestation,
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

    def _resign_attestation(self, attestation: dict) -> None:
        body = without_keys(attestation, "attestation_id", "signatures")
        attestation_id = content_hash(body)
        attestation["attestation_id"] = attestation_id
        attestation["signatures"] = [
            sign_value({"attestation_id": attestation_id, "framework_runtime_service_authority_attestation": body})
        ]

    def test_framework_runtime_service_authority_attestation_verifies_and_appends(self):
        (
            attestation,
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
        ) = self._attestation()
        result = verify_framework_runtime_service_authority_attestation(
            attestation,
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
            root=ROOT,
            require_fresh=True,
            now="2026-07-09T01:10:00Z",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-service-authority-attestation-test")
            entry = append_framework_runtime_service_authority_attestation(
                chain,
                attestation,
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
                root=ROOT,
                require_fresh=True,
                now="2026-07-09T01:10:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_SCHEMA, attestation["schema"])
            self.assertTrue(result.warnings)
            self.assertEqual(2, result.evidence_count)
            self.assertEqual(2, result.fresh_evidence_count)
            self.assertEqual(authority_provider_receipt["provider_receipt_id"], attestation["authority_provider_binding"]["provider_receipt_id"])
            self.assertEqual(authority_dossier["dossier_id"], attestation["authority_dossier_binding"]["dossier_id"])
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_authority_attestation_detects_provider_tamper(self):
        (
            attestation,
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
        ) = self._attestation()
        tampered_provider = copy.deepcopy(authority_provider_receipt)
        tampered_provider["provider_exchange"]["response_hash"] = "sha256:changed-authority-provider-response"

        result = verify_framework_runtime_service_authority_attestation(
            attestation,
            authority_provider_receipt=tampered_provider,
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
        self.assertTrue(any("authority_provider_binding does not match" in error for error in result.errors))
        self.assertTrue(any("provider source" in error for error in result.errors))

    def test_framework_runtime_service_authority_attestation_detects_dossier_tamper(self):
        (
            attestation,
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
        ) = self._attestation()
        tampered_dossier = copy.deepcopy(authority_dossier)
        tampered_dossier["summary"]["covered_requirement_count"] = 0

        result = verify_framework_runtime_service_authority_attestation(
            attestation,
            authority_provider_receipt=authority_provider_receipt,
            authority_provider_export=authority_provider_export,
            authority_worker=authority_worker,
            authority_dossier=tampered_dossier,
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
        self.assertTrue(any("authority_dossier_binding does not match" in error for error in result.errors))
        self.assertTrue(any("dossier source" in error for error in result.errors))

    def test_framework_runtime_service_authority_attestation_requires_complete_bindings_without_sources(self):
        attestation, *_ = self._attestation()
        cases = [
            (["authority_provider_binding"], "provider_schema", "authority_provider_binding.provider_schema is required"),
            (["authority_provider_binding"], "service_worker_operation_id", "authority_provider_binding.service_worker_operation_id is required"),
            (["authority_provider_binding"], "request_record_root", "authority_provider_binding.request_record_root is required"),
            (["authority_provider_binding", "provider_exchange"], "actor_ref", "authority_provider_binding.provider_exchange.actor_ref is required"),
            (["authority_dossier_binding"], "producer_ref", "authority_dossier_binding.producer_ref is required"),
            (["authority_dossier_binding", "summary"], "missing_requirement_ids", "authority_dossier_binding.summary.missing_requirement_ids is required"),
        ]
        for parent_path, field, expected_error in cases:
            with self.subTest(field=field):
                tampered = copy.deepcopy(attestation)
                target = tampered
                for part in parent_path:
                    target = target[part]
                target.pop(field)
                self._resign_attestation(tampered)

                result = verify_framework_runtime_service_authority_attestation(
                    tampered,
                    require_fresh=True,
                    now="2026-07-09T01:10:00Z",
                )

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_framework_runtime_service_authority_attestation_rejects_stale_evidence_when_strict(self):
        evidence = copy.deepcopy(self._attestation_evidence())
        evidence[0]["expires_at"] = "2026-07-09T01:09:00Z"
        (
            attestation,
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
        ) = self._attestation(attestation_evidence=evidence)

        result = verify_framework_runtime_service_authority_attestation(
            attestation,
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
            root=ROOT,
            require_fresh=True,
            now="2026-07-09T01:10:00Z",
        )

        self.assertFalse(result.ok)
        self.assertEqual(1, result.stale_evidence_count)
        self.assertTrue(any("evidence expired" in error for error in result.errors))

    def test_framework_runtime_service_authority_attestation_rejects_raw_credential(self):
        (
            attestation,
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
        ) = self._attestation()
        tampered = copy.deepcopy(attestation)
        tampered["attester"]["credential"] = "plain-authority-secret"

        result = verify_framework_runtime_service_authority_attestation(
            tampered,
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
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("framework runtime service authority attestation credential must be a redacted reference", result.errors)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_framework_runtime_service_authority_attestation_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
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
            ) = self._sources()
            authority_provider_receipt_path = tmp / "framework-runtime-service-authority-provider.json"
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
            attestation_path = tmp / "framework-runtime-service-authority-attestation.json"
            entry_path = tmp / "framework-runtime-service-authority-attestation-entry.json"
            state_path = tmp / "evidence-chain.json"
            write_framework_runtime_service_authority_provider_receipt(authority_provider_receipt_path, authority_provider_receipt)
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
                "--authority-provider-export",
                str(authority_provider_export_path),
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
            evidence_args = [
                "--attestation-evidence",
                "authority-review,authority-review:framework-runtime-service/lg-trace-001,sha256:framework-runtime-service-authority-review,Production authority reviewer accepted the provider export evidence set.;issuer=TrustAI authority desk;subject=aitrade-prod framework runtime service authority;source_uri=https://audit.example/authority-review/framework-runtime-service/lg-trace-001;issued_at=2026-07-09T01:08:00Z;expires_at=2026-12-31T00:00:00Z",
                "--attestation-evidence",
                "provider-export,provider-export:framework-runtime-service-authority/lg-trace-001,sha256:framework-runtime-service-authority-provider-export-review,Provider export custody record for the authority worker evidence.;issuer=Example Provider;subject=redpanda-s3-postgres-authority export lg-trace-001;source_uri=https://provider.example/audit/framework-runtime-service-authority/lg-trace-001;issued_at=2026-07-09T01:07:00Z;expires_at=2026-12-31T00:00:00Z",
            ]

            subprocess.run(
                base
                + ["framework-runtime-service-authority-attestation", str(authority_provider_receipt_path)]
                + source_args
                + [
                    "--mode",
                    "provider-attestation",
                    "--environment",
                    "aitrade-prod",
                    "--issuer",
                    "TrustAI production authority",
                    "--subject-ref",
                    "authority:framework-runtime-service/aitrade-prod",
                    "--attester-ref",
                    "oidc:trustai.example/framework-runtime-authority-attester",
                    "--statement-ref",
                    "authority-attestation:framework-runtime-service/lg-trace-001",
                    "--credential-ref",
                    "env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_TOKEN",
                    "--issued-at",
                    "2026-07-09T01:10:00Z",
                    "--expires-at",
                    "2027-07-09T01:10:00Z",
                    "--require-fresh",
                ]
                + evidence_args
                + ["--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-attestation-verify",
                    str(attestation_path),
                    "--authority-provider-receipt",
                    str(authority_provider_receipt_path),
                ]
                + source_args
                + ["--require-fresh", "--now", "2026-07-09T01:10:00Z"],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-attestation-append",
                    str(attestation_path),
                    "--authority-provider-receipt",
                    str(authority_provider_receipt_path),
                ]
                + source_args
                + [
                    "--require-fresh",
                    "--now",
                    "2026-07-09T01:10:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-service-authority-attestation-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_runtime_service_authority_attestation(
            attestation,
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
            root=ROOT,
            require_fresh=True,
            now="2026-07-09T01:10:00Z",
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])


if __name__ == "__main__":
    unittest.main()
