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
from trustai.framework_runtime_service_authority import (
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ENTRY_TYPE,
    FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_SCHEMA,
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    append_framework_runtime_service_authority_dossier,
    build_framework_runtime_service_authority_dossier,
    verify_framework_runtime_service_authority_dossier,
)
from trustai.framework_runtime_service_provider import write_framework_runtime_service_provider_receipt
from trustai.framework_runtime_service_worker import write_framework_runtime_service_worker_receipt
from trustai.framework_runtime_storage import write_framework_runtime_storage_receipt
from trustai.framework_runtime_worker import write_framework_runtime_worker_receipt

from tests import test_framework_runtime_service_provider as provider_fixtures


ROOT = Path(__file__).resolve().parents[1]
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"
AUDIT_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-audit.json"
STORAGE_EXPORT_FIXTURE = ROOT / "examples" / "aitrade" / "framework-runtime-storage-export.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class FrameworkRuntimeServiceAuthorityTests(unittest.TestCase):
    def _provider_sources(self):
        helper = provider_fixtures.FrameworkRuntimeServiceProviderTests()
        return helper._receipt()

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "collector-fleet",
                "authority_kind": "hosted-service",
                "evidence_ref": "service:collector-fleet/aitrade-prod",
                "evidence_hash": "sha256:e97cac965923d628721ba2cb6151dd12d79ce342dc4ab97653cf382483d8a680",
                "description": "Hosted collector fleet deployment export.",
                "issuer": "TrustAI Cloud",
                "subject": "aitrade-prod framework runtime collector fleet",
                "source_uri": "https://ops.example/trustai/collector-fleet/aitrade-prod",
                "issued_at": "2026-07-09T00:50:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
            {
                "requirement_id": "scheduler-queue-lease",
                "authority_kind": "provider-api",
                "evidence_ref": "provider:redpanda-postgres/scheduler-queue-lease/lg-trace-001",
                "evidence_hash": "sha256:a1096c180fa91153a0a51be6428e92ad74468cc2677c0e128ed67c4e81920a0f",
                "description": "Provider scheduler, queue, lease, checkpoint, and cursor export.",
                "issuer": "Example Provider",
                "subject": "framework runtime service lg-trace-001",
                "source_uri": "https://provider.example/audit/framework-runtime/lg-trace-001",
                "issued_at": "2026-07-09T00:51:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
        ]

    def _dossier(self, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None):
        (
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
        ) = self._provider_sources()
        dossier = build_framework_runtime_service_authority_dossier(
            provider_receipt,
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
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:framework-runtime-service-authority/lg-trace-001",
            authority_ref="authority:framework-runtime-service/aitrade-prod",
            producer_ref="oidc:trustai.example/framework-runtime-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-09T01:00:00Z",
        )
        return (
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

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "framework_runtime_service_authority": body})]

    def test_framework_runtime_service_authority_verifies_and_appends(self):
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
        ) = self._dossier()
        result = verify_framework_runtime_service_authority_dossier(
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
            require_fresh=True,
            now="2026-07-09T01:00:00Z",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-runtime-service-authority-test")
            entry = append_framework_runtime_service_authority_dossier(
                chain,
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
                require_fresh=True,
                now="2026-07-09T01:00:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertTrue(any("missing for" in warning for warning in result.warnings))
            self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(dossier["authority_evidence"][0]["source_context"], entry["payload"]["authority_evidence"][0]["source_context"])
            self.assertEqual({"deferred": 1, "passed": 5}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_runtime_service_authority_normalizes_uppercase_evidence_hash(self):
        expected_hash = self._authority_evidence()[0]["evidence_hash"]
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0]["evidence_hash"] = "sha256:" + expected_hash.removeprefix("sha256:").upper()
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
        ) = self._dossier(authority_evidence=evidence)
        result = verify_framework_runtime_service_authority_dossier(
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
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(expected_hash, dossier["authority_evidence"][0]["evidence_hash"])

    def test_framework_runtime_service_authority_rejects_resigned_malformed_evidence_hash(self):
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
        ) = self._dossier(authority_evidence=[dict(self._authority_evidence()[0])])
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["evidence_hash"] = "sha256:not-a-real-digest"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_framework_runtime_service_authority_dossier(
            tampered,
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
        )

        self.assertFalse(result.ok)
        self.assertIn(
            "invalid framework runtime service authority evidence: framework runtime service authority evidence_hash must contain a 64-character sha256 digest",
            result.errors,
        )
        self.assertNotIn("dossier_id does not match canonical framework runtime service authority body", result.errors)
        self.assertNotIn("framework runtime service authority signature verification failed", result.errors)
        self.assertNotIn("framework runtime service authority evidence_id does not match evidence body: collector-fleet", result.errors)

    def test_framework_runtime_service_authority_detects_provider_tamper(self):
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
        ) = self._dossier()
        tampered_provider = copy.deepcopy(provider_receipt)
        tampered_provider["provider_exchange"]["response_hash"] = "sha256:changed-provider-response"

        result = verify_framework_runtime_service_authority_dossier(
            dossier,
            provider_receipt=tampered_provider,
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
        self.assertTrue(any("provider_receipt_binding does not match" in error for error in result.errors))
        self.assertTrue(any("provider source" in error for error in result.errors))

    def test_framework_runtime_service_authority_requires_complete_provider_binding_without_sources(self):
        dossier, *_ = self._dossier()
        cases = [
            (("provider_receipt_binding",), "provider_schema", "provider_receipt_binding.provider_schema is required"),
            (("provider_receipt_binding",), "scheduler_record_root", "provider_receipt_binding.scheduler_record_root is required"),
            (
                ("provider_receipt_binding", "provider_exchange"),
                "response_hash",
                "provider_receipt_binding.provider_exchange.response_hash is required",
            ),
        ]
        for parent_path, field, expected_error in cases:
            with self.subTest(field=field):
                tampered = copy.deepcopy(dossier)
                target = tampered
                for part in parent_path:
                    target = target[part]
                target.pop(field)
                self._resign_dossier(tampered)

                result = verify_framework_runtime_service_authority_dossier(
                    tampered,
                    now="2026-07-09T01:00:00Z",
                )

                self.assertFalse(result.ok)
                self.assertTrue(any(expected_error in error for error in result.errors), result.errors)

    def test_framework_runtime_service_authority_requires_provider_replay_without_sources(self):
        dossier, provider_receipt, *_ = self._dossier()

        missing_provider_receipt = verify_framework_runtime_service_authority_dossier(
            dossier,
            now="2026-07-09T01:00:00Z",
        )
        missing_nested_sources = verify_framework_runtime_service_authority_dossier(
            dossier,
            provider_receipt=provider_receipt,
            now="2026-07-09T01:00:00Z",
        )

        self.assertFalse(missing_provider_receipt.ok)
        self.assertIn(
            "framework runtime service authority provider receipt is required for verification",
            missing_provider_receipt.errors,
        )
        self.assertFalse(missing_nested_sources.ok)
        self.assertTrue(
            any("provider source:" in error and "artifact is required for verification" in error for error in missing_nested_sources.errors),
            missing_nested_sources.errors,
        )

    def test_framework_runtime_service_authority_rejects_resigned_authority_source_context_mismatch(self):
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
        ) = self._dossier()
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["source_context"]["provider_receipt_hash"] = "sha256:tampered-provider-receipt"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_framework_runtime_service_authority_dossier(
            tampered,
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
        )

        self.assertFalse(result.ok)
        self.assertNotIn("dossier_id does not match canonical framework runtime service authority body", result.errors)
        self.assertNotIn("framework runtime service authority signature verification failed", result.errors)
        self.assertNotIn("framework runtime service authority evidence_id does not match evidence body: collector-fleet", result.errors)
        self.assertIn("framework runtime service authority source_context does not match provider receipt binding: collector-fleet", result.errors)

    def test_framework_runtime_service_authority_rejects_resigned_control_tamper(self):
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
        ) = self._dossier()
        tampered = copy.deepcopy(dossier)
        tampered["controls"][0]["status"] = "deferred"
        self._resign_dossier(tampered)

        result = verify_framework_runtime_service_authority_dossier(
            tampered,
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
        )

        self.assertFalse(result.ok)
        self.assertNotIn("dossier_id does not match canonical framework runtime service authority body", result.errors)
        self.assertNotIn("framework runtime service authority signature verification failed", result.errors)
        self.assertIn("framework runtime service authority controls do not match dossier body", result.errors)

    def test_framework_runtime_service_authority_requires_freshness_when_strict(self):
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0].pop("issued_at")
        evidence[0].pop("expires_at")
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
        ) = self._dossier(authority_evidence=evidence)

        result = verify_framework_runtime_service_authority_dossier(
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
            require_fresh=True,
            now="2026-07-09T01:00:00Z",
        )

        self.assertFalse(result.ok)
        self.assertEqual(1, result.missing_freshness_count)
        self.assertTrue(any("freshness metadata missing" in error for error in result.errors))

    def test_framework_runtime_service_authority_rejects_incomplete_production_claim(self):
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
        ) = self._dossier(mode="production-dossier")

        result = verify_framework_runtime_service_authority_dossier(
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
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("production-dossier mode requires" in error for error in result.errors))

    def test_cli_framework_runtime_service_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (
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
            ) = self._provider_sources()
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
            dossier_path = tmp / "framework-runtime-service-authority.json"
            entry_path = tmp / "framework-runtime-service-authority-entry.json"
            state_path = tmp / "evidence-chain.json"
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
            evidence_arg = (
                "collector-fleet,hosted-service,service:collector-fleet/aitrade-prod,"
                "sha256:e97cac965923d628721ba2cb6151dd12d79ce342dc4ab97653cf382483d8a680,Hosted collector fleet deployment export;"
                "issuer=TrustAI Cloud;subject=aitrade-prod framework runtime collector fleet;"
                "source_uri=https://ops.example/trustai/collector-fleet/aitrade-prod;"
                "issued_at=2026-07-09T00:50:00Z;expires_at=2026-12-31T00:00:00Z"
            )

            subprocess.run(
                base
                + ["framework-runtime-service-authority", str(provider_receipt_path)]
                + source_args
                + [
                    "--mode",
                    "provider-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:framework-runtime-service-authority/lg-trace-001",
                    "--authority-ref",
                    "authority:framework-runtime-service/aitrade-prod",
                    "--producer-ref",
                    "oidc:trustai.example/framework-runtime-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-09T01:00:00Z",
                    "--require-fresh",
                    "--now",
                    "2026-07-09T01:00:00Z",
                    "--out",
                    str(dossier_path),
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
                    "framework-runtime-service-authority-verify",
                    str(dossier_path),
                    "--provider-receipt",
                    str(provider_receipt_path),
                ]
                + source_args
                + ["--require-fresh", "--now", "2026-07-09T01:00:00Z"],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-runtime-service-authority-append",
                    str(dossier_path),
                    "--provider-receipt",
                    str(provider_receipt_path),
                ]
                + source_args
                + [
                    "--require-fresh",
                    "--now",
                    "2026-07-09T01:00:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-runtime-service-authority-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_runtime_service_authority_dossier(
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
            require_fresh=True,
            now="2026-07-09T01:00:00Z",
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])


if __name__ == "__main__":
    unittest.main()
