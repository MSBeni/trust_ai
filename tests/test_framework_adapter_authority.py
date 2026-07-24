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
from trustai.framework_adapter_authority import (
    FRAMEWORK_ADAPTER_AUTHORITY_ENTRY_TYPE,
    FRAMEWORK_ADAPTER_AUTHORITY_SCHEMA,
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    append_framework_adapter_authority_dossier,
    build_framework_adapter_authority_dossier,
    verify_framework_adapter_authority_dossier,
    write_framework_adapter_authority_dossier,
)
from trustai.framework_adapter_matrix import (
    build_framework_adapter_matrix,
    load_framework_adapter_matrix_source,
    write_framework_adapter_matrix,
)
from trustai.framework_hook_release import (
    build_framework_hook_release,
    load_framework_hook_release_source,
    write_framework_hook_release,
)
from trustai.framework_runtime_service_authority import write_framework_runtime_service_authority_dossier

from tests import test_framework_runtime_service_authority as runtime_authority_fixtures


ROOT = Path(__file__).resolve().parents[1]
MATRIX_SOURCE = ROOT / "examples" / "aitrade" / "framework-adapter-matrix.json"
HOOK_SOURCE = ROOT / "examples" / "aitrade" / "framework-hook-release.json"


class FrameworkAdapterAuthorityTests(unittest.TestCase):
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

    def _runtime_service_authority(self) -> dict:
        helper = runtime_authority_fixtures.FrameworkRuntimeServiceAuthorityTests()
        return helper._dossier()[0]

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "exact-runtime-release-matrix",
                "authority_kind": "ci-run",
                "evidence_ref": "ci:framework-adapter-matrix/nightly/aitrade-prod",
                "evidence_hash": "sha256:da1dbc3f0e823e27b23ccdbd395cd21349cdd1ff05c00b2b64d1ce97f071270c",
                "description": "Nightly adapter matrix replay export for exact framework runtime versions.",
                "issuer": "TrustAI CI",
                "subject": "aitrade-prod framework adapter matrix",
                "source_uri": "https://ci.example/trustai/framework-adapter-matrix/aitrade-prod",
                "issued_at": "2026-07-09T00:45:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
            {
                "requirement_id": "native-hook-package-provenance",
                "authority_kind": "ci-run",
                "evidence_ref": "ci:framework-hook-release/provenance/0.1.0",
                "evidence_hash": "sha256:cdae0a2dffb07721ed933c895b8c128dec2278ce0b3ce7b7829737d6975647ab",
                "description": "Hook package build provenance and source artifact attestation.",
                "issuer": "TrustAI CI",
                "subject": "trustai-framework-hooks 0.1.0",
                "source_uri": "https://ci.example/trustai/framework-hook-release/0.1.0",
                "issued_at": "2026-07-09T00:46:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
        ]

    def _dossier(
        self,
        *,
        mode: str = "provider-dossier",
        authority_evidence: list[dict] | None = None,
        runtime_service_authority: dict | None = None,
    ) -> tuple[dict, dict, dict, dict]:
        matrix = self._matrix()
        release = self._release(matrix)
        runtime_authority = runtime_service_authority if runtime_service_authority is not None else self._runtime_service_authority()
        dossier = build_framework_adapter_authority_dossier(
            matrix,
            release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:framework-adapter-authority/aitrade-prod",
            authority_ref="authority:framework-adapter/aitrade-prod",
            producer_ref="oidc:trustai.example/framework-adapter-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-09T01:05:00Z",
        )
        return dossier, matrix, release, runtime_authority

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "framework_adapter_authority": body})]

    def test_framework_adapter_authority_verifies_and_appends(self):
        dossier, matrix, release, runtime_authority = self._dossier()
        result = verify_framework_adapter_authority_dossier(
            dossier,
            matrix=matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
            require_fresh=True,
            now="2026-07-09T01:05:00Z",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-adapter-authority-test")
            entry = append_framework_adapter_authority_dossier(
                chain,
                dossier,
                matrix=matrix,
                release=release,
                runtime_service_authority=runtime_authority,
                root=ROOT,
                require_fresh=True,
                now="2026-07-09T01:05:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(FRAMEWORK_ADAPTER_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertTrue(any("missing for" in warning for warning in result.warnings))
            self.assertEqual(FRAMEWORK_ADAPTER_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual({"deferred": 2, "passed": 6}, entry["payload"]["control_summary"])
            self.assertEqual(dossier["authority_evidence"][0]["source_context"], entry["payload"]["authority_evidence"][0]["source_context"])
            self.assertEqual(content_hash(dossier["source_binding"]), dossier["authority_evidence"][0]["source_context"]["source_binding_hash"])
            self.assertTrue(chain.verify_all().ok)

    def test_framework_adapter_authority_normalizes_uppercase_evidence_hash(self):
        expected_hash = self._authority_evidence()[0]["evidence_hash"]
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0]["evidence_hash"] = "sha256:" + expected_hash.removeprefix("sha256:").upper()
        dossier, matrix, release, runtime_authority = self._dossier(authority_evidence=evidence)

        result = verify_framework_adapter_authority_dossier(
            dossier,
            matrix=matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(expected_hash, dossier["authority_evidence"][0]["evidence_hash"])

    def test_framework_adapter_authority_rejects_resigned_malformed_evidence_hash(self):
        dossier, matrix, release, runtime_authority = self._dossier(authority_evidence=[dict(self._authority_evidence()[0])])
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["evidence_hash"] = "sha256:not-a-real-digest"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_framework_adapter_authority_dossier(
            tampered,
            matrix=matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn(
            "invalid framework adapter authority evidence: framework adapter authority evidence_hash must contain a 64-character sha256 digest",
            result.errors,
        )
        self.assertNotIn("dossier_id does not match canonical framework adapter authority body", result.errors)
        self.assertNotIn("framework adapter authority signature verification failed", result.errors)
        self.assertNotIn("framework adapter authority evidence_id does not match evidence body: exact-runtime-release-matrix", result.errors)

    def test_framework_adapter_authority_rejects_resigned_source_context_mismatch(self):
        dossier, matrix, release, runtime_authority = self._dossier()
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["source_context"]["adapter_matrix_hash"] = "sha256:tampered-adapter-matrix"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_framework_adapter_authority_dossier(
            tampered,
            matrix=matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("framework adapter authority source_context does not match source binding: exact-runtime-release-matrix", result.errors)

    def test_framework_adapter_authority_rejects_resigned_control_tamper(self):
        dossier, matrix, release, runtime_authority = self._dossier()
        tampered = copy.deepcopy(dossier)
        tampered["controls"][0]["status"] = "failed"
        self._resign_dossier(tampered)

        result = verify_framework_adapter_authority_dossier(
            tampered,
            matrix=matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("framework adapter authority controls do not match dossier body", result.errors)

    def test_framework_adapter_authority_detects_matrix_tamper(self):
        dossier, matrix, release, runtime_authority = self._dossier()
        tampered_matrix = copy.deepcopy(matrix)
        tampered_matrix["entries"][0]["runtime"]["version"] = "0.0.tampered"

        result = verify_framework_adapter_authority_dossier(
            dossier,
            matrix=tampered_matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("source_binding does not match" in error for error in result.errors))
        self.assertTrue(any("matrix source" in error for error in result.errors))

    def test_framework_adapter_authority_requires_complete_source_binding_without_sources(self):
        dossier, *_ = self._dossier()
        tampered = copy.deepcopy(dossier)
        tampered["source_binding"]["hook_release"].pop("release_hash")
        body = without_keys(tampered, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        tampered["dossier_id"] = dossier_id
        tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "framework_adapter_authority": body})]

        result = verify_framework_adapter_authority_dossier(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("hook_release.release_hash is required" in error for error in result.errors), result.errors)

    def test_framework_adapter_authority_requires_freshness_when_strict(self):
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0].pop("issued_at")
        evidence[0].pop("expires_at")
        dossier, matrix, release, runtime_authority = self._dossier(authority_evidence=evidence)

        result = verify_framework_adapter_authority_dossier(
            dossier,
            matrix=matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
            require_fresh=True,
            now="2026-07-09T01:05:00Z",
        )

        self.assertFalse(result.ok)
        self.assertEqual(1, result.missing_freshness_count)
        self.assertTrue(any("freshness metadata missing" in error for error in result.errors))

    def test_framework_adapter_authority_rejects_incomplete_production_claim(self):
        dossier, matrix, release, runtime_authority = self._dossier(mode="production-dossier")

        result = verify_framework_adapter_authority_dossier(
            dossier,
            matrix=matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
            now="2026-07-09T01:05:00Z",
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("production-dossier mode requires" in error for error in result.errors))

    def test_cli_framework_adapter_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier_path = tmp / "framework-adapter-authority.json"
            entry_path = tmp / "framework-adapter-authority-entry.json"
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            runtime_authority_path = tmp / "framework-runtime-service-authority.json"
            state_path = tmp / "evidence-chain.json"
            dossier, matrix, release, runtime_authority = self._dossier()
            write_framework_adapter_matrix(matrix_path, matrix)
            write_framework_hook_release(release_path, release)
            write_framework_runtime_service_authority_dossier(runtime_authority_path, runtime_authority)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.run(
                base
                + [
                    "framework-adapter-authority",
                    str(matrix_path),
                    str(release_path),
                    "--runtime-service-authority",
                    str(runtime_authority_path),
                    "--root",
                    str(ROOT),
                    "--mode",
                    "provider-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:framework-adapter-authority/aitrade-prod",
                    "--authority-ref",
                    "authority:framework-adapter/aitrade-prod",
                    "--producer-ref",
                    "oidc:trustai.example/framework-adapter-authority-worker",
                    "--authority-evidence",
                    "exact-runtime-release-matrix,ci-run,ci:framework-adapter-matrix/nightly/aitrade-prod,sha256:da1dbc3f0e823e27b23ccdbd395cd21349cdd1ff05c00b2b64d1ce97f071270c,Nightly adapter matrix replay export;issuer=TrustAI CI;subject=aitrade-prod framework adapter matrix;source_uri=https://ci.example/trustai/framework-adapter-matrix/aitrade-prod;issued_at=2026-07-09T00:45:00Z;expires_at=2026-12-31T00:00:00Z",
                    "--generated-at",
                    "2026-07-09T01:05:00Z",
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
                    "framework-adapter-authority-verify",
                    str(dossier_path),
                    "--matrix",
                    str(matrix_path),
                    "--release",
                    str(release_path),
                    "--runtime-service-authority",
                    str(runtime_authority_path),
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T01:05:00Z",
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
                    "framework-adapter-authority-append",
                    str(dossier_path),
                    str(matrix_path),
                    str(release_path),
                    "--runtime-service-authority",
                    str(runtime_authority_path),
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T01:05:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-adapter-authority-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            cli_dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_adapter_authority_dossier(
            cli_dossier,
            matrix=matrix,
            release=release,
            runtime_service_authority=runtime_authority,
            root=ROOT,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertNotEqual(dossier["dossier_id"], cli_dossier["dossier_id"])
        self.assertEqual(cli_dossier["dossier_id"], entry["payload"]["dossier_id"])


if __name__ == "__main__":
    unittest.main()
