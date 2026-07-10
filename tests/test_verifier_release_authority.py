import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.verifier_public_release import write_verifier_public_release_receipt
from trustai.verifier_release_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    PRODUCTION_AUTHORITY_REQUIREMENTS,
    VERIFIER_RELEASE_AUTHORITY_ENTRY_TYPE,
    VERIFIER_RELEASE_AUTHORITY_SCHEMA,
    append_verifier_release_authority_dossier,
    build_verifier_release_authority_dossier,
    verify_verifier_release_authority_dossier,
)

import tests.test_verifier_public_release as public_release_helpers


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_WORKFLOW_AUTHORITY_EXPORT = ROOT / "examples" / "aitrade" / "external-evidence" / "go-verifier-workflow-run.json"
VERIFIER_WORKFLOW_AUTHORITY_EXPORT_REL = "examples/aitrade/external-evidence/go-verifier-workflow-run.json"


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class VerifierReleaseAuthorityTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = public_release_helpers.VerifierPublicReleaseTests()
        receipt, sources = helper._receipt(tmp)
        sources["public_release"] = receipt
        return sources

    def _source_kwargs(self, sources: dict) -> dict:
        return {
            "verifier_release": sources["release"],
            "distribution_receipt": sources["distribution"],
            "build_attestation": sources["build_attestation"],
            "release_run": sources["release_run"],
            "release_run_bundle": sources["release_run_bundle"],
            "root": ROOT,
            "conformance_report": sources["conformance"],
            "standards_package": sources["standards"],
            **sources["distribution_paths"],
            "binary_path": sources["binary_path"],
        }

    def _evidence(self, requirement_id: str = "completed-provider-workflow-run", authority_kind: str = "ci-run") -> dict:
        evidence_hash = (
            _sha256_ref(VERIFIER_WORKFLOW_AUTHORITY_EXPORT)
            if requirement_id == "completed-provider-workflow-run"
            else f"sha256:verifier-release-authority-{requirement_id}"
        )
        return {
            "requirement_id": requirement_id,
            "authority_kind": authority_kind,
            "evidence_ref": f"github:release-authority/{requirement_id}",
            "evidence_hash": evidence_hash,
            "description": f"Fresh authority evidence for {requirement_id}",
            "issuer": "GitHub Actions",
            "subject": "trustai verifier release v0.1.0",
            "source_uri": f"https://github.example/MSBeni/trust_ai/releases/{requirement_id}",
            "issued_at": "2026-07-16T00:10:00Z",
            "expires_at": "2026-07-23T00:10:00Z",
        }

    def _authority_artifacts(self) -> list[dict[str, str]]:
        return [{"requirement_id": "completed-provider-workflow-run", "path": VERIFIER_WORKFLOW_AUTHORITY_EXPORT_REL}]

    def _dossier(self, sources: dict, **overrides):
        values = {
            "public_release_receipt": sources["public_release"],
            **self._source_kwargs(sources),
            "mode": "provider-dossier",
            "environment": "release-prod",
            "dossier_ref": "dossier:verifier-release-authority/v0.1.0",
            "authority_ref": "authority:verifier-release/github/v0.1.0",
            "producer_ref": "oidc:trustai.example/verifier-release-authority-worker",
            "authority_evidence": [
                self._evidence(),
                self._evidence("public-release-api-publication", "provider-api"),
            ],
            "generated_at": "2026-07-16T00:12:00Z",
        }
        values["authority_artifacts"] = self._authority_artifacts() if "authority_evidence" not in overrides else []
        values.update(overrides)
        return build_verifier_release_authority_dossier(**values)

    def test_verifier_release_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources)
            result = verify_verifier_release_authority_dossier(
                dossier,
                public_release_receipt=sources["public_release"],
                **self._source_kwargs(sources),
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="verifier-release-authority-test")
            entry = append_verifier_release_authority_dossier(
                chain,
                dossier,
                public_release_receipt=sources["public_release"],
                **self._source_kwargs(sources),
            )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(VERIFIER_RELEASE_AUTHORITY_SCHEMA, dossier["schema"])
        self.assertEqual(result.covered_count, 2)
        self.assertEqual(result.required_count, len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS))
        self.assertEqual(result.fresh_evidence_count, 2)
        self.assertEqual(result.replayed_artifact_count, 1)
        self.assertEqual(dossier["artifact_summary"]["artifact_count"], 1)
        self.assertIn("live production release authority is not claimed", "\n".join(result.warnings))
        self.assertEqual(VERIFIER_RELEASE_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(entry["payload"]["dossier_id"], dossier["dossier_id"])
        self.assertEqual(entry["payload"]["control_summary"], {"deferred": 1, "passed": 7})
        self.assertEqual(entry["payload"]["public_release_binding"]["release_publication_id"], sources["public_release"]["release_publication_id"])
        self.assertEqual(entry["payload"]["artifact_summary"]["artifact_count"], 1)
        self.assertEqual(entry["payload"]["authority_artifacts"][0]["path"], VERIFIER_WORKFLOW_AUTHORITY_EXPORT_REL)
        self.assertTrue(chain.verify_all().ok)

    def test_verifier_release_authority_detects_public_release_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources)
            tampered = copy.deepcopy(sources["public_release"])
            tampered["public_release"]["tag"] = "v9.9.9"
            result = verify_verifier_release_authority_dossier(
                dossier,
                public_release_receipt=tampered,
                **self._source_kwargs(sources),
            )

        self.assertFalse(result.ok)
        self.assertTrue(any("public_release_binding" in error for error in result.errors))
        self.assertTrue(any("release_publication_id" in error for error in result.errors))

    def test_verifier_release_authority_detects_authority_artifact_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources)
            tampered = copy.deepcopy(dossier)
            tampered["authority_artifacts"][0]["path"] = "examples/aitrade/byoc-network-policy-authority-export.json"
            result = verify_verifier_release_authority_dossier(
                tampered,
                public_release_receipt=sources["public_release"],
                **self._source_kwargs(sources),
            )

        self.assertFalse(result.ok)
        errors = "\n".join(result.errors)
        self.assertIn("authority artifact", errors)
        self.assertIn("hash", errors)

    def test_verifier_release_authority_strict_freshness_rejects_missing_window(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            evidence = self._evidence()
            evidence.pop("issued_at")
            evidence.pop("expires_at")
            dossier = self._dossier(sources, authority_evidence=[evidence])
            result = verify_verifier_release_authority_dossier(
                dossier,
                public_release_receipt=sources["public_release"],
                require_fresh=True,
                **self._source_kwargs(sources),
            )

        self.assertFalse(result.ok)
        self.assertTrue(any("freshness metadata missing" in error for error in result.errors))

    def test_verifier_release_authority_production_mode_requires_complete_coverage(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources, mode="production-dossier", authority_evidence=[self._evidence()])
            result = verify_verifier_release_authority_dossier(
                dossier,
                public_release_receipt=sources["public_release"],
                **self._source_kwargs(sources),
            )

        self.assertFalse(result.ok)
        self.assertTrue(any("production-dossier mode requires every verifier release authority requirement" in error for error in result.errors))

    def test_verifier_release_authority_production_mode_requires_fresh_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            evidence = []
            for requirement in PRODUCTION_AUTHORITY_REQUIREMENTS:
                item = self._evidence(requirement["id"], requirement["authority_kinds"][0])
                item["issued_at"] = "2026-07-01T00:00:00Z"
                item["expires_at"] = "2026-07-02T00:00:00Z"
                evidence.append(item)
            dossier = self._dossier(sources, mode="production-dossier", authority_evidence=evidence)
            result = verify_verifier_release_authority_dossier(
                dossier,
                public_release_receipt=sources["public_release"],
                **self._source_kwargs(sources),
            )

        self.assertFalse(result.ok)
        self.assertTrue(any("production-dossier mode requires every verifier release authority evidence item to be fresh" in error for error in result.errors))

    def test_verifier_release_authority_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            public_release_path = tmp / "verifier-public-release.json"
            dossier_path = tmp / "verifier-release-authority.json"
            entry_path = tmp / "verifier-release-authority-entry.json"
            chain_path = tmp / "chain.json"
            write_verifier_public_release_receipt(public_release_path, sources["public_release"])
            source_args = [
                str(public_release_path),
                str(sources["source_paths"]["verifier_release"]),
                str(sources["distribution_path"]),
                str(sources["source_paths"]["build_attestation"]),
                str(sources["source_paths"]["release_run"]),
                str(sources["bundle_path"]),
                "--conformance-report", str(sources["source_paths"]["conformance_report"]),
                "--standards-package", str(sources["source_paths"]["standards_package"]),
                "--root", str(ROOT),
                "--distribution-bundle", str(sources["distribution_paths"]["distribution_bundle_path"]),
                "--distribution-sbom", str(sources["distribution_paths"]["distribution_sbom_path"]),
                "--distribution-provenance", str(sources["distribution_paths"]["distribution_provenance_path"]),
                "--distribution-signature", str(sources["distribution_paths"]["distribution_signature_path"]),
                "--binary", str(sources["binary_path"]),
            ]
            authority_artifact = f"completed-provider-workflow-run,{VERIFIER_WORKFLOW_AUTHORITY_EXPORT_REL}"
            evidence = f"completed-provider-workflow-run,ci-run,github-actions-run:1234567890,{_sha256_ref(VERIFIER_WORKFLOW_AUTHORITY_EXPORT)},Provider workflow run export;issuer=GitHub Actions;subject=trustai verifier release v0.1.0;source_uri=https://github.com/MSBeni/trust_ai/actions/runs/1234567890;issued_at=2026-07-16T00:10:00Z;expires_at=2026-07-23T00:10:00Z"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.check_call([
                *base,
                "verifier-release-authority",
                *source_args,
                "--environment", "release-prod",
                "--dossier-ref", "dossier:verifier-release-authority/v0.1.0",
                "--authority-ref", "authority:verifier-release/github/v0.1.0",
                "--producer-ref", "oidc:trustai.example/verifier-release-authority-worker",
                "--authority-evidence", evidence,
                "--authority-artifact", authority_artifact,
                "--generated-at", "2026-07-16T00:12:00Z",
                "--out", str(dossier_path),
            ], cwd=ROOT, env=env)
            subprocess.check_call([*base, "verifier-release-authority-verify", str(dossier_path), *source_args, "--authority-artifact", authority_artifact], cwd=ROOT, env=env)
            subprocess.check_call([
                *base,
                "verifier-release-authority-append",
                str(dossier_path),
                *source_args,
                "--authority-artifact", authority_artifact,
                "--state", str(chain_path),
                "--tenant", "verifier-release-authority-cli",
                "--out", str(entry_path),
            ], cwd=ROOT, env=env)

            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        self.assertEqual(VERIFIER_RELEASE_AUTHORITY_ENTRY_TYPE, entry["entry_type"])


if __name__ == "__main__":
    unittest.main()
