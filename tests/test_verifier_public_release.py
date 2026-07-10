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
from trustai.go_verifier_build import write_go_verifier_build_attestation
from trustai.go_verifier_release_run import write_go_verifier_release_run_receipt
from trustai.go_verifier_release_run_bundle import build_go_verifier_release_run_bundle, write_go_verifier_release_run_bundle
from trustai.standards import write_standards_submission
from trustai.verifier_conformance import write_verifier_conformance_report
from trustai.verifier_distribution import build_verifier_distribution_receipt, write_verifier_distribution_receipt
from trustai.verifier_public_release import (
    VERIFIER_PUBLIC_RELEASE_ENTRY_TYPE,
    VERIFIER_PUBLIC_RELEASE_SCHEMA,
    append_verifier_public_release_receipt,
    build_verifier_public_release_receipt,
    verify_verifier_public_release_receipt,
    write_verifier_public_release_receipt,
)
from trustai.verifier_release import write_verifier_release_manifest

from tests import test_go_verifier_release_run as release_run_tests


ROOT = Path(__file__).resolve().parents[1]


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class VerifierPublicReleaseTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = release_run_tests.GoVerifierReleaseRunTests(methodName="test_go_verifier_release_run_verifies_and_appends")
        conformance, standards, release = helper._inputs()
        build_attestation, binary_path, build_log_path, sbom_path, provenance_path, signature_path = helper._binary_attestation(
            tmp,
            release,
            conformance,
            standards,
        )
        release_run = helper._release_run(
            release,
            build_attestation,
            conformance,
            standards,
            binary_path,
            (build_log_path, sbom_path, provenance_path, signature_path),
        )
        source_paths = {
            "release_run": tmp / "go-verifier-release-run.json",
            "verifier_release": tmp / "verifier-release.json",
            "build_attestation": tmp / "go-verifier-build-attestation.json",
            "conformance_report": tmp / "verifier-conformance.json",
            "standards_package": tmp / "standards-submission.json",
        }
        write_go_verifier_release_run_receipt(source_paths["release_run"], release_run)
        write_verifier_release_manifest(source_paths["verifier_release"], release)
        write_go_verifier_build_attestation(source_paths["build_attestation"], build_attestation)
        write_verifier_conformance_report(source_paths["conformance_report"], conformance)
        write_standards_submission(source_paths["standards_package"], standards)

        release_run_bundle = build_go_verifier_release_run_bundle(
            release_run,
            release,
            build_attestation,
            conformance,
            standards,
            artifact_paths=source_paths,
            root=ROOT,
            binary_path=binary_path,
            reviewer_ref="oidc:auditor.example/go-verifier-release-reviewer",
            environment="release-ci",
            generated_at="2026-07-16T00:06:00Z",
        )
        bundle_path = tmp / "go-verifier-release-run-bundle.json"
        write_go_verifier_release_run_bundle(bundle_path, release_run_bundle)

        distribution_paths = {
            "distribution_bundle_path": tmp / "verifier-source-bundle.zip",
            "distribution_sbom_path": tmp / "verifier-source-sbom.json",
            "distribution_provenance_path": tmp / "verifier-source-provenance.json",
            "distribution_signature_path": tmp / "verifier-source-signature.json",
        }
        distribution = build_verifier_distribution_receipt(
            release,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
            bundle_path=distribution_paths["distribution_bundle_path"],
            sbom_path=distribution_paths["distribution_sbom_path"],
            provenance_path=distribution_paths["distribution_provenance_path"],
            signature_path=distribution_paths["distribution_signature_path"],
            distribution_ref="release:trustai-verifier/source-v0.1",
            publisher_ref="publisher:trustai/local",
            release_url="https://github.com/MSBeni/trust_ai/releases/tag/v0.1.0",
            generated_at="2026-07-16T00:03:00Z",
        )
        distribution_path = tmp / "verifier-distribution.json"
        write_verifier_distribution_receipt(distribution_path, distribution)
        public_artifacts = [
            {"name": "verifier-source-bundle.zip", "path": str(distribution_paths["distribution_bundle_path"]), "kind": "source-bundle", "url": "https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/verifier-source-bundle.zip"},
            {"name": "verifier-source-sbom.json", "path": str(distribution_paths["distribution_sbom_path"]), "kind": "source-sbom", "url": "https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/verifier-source-sbom.json"},
            {"name": "verifier-source-provenance.json", "path": str(distribution_paths["distribution_provenance_path"]), "kind": "source-provenance", "url": "https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/verifier-source-provenance.json"},
            {"name": "verifier-source-signature.json", "path": str(distribution_paths["distribution_signature_path"]), "kind": "source-signature", "url": "https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/verifier-source-signature.json"},
            {"name": binary_path.name, "path": str(binary_path), "kind": "binary", "url": "https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/trustai-verify-linux-amd64"},
            {"name": sbom_path.name, "path": str(sbom_path), "kind": "binary-sbom", "url": "https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/trustai-verify-linux-amd64.sbom.json"},
            {"name": provenance_path.name, "path": str(provenance_path), "kind": "binary-provenance", "url": "https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/trustai-verify-linux-amd64.provenance.json"},
            {"name": signature_path.name, "path": str(signature_path), "kind": "binary-signature", "url": "https://github.com/MSBeni/trust_ai/releases/download/v0.1.0/trustai-verify-linux-amd64.sig"},
        ]
        return {
            "conformance": conformance,
            "standards": standards,
            "release": release,
            "build_attestation": build_attestation,
            "release_run": release_run,
            "release_run_bundle": release_run_bundle,
            "distribution": distribution,
            "source_paths": source_paths,
            "distribution_path": distribution_path,
            "distribution_paths": distribution_paths,
            "bundle_path": bundle_path,
            "binary_path": binary_path,
            "public_artifacts": public_artifacts,
        }

    def _receipt(self, tmp: Path):
        sources = self._sources(tmp)
        receipt = build_verifier_public_release_receipt(
            sources["release"],
            sources["distribution"],
            sources["build_attestation"],
            sources["release_run"],
            sources["release_run_bundle"],
            root=ROOT,
            conformance_report=sources["conformance"],
            standards_package=sources["standards"],
            **sources["distribution_paths"],
            binary_path=sources["binary_path"],
            public_artifacts=sources["public_artifacts"],
            mode="public-release",
            provider="github",
            release_ref="github:MSBeni/trust_ai/releases/tag/v0.1.0",
            release_url="https://github.com/MSBeni/trust_ai/releases/tag/v0.1.0",
            tag="v0.1.0",
            publisher_ref="publisher:trustai/release-bot",
            workflow_run_export_ref="github-actions-run:1234567890",
            workflow_run_export_hash=_sha256_ref(sources["source_paths"]["release_run"]),
            release_api_export_ref="github-release-api:v0.1.0",
            release_api_export_hash=_sha256_ref(sources["distribution_path"]),
            artifact_manifest_ref="github-release-artifacts:v0.1.0",
            artifact_manifest_hash=_sha256_ref(sources["bundle_path"]),
            audit_log_ref="github-audit-log:MSBeni/trust_ai/releases/v0.1.0",
            audit_log_root="sha256:" + "a" * 64,
            audit_log_size=8,
            transparency_log_ref="sigstore-rekor:trustai-verifier/v0.1.0",
            transparency_log_root="sha256:" + "b" * 64,
            retention_until="2033-07-16T00:00:00Z",
            published_at="2026-07-16T00:07:00Z",
            generated_at="2026-07-16T00:08:00Z",
        )
        return receipt, sources

    def test_verifier_public_release_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt, sources = self._receipt(tmp)
            result = verify_verifier_public_release_receipt(
                receipt,
                sources["release"],
                sources["distribution"],
                sources["build_attestation"],
                sources["release_run"],
                sources["release_run_bundle"],
                root=ROOT,
                conformance_report=sources["conformance"],
                standards_package=sources["standards"],
                **sources["distribution_paths"],
                binary_path=sources["binary_path"],
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="verifier-public-release-test")
            entry = append_verifier_public_release_receipt(
                chain,
                receipt,
                sources["release"],
                sources["distribution"],
                sources["build_attestation"],
                sources["release_run"],
                sources["release_run_bundle"],
                root=ROOT,
                conformance_report=sources["conformance"],
                standards_package=sources["standards"],
                **sources["distribution_paths"],
                binary_path=sources["binary_path"],
            )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(VERIFIER_PUBLIC_RELEASE_SCHEMA, receipt["schema"])
        self.assertEqual(8, len(receipt["artifacts"]))
        self.assertEqual({"attested": 7}, entry["payload"]["control_status_summary"])
        self.assertEqual(VERIFIER_PUBLIC_RELEASE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["release_publication_id"], entry["payload"]["release_publication_id"])
        self.assertTrue(chain.verify_all().ok)

    def test_verifier_public_release_detects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt, sources = self._receipt(tmp)
            tampered = copy.deepcopy(receipt)
            tampered["artifacts"][0]["sha256"] = "0" * 64
            result = verify_verifier_public_release_receipt(
                tampered,
                sources["release"],
                sources["distribution"],
                sources["build_attestation"],
                sources["release_run"],
                sources["release_run_bundle"],
                root=ROOT,
                conformance_report=sources["conformance"],
                standards_package=sources["standards"],
                **sources["distribution_paths"],
                binary_path=sources["binary_path"],
            )

        self.assertFalse(result.ok)
        self.assertTrue(any("release_publication_id" in error for error in result.errors))
        self.assertTrue(any("artifact id mismatch" in error for error in result.errors))
        self.assertTrue(any("missing source distribution artifact" in error for error in result.errors))

    def test_verifier_public_release_detects_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt, sources = self._receipt(tmp)
            tampered_release = copy.deepcopy(sources["release"])
            tampered_release["release"]["version"] = "9.9.9"
            result = verify_verifier_public_release_receipt(
                receipt,
                tampered_release,
                sources["distribution"],
                sources["build_attestation"],
                sources["release_run"],
                sources["release_run_bundle"],
                root=ROOT,
                conformance_report=sources["conformance"],
                standards_package=sources["standards"],
                **sources["distribution_paths"],
                binary_path=sources["binary_path"],
            )

        self.assertFalse(result.ok)
        self.assertTrue(any("verifier release source" in error for error in result.errors))
        self.assertTrue(any("source summary" in error for error in result.errors))

    def test_cli_verifier_public_release_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, sources = self._receipt(tmp)
            receipt_path = tmp / "verifier-public-release.json"
            entry_path = tmp / "verifier-public-release-entry.json"
            state_path = tmp / "verifier-public-release-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
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
            artifact_args = []
            for artifact in sources["public_artifacts"]:
                artifact_args.extend(["--artifact", f"{artifact['name']},{artifact['path']},{artifact['kind']},{artifact['url']}"])

            subprocess.run(
                base
                + [
                    "verifier-public-release",
                    *source_args,
                    *artifact_args,
                    "--provider", "github",
                    "--release-ref", "github:MSBeni/trust_ai/releases/tag/v0.1.0",
                    "--release-url", "https://github.com/MSBeni/trust_ai/releases/tag/v0.1.0",
                    "--tag", "v0.1.0",
                    "--publisher-ref", "publisher:trustai/release-bot",
                    "--workflow-run-export-ref", "github-actions-run:1234567890",
                    "--workflow-run-export-hash", _sha256_ref(sources["source_paths"]["release_run"]),
                    "--release-api-export-ref", "github-release-api:v0.1.0",
                    "--release-api-export-hash", _sha256_ref(sources["distribution_path"]),
                    "--artifact-manifest-ref", "github-release-artifacts:v0.1.0",
                    "--artifact-manifest-hash", _sha256_ref(sources["bundle_path"]),
                    "--audit-log-ref", "github-audit-log:MSBeni/trust_ai/releases/v0.1.0",
                    "--audit-log-root", "sha256:" + "a" * 64,
                    "--audit-log-size", "8",
                    "--transparency-log-ref", "sigstore-rekor:trustai-verifier/v0.1.0",
                    "--transparency-log-root", "sha256:" + "b" * 64,
                    "--retention-until", "2033-07-16T00:00:00Z",
                    "--published-at", "2026-07-16T00:07:00Z",
                    "--generated-at", "2026-07-16T00:08:00Z",
                    "--out", str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(base + ["verifier-public-release-verify", str(receipt_path), *source_args], cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            subprocess.run(
                base
                + [
                    "verifier-public-release-append",
                    str(receipt_path),
                    *source_args,
                    "--state", str(state_path),
                    "--tenant", "verifier-public-release-cli",
                    "--out", str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        self.assertEqual(VERIFIER_PUBLIC_RELEASE_SCHEMA, receipt["schema"])
        self.assertEqual(VERIFIER_PUBLIC_RELEASE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["release_publication_id"], entry["payload"]["release_publication_id"])


if __name__ == "__main__":
    unittest.main()
