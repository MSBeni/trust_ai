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
from trustai.go_verifier_build import write_go_verifier_build_attestation
from trustai.go_verifier_release_run import write_go_verifier_release_run_receipt
from trustai.go_verifier_release_run_bundle import (
    GO_VERIFIER_RELEASE_RUN_BUNDLE_ENTRY_TYPE,
    GO_VERIFIER_RELEASE_RUN_BUNDLE_SCHEMA,
    append_go_verifier_release_run_bundle,
    build_go_verifier_release_run_bundle,
    extract_go_verifier_release_run_bundle_sources,
    render_go_verifier_release_run_bundle_markdown,
    verify_go_verifier_release_run_bundle,
)
from trustai.standards import write_standards_submission
from trustai.verifier_conformance import write_verifier_conformance_report
from trustai.verifier_release import write_verifier_release_manifest

from tests import test_go_verifier_release_run as release_run_tests


ROOT = Path(__file__).resolve().parents[1]


class GoVerifierReleaseRunBundleTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = release_run_tests.GoVerifierReleaseRunTests(methodName="test_go_verifier_release_run_verifies_and_appends")
        conformance, standards, release = helper._inputs()
        build_attestation, binary_path, build_log_path, sbom_path, provenance_path, signature_path = helper._binary_attestation(
            tmp,
            release,
            conformance,
            standards,
        )
        receipt = helper._release_run(
            release,
            build_attestation,
            conformance,
            standards,
            binary_path,
            (build_log_path, sbom_path, provenance_path, signature_path),
        )
        paths = {
            "release_run": tmp / "go-verifier-release-run.json",
            "verifier_release": tmp / "verifier-release.json",
            "build_attestation": tmp / "go-verifier-build-attestation.json",
            "conformance_report": tmp / "verifier-conformance.json",
            "standards_package": tmp / "standards-submission.json",
        }
        write_go_verifier_release_run_receipt(paths["release_run"], receipt)
        write_verifier_release_manifest(paths["verifier_release"], release)
        write_go_verifier_build_attestation(paths["build_attestation"], build_attestation)
        write_verifier_conformance_report(paths["conformance_report"], conformance)
        write_standards_submission(paths["standards_package"], standards)
        return receipt, release, build_attestation, conformance, standards, paths, binary_path

    def _bundle(self, tmp: Path):
        receipt, release, build_attestation, conformance, standards, paths, binary_path = self._sources(tmp)
        bundle = build_go_verifier_release_run_bundle(
            receipt,
            release,
            build_attestation,
            conformance,
            standards,
            artifact_paths=paths,
            root=ROOT,
            binary_path=binary_path,
            mode="offline-review",
            environment="release-ci",
            reviewer_ref="oidc:auditor.example/go-verifier-release-reviewer",
            generated_at="2026-07-16T00:06:00Z",
        )
        return bundle, receipt, release, build_attestation, paths

    def test_go_verifier_release_run_bundle_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, receipt, release, _, _ = self._bundle(tmp)
            result = verify_go_verifier_release_run_bundle(bundle)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="go-verifier-release-run-bundle-test")
            entry = append_go_verifier_release_run_bundle(chain, bundle)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(GO_VERIFIER_RELEASE_RUN_BUNDLE_SCHEMA, bundle["schema"])
        self.assertEqual(receipt["run_id"], bundle["source"]["run_id"])
        self.assertEqual(release["release_id"], bundle["source"]["release_id"])
        self.assertEqual(5, bundle["summary"]["source_artifact_count"])
        self.assertGreaterEqual(bundle["summary"]["raw_artifact_count"], 20)
        self.assertEqual(GO_VERIFIER_RELEASE_RUN_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
        self.assertEqual({"passed": 7}, entry["payload"]["control_summary"])
        self.assertTrue(chain.verify_all().ok)

    def test_go_verifier_release_run_bundle_renders_and_extracts_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, _, _, _, paths = self._bundle(tmp)
            markdown = render_go_verifier_release_run_bundle_markdown(bundle)
            extract_dir = tmp / "bundle-sources"
            extracted = extract_go_verifier_release_run_bundle_sources(bundle, extract_dir)

            self.assertIn("TrustAI Go Verifier Release-Run Bundle", markdown)
            self.assertIn("Embedded raw artifacts:", markdown)
            self.assertEqual(5 + bundle["summary"]["raw_artifact_count"], len(extracted))
            release_run_extract = extract_dir / "release_run.json"
            self.assertTrue(release_run_extract.exists())
            self.assertEqual(Path(paths["release_run"]).read_bytes(), release_run_extract.read_bytes())
            self.assertTrue((extract_dir / "raw").exists())
            with self.assertRaisesRegex(ValueError, "already exists"):
                extract_go_verifier_release_run_bundle_sources(bundle, extract_dir)
            overwritten = extract_go_verifier_release_run_bundle_sources(bundle, extract_dir, overwrite=True)
            self.assertEqual(len(extracted), len(overwritten))

    def test_go_verifier_release_run_bundle_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["release_run"]["workflow"]["sha256"] = "0" * 64
            result = verify_go_verifier_release_run_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("bundle_id" in error for error in result.errors))
        self.assertTrue(any("source artifact does not match embedded source" in error for error in result.errors))
        self.assertTrue(any("workflow raw artifact missing" in error for error in result.errors))

    def test_go_verifier_release_run_bundle_detects_raw_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["raw_artifacts"][0]["content_b64"] = base64.b64encode(b"tampered").decode("ascii")
            result = verify_go_verifier_release_run_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("raw artifact sha256 mismatch" in error for error in result.errors))

    def test_cli_go_verifier_release_run_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, _, _, _, _, paths, binary_path = self._sources(tmp)
            bundle_path = tmp / "go-verifier-release-run-bundle.json"
            markdown_path = tmp / "go-verifier-release-run-bundle.md"
            render_path = tmp / "go-verifier-release-run-bundle-rendered.md"
            extract_dir = tmp / "go-verifier-release-run-bundle-sources"
            entry_path = tmp / "go-verifier-release-run-bundle-entry.json"
            state_path = tmp / "go-verifier-release-run-bundle-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
                str(paths["release_run"]),
                str(paths["verifier_release"]),
                str(paths["build_attestation"]),
                "--conformance-report", str(paths["conformance_report"]),
                "--standards-package", str(paths["standards_package"]),
                "--root", str(ROOT),
                "--binary", str(binary_path),
            ]

            subprocess.run(
                base
                + [
                    "go-verifier-release-run-bundle",
                    *source_args,
                    "--reviewer-ref", "oidc:auditor.example/go-verifier-release-reviewer",
                    "--environment", "release-ci",
                    "--generated-at", "2026-07-16T00:06:00Z",
                    "--out", str(bundle_path),
                    "--markdown", str(markdown_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(base + ["go-verifier-release-run-bundle-verify", str(bundle_path)], cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            subprocess.run(
                base + ["go-verifier-release-run-bundle-render", str(bundle_path), "--out", str(render_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["go-verifier-release-run-bundle-extract", str(bundle_path), "--out-dir", str(extract_dir)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "go-verifier-release-run-bundle-append",
                    str(bundle_path),
                    "--state", str(state_path),
                    "--tenant", "go-verifier-release-run-bundle-cli",
                    "--out", str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            markdown_exists = markdown_path.exists()
            render_exists = render_path.exists()
            release_run_extract_exists = (extract_dir / "release_run.json").exists()

        self.assertEqual(GO_VERIFIER_RELEASE_RUN_BUNDLE_SCHEMA, bundle["schema"])
        self.assertEqual(GO_VERIFIER_RELEASE_RUN_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
        self.assertTrue(markdown_exists)
        self.assertTrue(render_exists)
        self.assertTrue(release_run_extract_exists)


if __name__ == "__main__":
    unittest.main()
