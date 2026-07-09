import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.go_verifier_build import (
    GO_VERIFIER_BUILD_ENTRY_TYPE,
    GO_VERIFIER_BUILD_SCHEMA,
    append_go_verifier_build_attestation,
    build_go_verifier_build_attestation,
    verify_go_verifier_build_attestation,
    write_go_verifier_build_attestation,
)
from trustai.standards import build_standards_submission, write_standards_markdown, write_standards_submission
from trustai.verifier import load_proof_pack
from trustai.verifier_conformance import build_verifier_conformance_report, write_verifier_conformance_report
from trustai.verifier_release import build_verifier_release_manifest, write_verifier_release_manifest


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class GoVerifierBuildTests(unittest.TestCase):
    def _inputs(self):
        pack = load_proof_pack(PACK)
        conformance = build_verifier_conformance_report(pack)
        standards = build_standards_submission(ROOT)
        release = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        return conformance, standards, release

    def _attestation(self, release, conformance, standards, **overrides):
        values = {
            "verifier_release": release,
            "root": ROOT,
            "conformance_report": conformance,
            "standards_package": standards,
            "mode": "source-plan",
            "builder_ref": "builder:trustai/go-verifier/local",
            "toolchain_ref": "go:download-required",
            "toolchain_version": "not-installed-local-reference",
            "goos": "linux",
            "goarch": "amd64",
            "cgo_enabled": False,
            "trimpath": True,
            "ldflags": "-s -w",
            "build_started_at": "2026-07-16T00:00:00Z",
            "build_finished_at": "2026-07-16T00:01:00Z",
            "attested_at": "2026-07-16T00:02:00Z",
        }
        values.update(overrides)
        return build_go_verifier_build_attestation(**values)

    def test_go_verifier_build_attestation_verifies_and_appends_source_plan(self):
        conformance, standards, release = self._inputs()
        attestation = self._attestation(release, conformance, standards)

        result = verify_go_verifier_build_attestation(
            attestation,
            release,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="go-verifier-build-local")
            entry = append_go_verifier_build_attestation(
                chain,
                attestation,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
            )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(GO_VERIFIER_BUILD_SCHEMA, attestation["schema"])
        self.assertEqual("source-plan", attestation["build"]["mode"])
        self.assertEqual("not-built", attestation["binary"]["status"])
        self.assertEqual(release["release_id"], attestation["source"]["release_id"])
        self.assertIn("verifier/go/trustai-verify/main.go", {item["path"] for item in attestation["go_sources"]})
        self.assertEqual(GO_VERIFIER_BUILD_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(attestation["build_id"], entry["payload"]["build_id"])

    def test_go_verifier_build_detects_release_source_mismatch(self):
        conformance, standards, release = self._inputs()
        attestation = self._attestation(release, conformance, standards)
        tampered = copy.deepcopy(release)
        tampered["source_files"][-1]["sha256"] = "0" * 64

        result = verify_go_verifier_build_attestation(
            attestation,
            tampered,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("verifier release source" in error for error in result.errors))
        self.assertTrue(any("go_sources do not match" in error or "go_source_hash" in error for error in result.errors))

    def test_go_verifier_build_rejects_cgo_enabled(self):
        conformance, standards, release = self._inputs()
        attestation = self._attestation(release, conformance, standards, cgo_enabled=True)

        result = verify_go_verifier_build_attestation(
            attestation,
            release,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )

        self.assertFalse(result.ok)
        self.assertIn("Go verifier build must set cgo_enabled=false for static verifier releases", result.errors)

    def test_go_verifier_build_requires_binary_for_binary_attested_mode(self):
        conformance, standards, release = self._inputs()

        with self.assertRaisesRegex(ValueError, "binary_path is required"):
            self._attestation(release, conformance, standards, mode="binary-attested")

    def test_cli_go_verifier_build_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            conformance, standards, release = self._inputs()
            conformance_path = tmp / "verifier-conformance.json"
            standards_path = tmp / "standards-submission.json"
            standards_md_path = tmp / "standards-submission.md"
            release_path = tmp / "verifier-release.json"
            attestation_path = tmp / "go-verifier-build.json"
            entry_path = tmp / "go-verifier-build-entry.json"
            state_path = tmp / "go-verifier-build-chain.json"
            write_verifier_conformance_report(conformance_path, conformance)
            write_standards_submission(standards_path, standards)
            write_standards_markdown(standards_md_path, standards)
            write_verifier_release_manifest(release_path, release)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(release_path),
                "--conformance-report", str(conformance_path),
                "--standards-package", str(standards_path),
                "--root", str(ROOT),
            ]
            build_args = [
                "--mode", "source-plan",
                "--builder-ref", "builder:trustai/go-verifier/local",
                "--toolchain-ref", "go:download-required",
                "--toolchain-version", "not-installed-local-reference",
                "--goos", "linux",
                "--goarch", "amd64",
                "--build-started-at", "2026-07-16T00:00:00Z",
                "--build-finished-at", "2026-07-16T00:01:00Z",
                "--attested-at", "2026-07-16T00:02:00Z",
            ]
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-build-attestation", *source_args, *build_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-build-verify", str(attestation_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "go-verifier-build-append",
                    str(attestation_path),
                    *source_args,
                    "--state", str(state_path),
                    "--tenant", "go-verifier-build-local",
                    "--out", str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(attestation_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
