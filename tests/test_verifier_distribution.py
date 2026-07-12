import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.standards import build_standards_submission, write_standards_markdown, write_standards_submission
from trustai.verifier import load_proof_pack
from trustai.verifier_conformance import build_verifier_conformance_report, write_verifier_conformance_report
from trustai.verifier_distribution import (
    VERIFIER_DISTRIBUTION_ENTRY_TYPE,
    VERIFIER_DISTRIBUTION_SCHEMA,
    append_verifier_distribution_receipt,
    build_verifier_distribution_receipt,
    verify_verifier_distribution_receipt,
)
from trustai.verifier_release import build_verifier_release_manifest, write_verifier_release_manifest


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class VerifierDistributionTests(unittest.TestCase):
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

    def _paths(self, tmp: Path):
        return {
            "bundle_path": tmp / "verifier-source-bundle.zip",
            "sbom_path": tmp / "verifier-source-sbom.json",
            "provenance_path": tmp / "verifier-source-provenance.json",
            "signature_path": tmp / "verifier-source-signature.json",
        }

    def _receipt(self, tmp: Path, release, conformance, standards, **overrides):
        values = {
            "verifier_release": release,
            "root": ROOT,
            "conformance_report": conformance,
            "standards_package": standards,
            **self._paths(tmp),
            "distribution_ref": "release:trustai-verifier/source-v0.1",
            "channel": "local-source-bundle",
            "publisher_ref": "publisher:trustai/local",
            "release_url": "https://github.com/MSBeni/trust_ai/releases/tag/source-v0.1",
            "generated_at": "2026-07-16T00:03:00Z",
        }
        values.update(overrides)
        return build_verifier_distribution_receipt(**values)

    def test_verifier_distribution_verifies_and_appends(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt = self._receipt(tmp, release, conformance, standards)
            paths = self._paths(tmp)

            result = verify_verifier_distribution_receipt(
                receipt,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                **paths,
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="verifier-distribution-local")
            entry = append_verifier_distribution_receipt(
                chain,
                receipt,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                **paths,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(VERIFIER_DISTRIBUTION_SCHEMA, receipt["schema"])
            self.assertEqual("source-bundle", receipt["distribution"]["mode"])
            self.assertEqual(["proof-pack"], receipt["release"]["conformance_targets"])
            self.assertEqual({"proof-pack": conformance["summary"]["case_count"]}, receipt["release"]["conformance_case_count_by_target"])
            self.assertTrue(paths["bundle_path"].exists())
            self.assertTrue(paths["sbom_path"].exists())
            self.assertTrue(paths["provenance_path"].exists())
            self.assertTrue(paths["signature_path"].exists())
            sbom = json.loads(paths["sbom_path"].read_text(encoding="utf-8"))
            provenance = json.loads(paths["provenance_path"].read_text(encoding="utf-8"))
            conformance_material = next(item for item in provenance["materials"] if item["uri"] == "verifier-conformance")
            self.assertEqual(["proof-pack"], sbom["release"]["conformance_targets"])
            self.assertEqual(["proof-pack"], conformance_material["targets"])
            self.assertEqual({"proof-pack": conformance["summary"]["case_count"]}, conformance_material["case_count_by_target"])
            self.assertEqual(VERIFIER_DISTRIBUTION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["distribution_id"], entry["payload"]["distribution_id"])

    def test_verifier_distribution_detects_bundle_tamper(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt = self._receipt(tmp, release, conformance, standards)
            paths = self._paths(tmp)
            with paths["bundle_path"].open("ab") as handle:
                handle.write(b"tamper")

            result = verify_verifier_distribution_receipt(
                receipt,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                **paths,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("bundle sha256 mismatch" in error for error in result.errors))

    def test_verifier_distribution_detects_release_mismatch(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt = self._receipt(tmp, release, conformance, standards)
            tampered = copy.deepcopy(release)
            tampered["source_files"][-1]["sha256"] = "0" * 64

            result = verify_verifier_distribution_receipt(
                receipt,
                tampered,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                **self._paths(tmp),
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("verifier release source" in error for error in result.errors))

    def test_cli_verifier_distribution_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            conformance, standards, release = self._inputs()
            conformance_path = tmp / "verifier-conformance.json"
            standards_path = tmp / "standards-submission.json"
            standards_md_path = tmp / "standards-submission.md"
            release_path = tmp / "verifier-release.json"
            receipt_path = tmp / "verifier-distribution.json"
            entry_path = tmp / "verifier-distribution-entry.json"
            state_path = tmp / "verifier-distribution-chain.json"
            bundle_path = tmp / "verifier-source-bundle.zip"
            sbom_path = tmp / "verifier-source-sbom.json"
            provenance_path = tmp / "verifier-source-provenance.json"
            signature_path = tmp / "verifier-source-signature.json"
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
                "--bundle", str(bundle_path),
                "--sbom", str(sbom_path),
                "--provenance", str(provenance_path),
                "--signature", str(signature_path),
            ]
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "verifier-distribution",
                    *source_args,
                    "--distribution-ref", "release:trustai-verifier/source-v0.1",
                    "--publisher-ref", "publisher:trustai/local",
                    "--release-url", "https://github.com/MSBeni/trust_ai/releases/tag/source-v0.1",
                    "--generated-at", "2026-07-16T00:03:00Z",
                    "--out", str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "verifier-distribution-verify", str(receipt_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "verifier-distribution-append",
                    str(receipt_path),
                    *source_args,
                    "--state", str(state_path),
                    "--tenant", "verifier-distribution-local",
                    "--out", str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(receipt_path.exists())
            self.assertTrue(entry_path.exists())
            self.assertEqual("trustai.verifier-source-sbom/0.1", json.loads(sbom_path.read_text())["schema"])


if __name__ == "__main__":
    unittest.main()
