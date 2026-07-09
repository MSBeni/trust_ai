import copy
import unittest
from pathlib import Path

from trustai.standards import build_standards_submission
from trustai.verifier import load_proof_pack
from trustai.verifier_conformance import build_verifier_conformance_report
from trustai.verifier_release import (
    VERIFIER_RELEASE_SCHEMA,
    build_verifier_release_manifest,
    render_verifier_release_markdown,
    verify_verifier_release_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class VerifierReleaseTests(unittest.TestCase):
    def _inputs(self) -> tuple[dict, dict]:
        pack = load_proof_pack(PACK)
        conformance = build_verifier_conformance_report(pack)
        standards = build_standards_submission(ROOT)
        return conformance, standards

    def test_release_manifest_binds_source_conformance_and_standards(self):
        conformance, standards = self._inputs()
        manifest = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )

        result = verify_verifier_release_manifest(
            manifest,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        markdown = render_verifier_release_markdown(manifest)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(VERIFIER_RELEASE_SCHEMA, manifest["schema"])
        self.assertEqual("offline-accountless", manifest["release"]["mode"])
        self.assertIn("src/trustai/verifier.py", {item["path"] for item in manifest["source_files"]})
        self.assertIn("python-reference-module", {item["id"] for item in manifest["targets"]})
        self.assertEqual(conformance["report_id"], manifest["conformance_report"]["report_id"])
        self.assertEqual(standards["package_id"], manifest["standards_package"]["package_id"])
        self.assertIn("TrustAI Verifier Release Manifest", markdown)

    def test_release_manifest_rejects_source_hash_tamper(self):
        conformance, standards = self._inputs()
        manifest = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        tampered = copy.deepcopy(manifest)
        tampered["source_files"][0]["sha256"] = "0" * 64

        result = verify_verifier_release_manifest(
            tampered,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("release_id" in error for error in result.errors))
        self.assertTrue(any("sha256 mismatch" in error for error in result.errors))

    def test_release_manifest_rejects_missing_conformance_reference(self):
        manifest = build_verifier_release_manifest(ROOT)
        manifest.pop("conformance_report", None)

        result = verify_verifier_release_manifest(manifest, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("conformance report" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
