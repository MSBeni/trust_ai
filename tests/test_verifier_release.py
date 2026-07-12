import copy
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.crypto import sign_value
from trustai.standards import build_standards_submission
from trustai.verifier import load_proof_pack
from trustai.verifier_conformance import build_verifier_conformance_report
from trustai.verifier_release import (
    VERIFIER_RELEASE_SCHEMA,
    build_verifier_release_manifest,
    render_verifier_release_markdown,
    verify_verifier_release_manifest,
)

from tests import test_framework_runtime_service_authority_recorded_export_provider_bundle as provider_bundle_fixtures


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class VerifierReleaseTests(unittest.TestCase):
    def _inputs(self) -> tuple[dict, dict]:
        pack = load_proof_pack(PACK)
        conformance = build_verifier_conformance_report(pack)
        standards = build_standards_submission(ROOT)
        return conformance, standards

    def _provider_bundle(self, tmp: Path):
        helper = provider_bundle_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleTests()
        bundle, *_ = helper._bundle(tmp)
        return bundle

    def _resign_manifest(self, manifest: dict) -> dict:
        body = without_keys(manifest, "release_id", "signatures")
        release_id = content_hash(body)
        return {
            **body,
            "release_id": release_id,
            "signatures": [sign_value({"release_id": release_id, "release": body})],
        }

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
        self.assertEqual(["proof-pack"], manifest["conformance_report"]["targets"])
        self.assertEqual({"proof-pack": conformance["summary"]["case_count"]}, manifest["conformance_report"]["case_count_by_target"])
        self.assertIsNone(manifest["conformance_report"]["source_provider_bundle"])
        self.assertEqual(standards["package_id"], manifest["standards_package"]["package_id"])
        self.assertIn("TrustAI Verifier Release Manifest", markdown)
        self.assertIn("Conformance targets: proof-pack", markdown)

    def test_release_manifest_binds_provider_bundle_conformance_scope(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = load_proof_pack(PACK)
            provider_bundle = self._provider_bundle(tmp)
            conformance = build_verifier_conformance_report(pack, provider_bundle=provider_bundle)
            standards = build_standards_submission(ROOT)
            manifest = build_verifier_release_manifest(
                ROOT,
                conformance_report=conformance,
                standards_package=standards,
            )
            markdown = render_verifier_release_markdown(manifest)

            result = verify_verifier_release_manifest(
                manifest,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
            )
            tampered = copy.deepcopy(manifest)
            tampered["conformance_report"]["case_count_by_target"]["framework-runtime-service-authority-recorded-export-provider-bundle"] = 3
            tampered = self._resign_manifest(tampered)
            tampered_result = verify_verifier_release_manifest(
                tampered,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
            )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(conformance["summary"]["case_count"], manifest["conformance_report"]["case_count"])
        self.assertEqual(
            ["framework-runtime-service-authority-recorded-export-provider-bundle", "proof-pack"],
            manifest["conformance_report"]["targets"],
        )
        self.assertEqual(4, manifest["conformance_report"]["case_count_by_target"]["framework-runtime-service-authority-recorded-export-provider-bundle"])
        self.assertEqual(provider_bundle["bundle_id"], manifest["conformance_report"]["source_provider_bundle"]["bundle_id"])
        self.assertIn("Provider bundle source", markdown)
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("case_count_by_target mismatch" in error for error in tampered_result.errors))

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
