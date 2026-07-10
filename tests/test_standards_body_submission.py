import copy
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.crypto import sign_value
from trustai.standards import build_standards_submission
from trustai.standards_body_submission import (
    STANDARDS_BODY_SUBMISSION_ENTRY_TYPE,
    STANDARDS_BODY_SUBMISSION_SCHEMA,
    append_standards_body_submission_receipt,
    build_standards_body_submission_receipt,
    verify_standards_body_submission_receipt,
)
from trustai.verifier import load_proof_pack
from trustai.verifier_conformance import build_verifier_conformance_report
from trustai.verifier_release import build_verifier_release_manifest

from tests import test_framework_runtime_service_authority_recorded_export_provider_bundle as provider_bundle_fixtures


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class StandardsBodySubmissionTests(unittest.TestCase):
    def _sources(self):
        pack = load_proof_pack(PACK)
        standards = build_standards_submission(ROOT)
        conformance = build_verifier_conformance_report(pack)
        release = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        return standards, conformance, release

    def _provider_bundle(self, tmp: Path):
        helper = provider_bundle_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleTests()
        bundle, *_ = helper._bundle(tmp)
        return bundle

    def _resign_receipt(self, receipt: dict) -> dict:
        body = without_keys(receipt, "submission_id", "signatures")
        submission_id = content_hash(body)
        return {
            **body,
            "submission_id": submission_id,
            "signatures": [sign_value({"submission_id": submission_id, "submission": body})],
        }

    def test_standards_body_submission_verifies_and_appends(self):
        standards, conformance, release = self._sources()
        receipt = build_standards_body_submission_receipt(
            standards,
            release,
            conformance,
            root=ROOT,
            standards_body="Linux Foundation TrustAI Working Group",
            program_ref="LF-TRUSTAI-PROOF-PACKS",
            target_track="draft-specification",
            endpoint="https://standards.example/submissions/trustai",
            contact_ref="wg:trustai-proof-packs",
            submission_ref="STD-TRUSTAI-2026-001",
            submitted_at="2026-07-17T00:00:00Z",
            acknowledgement_due_at="2026-08-17T00:00:00Z",
        )

        result = verify_standards_body_submission_receipt(
            receipt,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "standards-body-chain.json", tenant_id="standards-body-local")
            entry = append_standards_body_submission_receipt(
                chain,
                receipt,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

        self.assertEqual(STANDARDS_BODY_SUBMISSION_SCHEMA, receipt["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("submitted", result.status)
        self.assertEqual(STANDARDS_BODY_SUBMISSION_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["submission_id"], entry["payload"]["submission_id"])
        self.assertEqual(["proof-pack"], receipt["conformance_report"]["targets"])
        self.assertEqual(["proof-pack"], receipt["verifier_release"]["conformance_targets"])

    def test_standards_body_submission_binds_provider_bundle_conformance_scope(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = load_proof_pack(PACK)
            standards = build_standards_submission(ROOT)
            provider_bundle = self._provider_bundle(tmp)
            conformance = build_verifier_conformance_report(pack, provider_bundle=provider_bundle)
            release = build_verifier_release_manifest(
                ROOT,
                conformance_report=conformance,
                standards_package=standards,
            )
            receipt = build_standards_body_submission_receipt(
                standards,
                release,
                conformance,
                root=ROOT,
                submitted_at="2026-07-17T00:00:00Z",
            )
            result = verify_standards_body_submission_receipt(
                receipt,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )
            tampered = copy.deepcopy(receipt)
            tampered["conformance_report"]["case_count_by_target"]["framework-runtime-service-authority-recorded-export-provider-bundle"] = 3
            tampered = self._resign_receipt(tampered)
            tampered_result = verify_standards_body_submission_receipt(
                tampered,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

        conformance_artifact = next(item for item in receipt["source_artifacts"] if item["name"] == "verifier_conformance_report")
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(
            ["framework-runtime-service-authority-recorded-export-provider-bundle", "proof-pack"],
            receipt["conformance_report"]["targets"],
        )
        self.assertEqual(4, receipt["conformance_report"]["case_count_by_target"]["framework-runtime-service-authority-recorded-export-provider-bundle"])
        self.assertEqual(provider_bundle["bundle_id"], receipt["conformance_report"]["source_provider_bundle"]["bundle_id"])
        self.assertEqual(provider_bundle["bundle_id"], receipt["verifier_release"]["conformance_source_provider_bundle"]["bundle_id"])
        self.assertEqual(receipt["conformance_report"]["targets"], conformance_artifact["targets"])
        self.assertEqual(provider_bundle["bundle_id"], conformance_artifact["source_provider_bundle"]["bundle_id"])
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("conformance record does not match source report" in error for error in tampered_result.errors))

    def test_standards_body_submission_detects_source_hash_tamper(self):
        standards, conformance, release = self._sources()
        receipt = build_standards_body_submission_receipt(
            standards,
            release,
            conformance,
            root=ROOT,
            submitted_at="2026-07-17T00:00:00Z",
        )
        tampered = copy.deepcopy(receipt)
        tampered["source_artifacts"][0]["content_hash"] = "changed"

        result = verify_standards_body_submission_receipt(
            tampered,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("submission_id" in error for error in result.errors))
        self.assertTrue(any("standards_package content_hash mismatch" in error for error in result.errors))

    def test_standards_body_submission_rejects_release_for_other_standards_package(self):
        standards, conformance, release = self._sources()
        other_standards = copy.deepcopy(standards)
        other_standards["target_body"] = "Different Body"
        other_standards["package_id"] = "not-the-same"
        mismatched_release = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=other_standards,
        )

        with self.assertRaisesRegex(ValueError, "invalid verifier release manifest"):
            build_standards_body_submission_receipt(
                standards,
                mismatched_release,
                conformance,
                root=ROOT,
                submitted_at="2026-07-17T00:00:00Z",
            )


if __name__ == "__main__":
    unittest.main()
