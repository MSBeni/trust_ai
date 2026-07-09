import copy
import unittest
from pathlib import Path
import tempfile

from trustai.chain import EvidenceChain
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
