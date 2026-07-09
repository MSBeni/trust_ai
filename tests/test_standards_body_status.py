import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.standards import build_standards_submission
from trustai.standards_body_status import (
    STANDARDS_BODY_STATUS_ENTRY_TYPE,
    STANDARDS_BODY_STATUS_SCHEMA,
    append_standards_body_status_receipt,
    build_standards_body_status_receipt,
    verify_standards_body_status_receipt,
)
from trustai.standards_body_submission import build_standards_body_submission_receipt
from trustai.verifier import load_proof_pack
from trustai.verifier_conformance import build_verifier_conformance_report
from trustai.verifier_release import build_verifier_release_manifest


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class StandardsBodyStatusTests(unittest.TestCase):
    def _sources(self, *, submission_status: str = "submitted"):
        pack = load_proof_pack(PACK)
        standards = build_standards_submission(ROOT)
        conformance = build_verifier_conformance_report(pack)
        release = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        submission = build_standards_body_submission_receipt(
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
            status=submission_status,
            submitted_at="2026-07-17T00:00:00Z",
            acknowledgement_due_at="2026-08-17T00:00:00Z",
        )
        return standards, conformance, release, submission

    def test_standards_body_status_verifies_and_appends(self):
        standards, conformance, release, submission = self._sources()
        receipt = build_standards_body_status_receipt(
            submission,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            new_status="acknowledged",
            docket_ref="LF-TRUSTAI-DKT-2026-001",
            status_ref="LF-TRUSTAI-DKT-2026-001:ack",
            actor_ref="oidc:standards.example/chair-1",
            actor_role="working-group-chair",
            reason="Submission accepted into the working-group intake docket.",
            evidence_refs=["mail:trustai-wg/2026-07-18"],
            decided_at="2026-07-18T00:00:00Z",
            effective_at="2026-07-18T01:00:00Z",
        )

        result = verify_standards_body_status_receipt(
            receipt,
            submission_receipt=submission,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "standards-body-status-chain.json", tenant_id="standards-body-status-local")
            entry = append_standards_body_status_receipt(
                chain,
                receipt,
                submission_receipt=submission,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

        self.assertEqual(STANDARDS_BODY_STATUS_SCHEMA, receipt["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("submitted", result.previous_status)
        self.assertEqual("acknowledged", result.new_status)
        self.assertEqual(STANDARDS_BODY_STATUS_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["status_id"], entry["payload"]["status_id"])

    def test_standards_body_status_detects_source_artifact_tamper(self):
        standards, conformance, release, submission = self._sources()
        receipt = build_standards_body_status_receipt(
            submission,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            new_status="under_review",
            actor_ref="oidc:standards.example/chair-1",
            decided_at="2026-07-18T00:00:00Z",
        )
        tampered = copy.deepcopy(receipt)
        tampered["source_artifacts"][0]["content_hash"] = "changed"

        result = verify_standards_body_status_receipt(
            tampered,
            submission_receipt=submission,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("status_id" in error for error in result.errors))
        self.assertTrue(any("standards_body_submission_receipt content_hash mismatch" in error for error in result.errors))

    def test_standards_body_status_rejects_noop_status_change(self):
        _, _, _, submission = self._sources(submission_status="acknowledged")

        with self.assertRaisesRegex(ValueError, "must differ"):
            build_standards_body_status_receipt(
                submission,
                new_status="acknowledged",
                actor_ref="oidc:standards.example/chair-1",
                decided_at="2026-07-18T00:00:00Z",
            )

    def test_standards_body_status_requires_decision_or_ballot_for_accepted(self):
        _, _, _, submission = self._sources()

        with self.assertRaisesRegex(ValueError, "requires decision_ref or ballot_ref"):
            build_standards_body_status_receipt(
                submission,
                new_status="accepted",
                actor_ref="oidc:standards.example/chair-1",
                decided_at="2026-07-18T00:00:00Z",
            )


if __name__ == "__main__":
    unittest.main()
