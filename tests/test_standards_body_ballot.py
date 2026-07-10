import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.standards import build_standards_submission
from trustai.standards_body_ballot import (
    STANDARDS_BODY_BALLOT_ENTRY_TYPE,
    STANDARDS_BODY_BALLOT_SCHEMA,
    append_standards_body_ballot_receipt,
    build_standards_body_ballot_receipt,
    verify_standards_body_ballot_receipt,
)
from trustai.standards_body_status import build_standards_body_status_receipt
from trustai.standards_body_submission import build_standards_body_submission_receipt
from trustai.verifier import load_proof_pack
from trustai.verifier_conformance import build_verifier_conformance_report
from trustai.verifier_release import build_verifier_release_manifest

from tests import test_framework_runtime_service_authority_recorded_export_provider_bundle as provider_bundle_fixtures


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


class StandardsBodyBallotTests(unittest.TestCase):
    def _sources(self, *, provider_bundle: dict | None = None):
        pack = load_proof_pack(PACK)
        standards = build_standards_submission(ROOT)
        conformance = build_verifier_conformance_report(pack, provider_bundle=provider_bundle)
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
            status="submitted",
            submitted_at="2026-07-17T00:00:00Z",
            acknowledgement_due_at="2026-08-17T00:00:00Z",
        )
        status = build_standards_body_status_receipt(
            submission,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            new_status="ballot_open",
            docket_ref="LF-TRUSTAI-DKT-2026-001",
            status_ref="LF-TRUSTAI-DKT-2026-001:ballot",
            ballot_ref="LF-TRUSTAI-BALLOT-2026-001",
            ballot_opened_at="2026-07-19T00:00:00Z",
            actor_ref="oidc:standards.example/chair-1",
            actor_role="working-group-chair",
            reason="Working group opened a draft-specification ballot.",
            evidence_refs=["mail:trustai-wg/2026-07-19"],
            decided_at="2026-07-19T00:00:00Z",
            effective_at="2026-07-19T01:00:00Z",
        )
        return standards, conformance, release, submission, status

    def _provider_bundle(self, tmp: Path):
        helper = provider_bundle_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleTests()
        bundle, *_ = helper._bundle(tmp)
        return bundle

    def test_standards_body_ballot_verifies_and_appends(self):
        standards, conformance, release, submission, status = self._sources()
        receipt = build_standards_body_ballot_receipt(
            submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            ballot_ref="LF-TRUSTAI-BALLOT-2026-001",
            decision_ref="LF-TRUSTAI-DECISION-2026-001",
            motion="Accept TrustAI proof-pack v0.1 as a working-group draft specification.",
            eligible_voters=7,
            votes_for=6,
            votes_against=1,
            abstentions=0,
            quorum_required=4,
            approval_threshold_percent=66,
            opened_at="2026-07-19T00:00:00Z",
            closed_at="2026-07-25T00:00:00Z",
            decided_at="2026-07-25T02:00:00Z",
            effective_at="2026-07-25T03:00:00Z",
            minutes_ref="minutes:trustai-wg/2026-07-25",
            actor_ref="oidc:standards.example/chair-1",
            actor_role="working-group-chair",
            evidence_refs=["minutes:trustai-wg/2026-07-25"],
        )

        result = verify_standards_body_ballot_receipt(
            receipt,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "standards-body-ballot-chain.json", tenant_id="standards-body-ballot-local")
            entry = append_standards_body_ballot_receipt(
                chain,
                receipt,
                submission_receipt=submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

        self.assertEqual(STANDARDS_BODY_BALLOT_SCHEMA, receipt["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("LF-TRUSTAI-BALLOT-2026-001", result.ballot_ref)
        self.assertEqual("accepted", result.outcome)
        self.assertTrue(receipt["ballot"]["quorum_met"])
        self.assertTrue(receipt["ballot"]["approval_met"])
        self.assertEqual(["proof-pack"], receipt["target_submission"]["conformance_report"]["targets"])
        self.assertEqual(STANDARDS_BODY_BALLOT_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["ballot_id"], entry["payload"]["ballot_id"])

    def test_standards_body_ballot_preserves_provider_bundle_conformance_scope(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            provider_bundle = self._provider_bundle(Path(tmp_dir))
            standards, conformance, release, submission, status = self._sources(provider_bundle=provider_bundle)
            receipt = build_standards_body_ballot_receipt(
                submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
                ballot_ref="LF-TRUSTAI-BALLOT-2026-001",
                decision_ref="LF-TRUSTAI-DECISION-2026-001",
                eligible_voters=7,
                votes_for=6,
                votes_against=1,
                abstentions=0,
                quorum_required=4,
                approval_threshold_percent=66,
                opened_at="2026-07-19T00:00:00Z",
                closed_at="2026-07-25T00:00:00Z",
                decided_at="2026-07-25T02:00:00Z",
                actor_ref="oidc:standards.example/chair-1",
            )
            result = verify_standards_body_ballot_receipt(
                receipt,
                submission_receipt=submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(
            ["framework-runtime-service-authority-recorded-export-provider-bundle", "proof-pack"],
            receipt["target_submission"]["conformance_report"]["targets"],
        )
        self.assertEqual(4, receipt["target_submission"]["conformance_report"]["case_count_by_target"]["framework-runtime-service-authority-recorded-export-provider-bundle"])
        self.assertEqual(provider_bundle["bundle_id"], receipt["target_submission"]["conformance_report"]["source_provider_bundle"]["bundle_id"])
        self.assertEqual(provider_bundle["bundle_id"], receipt["target_submission"]["verifier_release"]["conformance_source_provider_bundle"]["bundle_id"])

    def test_standards_body_ballot_detects_source_status_tamper(self):
        standards, conformance, release, submission, status = self._sources()
        receipt = build_standards_body_ballot_receipt(
            submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
            ballot_ref="LF-TRUSTAI-BALLOT-2026-001",
            decision_ref="LF-TRUSTAI-DECISION-2026-001",
            eligible_voters=5,
            votes_for=4,
            votes_against=1,
            abstentions=0,
            quorum_required=3,
            approval_threshold_percent=60,
            opened_at="2026-07-19T00:00:00Z",
            closed_at="2026-07-25T00:00:00Z",
            decided_at="2026-07-25T02:00:00Z",
            actor_ref="oidc:standards.example/chair-1",
        )
        tampered = copy.deepcopy(receipt)
        tampered["source_artifacts"][1]["content_hash"] = "changed"

        result = verify_standards_body_ballot_receipt(
            tampered,
            submission_receipt=submission,
            status_receipt=status,
            standards_package=standards,
            verifier_release=release,
            conformance_report=conformance,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("ballot_id" in error for error in result.errors))
        self.assertTrue(any("standards_body_status_receipt content_hash mismatch" in error for error in result.errors))

    def test_standards_body_ballot_rejects_accepted_without_approval(self):
        standards, conformance, release, submission, status = self._sources()

        with self.assertRaisesRegex(ValueError, "requires quorum and approval"):
            build_standards_body_ballot_receipt(
                submission,
                status_receipt=status,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
                ballot_ref="LF-TRUSTAI-BALLOT-2026-001",
                decision_ref="LF-TRUSTAI-DECISION-2026-001",
                eligible_voters=5,
                votes_for=2,
                votes_against=3,
                abstentions=0,
                quorum_required=3,
                approval_threshold_percent=60,
                opened_at="2026-07-19T00:00:00Z",
                closed_at="2026-07-25T00:00:00Z",
                decided_at="2026-07-25T02:00:00Z",
                actor_ref="oidc:standards.example/chair-1",
            )


if __name__ == "__main__":
    unittest.main()
