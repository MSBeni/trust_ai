import copy
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.crypto import sign_value
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.eu_ai_act import build_eu_ai_act_document
from trustai.gate import append_eval_and_gate
from trustai.lifecycle import append_demotion, append_incident, append_rollback, load_incident
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.regulator import build_regulator_disclosure
from trustai.regulator_acceptance import (
    REGULATOR_ACCEPTANCE_ENTRY_TYPE,
    REGULATOR_ACCEPTANCE_SCHEMA,
    append_regulator_acceptance,
    build_regulator_acceptance,
    verify_regulator_acceptance,
)
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.supervised_access import build_supervised_access_receipt


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class RegulatorAcceptanceTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="acceptance-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        append_runtime_attestation(chain, contract, load_action(ACTION))
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        append_policy_decision(
            chain,
            load_policy_pack(POLICY),
            load_action(ACTION),
            proof_pack=pack,
            now="2026-07-04T02:00:00Z",
        )
        incident_entry = append_incident(chain, load_incident(INCIDENT))
        append_demotion(chain, contract, "High-severity latency drift incident", incident_entry["entry_id"])
        append_rollback(
            chain,
            contract,
            "sha256:previous-stable-agent-version",
            "Restore last known stable risk agent",
            incident_entry["entry_id"],
        )
        disclosure = build_regulator_disclosure(chain, pack, audience="Example Supervisor")
        document = build_eu_ai_act_document(pack, disclosure, operator="aitrade")
        supervised = build_supervised_access_receipt(
            pack,
            disclosure=disclosure,
            subject_ref="oidc:regulator.example/supervisor-123",
            organization="Example Supervisor",
            role="regulator_reviewer",
            audience_type="regulator",
            purpose="EU AI Act supervised review",
            issued_at="2026-07-08T00:00:00Z",
            expires_at="2026-08-08T00:00:00Z",
        )
        return chain, pack, disclosure, document, supervised

    def _resign_acceptance(self, acceptance: dict) -> None:
        body = without_keys(acceptance, "acceptance_id", "signatures")
        acceptance_id = content_hash(body)
        acceptance["acceptance_id"] = acceptance_id
        acceptance["signatures"] = [sign_value({"acceptance_id": acceptance_id, "acceptance": body})]

    def test_regulator_acceptance_verifies_sources_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack, disclosure, document, supervised = self._sources(Path(tmp_dir))
            acceptance = build_regulator_acceptance(
                pack,
                disclosure,
                document,
                supervised_access_receipt=supervised,
                regulator="Example Supervisor",
                authority_ref="EU-NCA:EXAMPLE",
                reviewer_ref="oidc:regulator.example/supervisor-123",
                examination_ref="EXAM-2026-TRUSTAI-001",
                accepted_at="2026-07-10T00:00:00Z",
                review_period_start="2026-07-08T00:00:00Z",
                review_period_end="2026-07-10T00:00:00Z",
                observations=["Offline verifier and selective disclosure package verified."],
            )

            result = verify_regulator_acceptance(
                acceptance,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                eu_ai_act_document=document,
                supervised_access_receipt=supervised,
            )
            entry = append_regulator_acceptance(chain, acceptance)

            self.assertEqual(REGULATOR_ACCEPTANCE_SCHEMA, acceptance["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("accepted", acceptance["decision"]["outcome"])
            self.assertEqual(REGULATOR_ACCEPTANCE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(acceptance["acceptance_id"], entry["payload"]["acceptance_id"])
            self.assertIn("eu_ai_act_document", {artifact["name"] for artifact in acceptance["source_artifacts"]})
            self.assertTrue(chain.verify_all().ok)

    def test_regulator_acceptance_detects_tampered_source_binding(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, document, supervised = self._sources(Path(tmp_dir))
            acceptance = build_regulator_acceptance(
                pack,
                disclosure,
                document,
                supervised_access_receipt=supervised,
                regulator="Example Supervisor",
                authority_ref="EU-NCA:EXAMPLE",
                reviewer_ref="oidc:regulator.example/supervisor-123",
                accepted_at="2026-07-10T00:00:00Z",
            )
            tampered = copy.deepcopy(acceptance)
            tampered["source_artifacts"][2]["document_id"] = "changed"

            result = verify_regulator_acceptance(
                tampered,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                eu_ai_act_document=document,
                supervised_access_receipt=supervised,
            )

            self.assertFalse(result.ok)
            self.assertIn("acceptance_id does not match canonical acceptance body", result.errors)
            self.assertIn("artifact eu_ai_act_document document_id mismatch", result.errors)

    def test_regulator_acceptance_rejects_resigned_source_summary_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, document, supervised = self._sources(Path(tmp_dir))
            acceptance = build_regulator_acceptance(
                pack,
                disclosure,
                document,
                supervised_access_receipt=supervised,
                regulator="Example Supervisor",
                authority_ref="EU-NCA:EXAMPLE",
                reviewer_ref="oidc:regulator.example/supervisor-123",
                accepted_at="2026-07-10T00:00:00Z",
            )
            artifact_by_name = {artifact["name"]: artifact for artifact in acceptance["source_artifacts"]}
            artifact_by_name["supervised_access"]["reviewer"]["role"] = "changed"
            self._resign_acceptance(acceptance)

            result = verify_regulator_acceptance(
                acceptance,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                eu_ai_act_document=document,
                supervised_access_receipt=supervised,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("acceptance_id does not match canonical acceptance body", result.errors)
            self.assertNotIn("regulator acceptance signature invalid", result.errors)
            self.assertIn("artifact supervised_access reviewer mismatch", result.errors)

    def test_regulator_acceptance_rejects_reviewer_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, document, supervised = self._sources(Path(tmp_dir))
            acceptance = build_regulator_acceptance(
                pack,
                disclosure,
                document,
                supervised_access_receipt=supervised,
                regulator="Example Supervisor",
                authority_ref="EU-NCA:EXAMPLE",
                reviewer_ref="oidc:regulator.example/different-reviewer",
                accepted_at="2026-07-10T00:00:00Z",
            )

            result = verify_regulator_acceptance(
                acceptance,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                eu_ai_act_document=document,
                supervised_access_receipt=supervised,
            )

            self.assertFalse(result.ok)
            self.assertIn("regulator acceptance reviewer_ref does not match supervised access reviewer subject_ref", result.errors)

    def test_regulator_acceptance_rejects_supervised_access_outside_review_period(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, document, supervised = self._sources(Path(tmp_dir))
            acceptance = build_regulator_acceptance(
                pack,
                disclosure,
                document,
                supervised_access_receipt=supervised,
                regulator="Example Supervisor",
                authority_ref="EU-NCA:EXAMPLE",
                reviewer_ref="oidc:regulator.example/supervisor-123",
                accepted_at="2026-07-10T00:00:00Z",
                review_period_start="2026-07-09T00:00:00Z",
                review_period_end="2026-07-10T00:00:00Z",
            )

            result = verify_regulator_acceptance(
                acceptance,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                eu_ai_act_document=document,
                supervised_access_receipt=supervised,
            )

            self.assertFalse(result.ok)
            self.assertIn("supervised access issued_at is outside regulator acceptance review period", result.errors)

    def test_regulator_acceptance_warns_when_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, document, _ = self._sources(Path(tmp_dir))
            acceptance = build_regulator_acceptance(
                pack,
                disclosure,
                document,
                regulator="Example Supervisor",
                authority_ref="EU-NCA:EXAMPLE",
                reviewer_ref="oidc:regulator.example/supervisor-123",
                decision="needs_remediation",
                accepted_at="2026-07-10T00:00:00Z",
            )
            result = verify_regulator_acceptance(
                acceptance,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                eu_ai_act_document=document,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertIn("regulator acceptance decision is not an accepted outcome", result.warnings)


if __name__ == "__main__":
    unittest.main()
