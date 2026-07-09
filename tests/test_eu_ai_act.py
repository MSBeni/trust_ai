import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.eu_ai_act import (
    EU_AI_ACT_DOCUMENT_SCHEMA,
    build_eu_ai_act_document,
    verify_eu_ai_act_document,
)
from trustai.gate import append_eval_and_gate
from trustai.lifecycle import append_demotion, append_incident, append_rollback, load_incident
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.regulator import build_regulator_disclosure
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class EUAIActDocumentTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
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
        disclosure = build_regulator_disclosure(chain, pack)
        return pack, disclosure

    def test_eu_ai_act_document_links_pack_disclosure_and_post_market_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure = self._sources(Path(tmp_dir))
            document = build_eu_ai_act_document(pack, disclosure, operator="aitrade")
            result = verify_eu_ai_act_document(document, proof_pack=pack, regulator_disclosure=disclosure)
            sections = {section["id"]: section for section in document["sections"]}

            self.assertEqual(EU_AI_ACT_DOCUMENT_SCHEMA, document["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(pack["pack_id"], document["source_artifacts"]["proof_pack"]["pack_id"])
            self.assertEqual(
                disclosure["disclosure_id"],
                document["source_artifacts"]["regulator_disclosure"]["disclosure_id"],
            )
            self.assertIn("incident.recorded", {item["entry_type"] for item in sections["post_market_monitoring"]["evidence"]})
            self.assertIn("policy.decision", {item["entry_type"] for item in sections["human_oversight"]["evidence"]})

    def test_eu_ai_act_document_detects_tampered_body(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure = self._sources(Path(tmp_dir))
            document = build_eu_ai_act_document(pack, disclosure)
            tampered = copy.deepcopy(document)
            tampered["sections"][0]["content"]["operator"] = "changed"

            result = verify_eu_ai_act_document(tampered, proof_pack=pack, regulator_disclosure=disclosure)

            self.assertFalse(result.ok)
            self.assertIn("document_id does not match canonical document body", result.errors)


if __name__ == "__main__":
    unittest.main()
