import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.lifecycle import append_demotion, append_incident, append_rollback, load_incident
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.regulator import (
    REGULATOR_DISCLOSURE_SCHEMA,
    build_regulator_disclosure,
    verify_regulator_disclosure,
)
from trustai.regulator_view import render_regulator_html
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class RegulatorDisclosureTests(unittest.TestCase):
    def _chain_and_pack(self, tmp: Path):
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
        append_demotion(
            chain,
            contract,
            reason="High-severity latency drift incident",
            triggering_entry_id=incident_entry["entry_id"],
        )
        append_rollback(
            chain,
            contract,
            target_agent_version="sha256:previous-stable-agent-version",
            reason="Restore last known stable risk agent",
            triggering_entry_id=incident_entry["entry_id"],
        )
        return chain, pack

    def test_regulator_disclosure_verifies_selected_entries_after_pack_issue(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack = self._chain_and_pack(Path(tmp_dir))
            disclosure = build_regulator_disclosure(chain, pack, audience="supervisor@example.test")
            result = verify_regulator_disclosure(disclosure)
            html = render_regulator_html(disclosure, result)
            entry_types = {entry["entry_type"] for entry in disclosure["chain"]["entries"]}

            self.assertEqual(REGULATOR_DISCLOSURE_SCHEMA, disclosure["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertIn("TrustAI Regulator Disclosure View", html)
            self.assertIn("VERIFIED", html)
            self.assertIn(disclosure["disclosure_id"], html)
            self.assertIn("policy.decision", entry_types)
            self.assertIn("incident.recorded", entry_types)
            self.assertIn("promotion_gate.rolled_back", entry_types)
            self.assertEqual(chain.tree(), disclosure["chain"]["tree"])
            self.assertGreater(disclosure["chain"]["tree"]["size"], pack["chain"]["tree"]["size"])

    def test_regulator_disclosure_rejects_tree_size_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack = self._chain_and_pack(Path(tmp_dir))
            disclosure = build_regulator_disclosure(chain, pack)
            tampered = copy.deepcopy(disclosure)
            tampered["chain"]["tree"]["size"] = 1
            for proof in tampered["chain"]["inclusion_proofs"].values():
                proof["tree_size"] = 1

            result = verify_regulator_disclosure(tampered)

            self.assertFalse(result.ok)
            self.assertIn("disclosure chain tree size is smaller than packed entry count", result.errors)
            self.assertIn("disclosure chain tree size is smaller than packed entry indexes", result.errors)
    def test_regulator_disclosure_detects_tampered_entry_payload(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack = self._chain_and_pack(Path(tmp_dir))
            disclosure = build_regulator_disclosure(chain, pack)
            tampered = copy.deepcopy(disclosure)
            tampered["chain"]["entries"][0]["payload"]["contract_id"] = "changed-after-disclosure"

            result = verify_regulator_disclosure(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("payload hash mismatch" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
