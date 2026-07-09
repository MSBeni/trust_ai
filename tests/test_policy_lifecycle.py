import json
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.lifecycle import (
    DEMOTION_ENTRY_TYPE,
    INCIDENT_ENTRY_TYPE,
    ROLLBACK_ENTRY_TYPE,
    append_demotion,
    append_incident,
    append_rollback,
    load_incident,
)
from trustai.policy import POLICY_DECISION_ENTRY_TYPE, append_policy_decision, evaluate_policy, load_policy_pack
from trustai.policy_export import POLICY_EXPORT_SCHEMA, export_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class PolicyLifecycleTests(unittest.TestCase):
    def _proof_pack(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        append_runtime_attestation(chain, contract, load_action(ACTION))
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        return chain, contract, pack

    def test_policy_allows_fresh_proof_with_required_approval(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, _, pack = self._proof_pack(Path(tmp_dir))
            policy = load_policy_pack(POLICY)
            action = load_action(ACTION)

            entry = append_policy_decision(
                chain,
                policy,
                action,
                proof_pack=pack,
                now="2026-07-04T02:00:00Z",
            )

            self.assertEqual(POLICY_DECISION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual("allowed", entry["payload"]["outcome"])
            self.assertTrue(entry["payload"]["passed"])
            self.assertTrue(chain.verify_all().ok)

    def test_policy_denies_stale_proof_even_when_signature_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, _, pack = self._proof_pack(Path(tmp_dir))
            policy = load_policy_pack(POLICY)
            action = load_action(ACTION)

            decision = evaluate_policy(policy, action, proof_pack=pack, now="2026-08-15T00:00:00Z")

            self.assertEqual("denied", decision["outcome"])
            self.assertFalse(decision["checks"][0]["passed"])

    def test_policy_pack_exports_to_opa_and_cedar_artifacts(self):
        policy = load_policy_pack(POLICY)

        export = export_policy_pack(policy)
        opa = export["targets"]["opa_rego"]["module"]
        cedar = export["targets"]["cedar"]
        opa_only = export_policy_pack(policy, target="opa")

        self.assertEqual(POLICY_EXPORT_SCHEMA, export["schema"])
        self.assertIn("package trustai.runtime", opa)
        self.assertIn("input.action.notional_usd > 5000", opa)
        self.assertIn('missing_approvals["require-trading-ops-approval-for-large-notional"]', opa)
        self.assertIn('not approval_present("trading_ops")', opa)
        self.assertEqual("trustai.cedar-policy-set/0.1", cedar["schema"])
        self.assertTrue(
            any(
                cedar_policy["id"] == "deny-non-shadow-before-production-promotion"
                and cedar_policy["effect"] == "forbid"
                for cedar_policy in cedar["policies"]
            )
        )
        self.assertIn("opa_rego", opa_only["targets"])
        self.assertNotIn("cedar", opa_only["targets"])

    def test_incident_demotion_and_rollback_are_chain_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, contract, _ = self._proof_pack(Path(tmp_dir))
            incident_entry = append_incident(chain, load_incident(INCIDENT))
            demotion_entry = append_demotion(
                chain,
                contract,
                reason="High-severity latency drift incident",
                triggering_entry_id=incident_entry["entry_id"],
            )
            rollback_entry = append_rollback(
                chain,
                contract,
                target_agent_version="sha256:previous-stable-agent-version",
                reason="Restore last known stable risk agent",
                triggering_entry_id=incident_entry["entry_id"],
            )

            self.assertEqual(INCIDENT_ENTRY_TYPE, incident_entry["entry_type"])
            self.assertEqual(DEMOTION_ENTRY_TYPE, demotion_entry["entry_type"])
            self.assertEqual(ROLLBACK_ENTRY_TYPE, rollback_entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)


if __name__ == "__main__":
    unittest.main()

