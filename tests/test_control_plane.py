import json
import tempfile
import unittest
from pathlib import Path

from trustai.control_plane import ControlPlane
from trustai.chain import EvidenceChain
from trustai.cicd import append_promotion_status_receipt, build_promotion_check_payload, build_promotion_status_receipt
from trustai.delivery import build_provider_delivery
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.ingest import append_events, load_events
from trustai.lifecycle import append_incident, load_incident
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.policy_engine import append_policy_engine_receipt, build_policy_engine_receipt
from trustai.policy_export import export_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.registry import append_inventory, load_inventory
from trustai.anchor import append_anchor
from trustai.runtime import append_runtime_attestation, load_action
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"
EVENTS = ROOT / "examples" / "aitrade" / "otel-events.json"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class ControlPlaneTests(unittest.TestCase):
    def test_indexes_chain_and_proof_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            append_inventory(chain, load_inventory(INVENTORY))
            append_events(chain, load_events(EVENTS))
            results = json.loads(RESULTS.read_text(encoding="utf-8"))
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
            append_anchor(chain)
            chain.save()
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
            verification = verify_proof_pack(pack)
            payload = build_promotion_check_payload(
                pack,
                verification,
                provider="github",
                commit_sha="0123456789abcdef0123456789abcdef01234567",
                repository="volelabs/trust_ai",
                target_url="https://example.test/proof-pack",
            )
            delivery = build_provider_delivery(
                payload,
                endpoint_base="https://api.github.com",
                credential_ref="env:GITHUB_TOKEN",
                mode="dry-run",
                delivered_at="2026-07-04T00:00:00Z",
            )
            receipt = build_promotion_status_receipt(
                pack,
                verification,
                payload,
                delivery=delivery,
                attested_at="2026-07-04T00:01:00Z",
            )
            append_promotion_status_receipt(
                chain,
                receipt,
                proof_pack=pack,
                verification=verification,
                payload=payload,
                delivery=delivery,
            )
            action = load_action(ACTION)
            append_runtime_attestation(chain, contract, action)
            policy = {**load_policy_pack(POLICY), "proof_decay": {}}
            policy_decision = append_policy_decision(
                chain,
                policy,
                action,
                proof_pack=pack,
                now="2026-07-04T02:00:00Z",
            )
            policy_export = export_policy_pack(policy)
            engine_receipt = build_policy_engine_receipt(
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                engine="opa",
            )
            append_policy_engine_receipt(
                chain,
                engine_receipt,
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
            )
            append_incident(chain, load_incident(INCIDENT))
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                counts = control.index_chain(chain)
                control.index_proof_pack(pack, tmp / "pack.json")
                summary = control.summary()

                self.assertGreaterEqual(counts["chain_entries"], 5)
                self.assertEqual(1, summary["counts"]["contracts"])
                self.assertEqual(1, counts["contracts"])
                self.assertEqual(2, summary["counts"]["agents"])
                self.assertEqual(1, summary["counts"]["eval_runs"])
                self.assertEqual(1, summary["counts"]["gate_decisions"])
                self.assertEqual(1, counts["eval_runs"])
                self.assertEqual(1, counts["gate_decisions"])
                self.assertEqual(1, summary["counts"]["proof_packs"])
                self.assertEqual(1, summary["counts"]["anchors"])
                self.assertEqual(2, summary["counts"]["ingest_events"])
                self.assertEqual(2, counts["ingest_events"])
                self.assertEqual(1, summary["counts"]["promotion_statuses"])
                self.assertEqual(1, counts["promotion_statuses"])
                self.assertEqual(1, summary["counts"]["runtime_attestations"])
                self.assertEqual(1, summary["counts"]["policy_decisions"])
                self.assertEqual(1, summary["counts"]["policy_engine_receipts"])
                self.assertEqual(1, summary["counts"]["incidents"])
                self.assertEqual(1, counts["runtime_attestations"])
                self.assertEqual(1, counts["policy_decisions"])
                self.assertEqual(1, counts["policy_engine_receipts"])
                self.assertEqual(1, counts["incidents"])
                self.assertEqual("passed", summary["latest_proof_pack"]["outcome"])
                self.assertEqual("aitrade-btcusdt-canary", summary["latest_eval_run"]["contract_id"])
                self.assertEqual("passed", summary["latest_gate_decision"]["outcome"])
                self.assertTrue(summary["latest_gate_decision"]["passed"])
                self.assertTrue(summary["latest_gate_decision"]["holdout_passed"])
                self.assertTrue(summary["latest_gate_decision"]["approvals_passed"])
                self.assertEqual("gen_ai.tool.call", summary["latest_ingest_event"]["event_name"])
                self.assertEqual("github", summary["latest_promotion_status"]["provider"])
                self.assertTrue(summary["latest_promotion_status"]["passed"])
                self.assertEqual("shadow-order-20260703-001", summary["latest_runtime_attestation"]["action_id"])
                self.assertTrue(summary["latest_runtime_attestation"]["passed"])
                self.assertEqual("trading-runtime-policy-v0", summary["latest_policy_decision"]["policy_pack_id"])
                self.assertTrue(summary["latest_policy_decision"]["passed"])
                self.assertEqual("opa", summary["latest_policy_engine_receipt"]["engine_name"])
                self.assertTrue(summary["latest_policy_engine_receipt"]["decision_passed"])
                self.assertEqual("high", summary["latest_incident"]["severity"])
                contracts = control.contracts()
                self.assertEqual(1, len(contracts))
                self.assertEqual("aitrade-btcusdt-canary", contracts[0]["contract_id"])
                self.assertEqual(2, len(control.agents()))
                eval_runs = control.recent_eval_runs()
                self.assertEqual(1, len(eval_runs))
                self.assertEqual("aitrade-btcusdt-canary", eval_runs[0]["contract_id"])
                gate_decisions = control.recent_gate_decisions()
                self.assertEqual(1, len(gate_decisions))
                self.assertEqual("passed", gate_decisions[0]["outcome"])
                self.assertTrue(gate_decisions[0]["passed"])
                self.assertEqual(1, len(control.recent_proof_packs()))
                ingest_events = control.recent_ingest_events()
                self.assertEqual(2, len(ingest_events))
                self.assertEqual("gen_ai.tool.call", ingest_events[0]["event_name"])
                self.assertEqual("place_shadow_order", ingest_events[0]["attributes"]["tool.name"])
                statuses = control.recent_promotion_statuses()
                self.assertEqual(1, len(statuses))
                self.assertEqual("volelabs/trust_ai", statuses[0]["target_ref"]["repository"])
                self.assertTrue(statuses[0]["provider_status_success"])
                runtime_evidence = control.runtime_evidence()
                self.assertEqual("shadow-order-20260703-001", runtime_evidence["runtime_attestations"][0]["action_id"])
                self.assertEqual("trading-runtime-policy-v0", runtime_evidence["policy_decisions"][0]["policy_pack_id"])
                self.assertEqual("opa", runtime_evidence["policy_engine_receipts"][0]["engine_name"])
                self.assertEqual("incident-20260704-latency-drift", runtime_evidence["incidents"][0]["incident_id"])
            finally:
                control.close()


if __name__ == "__main__":
    unittest.main()
