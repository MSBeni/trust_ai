import copy
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.crypto import sign_value
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.policy_engine import (
    POLICY_ENGINE_ENTRY_TYPE,
    POLICY_ENGINE_RECEIPT_SCHEMA,
    append_policy_engine_receipt,
    build_policy_engine_receipt,
    verify_policy_engine_receipt,
)
from trustai.policy_export import export_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


class PolicyEngineReceiptTests(unittest.TestCase):
    def _fixtures(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="policy-engine-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        action = load_action(ACTION)
        append_runtime_attestation(chain, contract, action)
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        policy = load_policy_pack(POLICY)
        policy_decision = append_policy_decision(
            chain,
            policy,
            action,
            proof_pack=pack,
            now="2026-07-04T02:00:00Z",
        )
        policy_export = export_policy_pack(policy)
        return chain, policy, action, pack, policy_decision, policy_export

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "receipt_id", "signatures")
        receipt_id = content_hash(body)
        receipt["receipt_id"] = receipt_id
        receipt["signatures"] = [sign_value({"receipt_id": receipt_id, "receipt": body})]

    def test_policy_engine_receipt_verifies_and_appends_to_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, policy, action, pack, policy_decision, policy_export = self._fixtures(Path(tmp_dir))

            receipt = build_policy_engine_receipt(
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                engine="opa",
            )
            result = verify_policy_engine_receipt(
                receipt,
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
            )
            entry = append_policy_engine_receipt(
                chain,
                receipt,
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_ENGINE_RECEIPT_SCHEMA, receipt["schema"])
            self.assertEqual("opa", receipt["engine"]["name"])
            self.assertEqual("allowed", receipt["decision"]["outcome"])
            self.assertEqual(POLICY_ENGINE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_policy_engine_receipt_detects_action_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, policy, action, pack, policy_decision, policy_export = self._fixtures(Path(tmp_dir))
            receipt = build_policy_engine_receipt(
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                engine="cedar",
            )
            tampered_action = {**action, "notional_usd": action["notional_usd"] + 1}

            result = verify_policy_engine_receipt(
                receipt,
                policy,
                tampered_action,
                pack,
                policy_decision,
                policy_export=policy_export,
            )

            self.assertFalse(result.ok)
            self.assertIn("receipt action hash does not match action", result.errors)

    def test_policy_engine_receipt_replays_active_gate_outcome(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, policy, action, pack, policy_decision, policy_export = self._fixtures(Path(tmp_dir))
            receipt = build_policy_engine_receipt(
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                engine="opa",
            )
            failed_pack = copy.deepcopy(pack)
            failed_pack["gate_decision"]["outcome"] = "failed"
            receipt["proof_pack"]["content_hash"] = content_hash(failed_pack)
            receipt["proof_pack"]["gate_outcome"] = "failed"
            self._resign_receipt(receipt)

            result = verify_policy_engine_receipt(
                receipt,
                policy,
                action,
                failed_pack,
                policy_decision,
                policy_export=policy_export,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("receipt_id does not match canonical receipt body", result.errors)
            self.assertNotIn("policy engine receipt signature verification failed", result.errors)
            self.assertIn("policy decision does not replay from policy, action, proof pack, and proof decay", result.errors)

    def test_policy_engine_receipt_replays_proof_decay(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, policy, action, pack, policy_decision, policy_export = self._fixtures(Path(tmp_dir))
            receipt = build_policy_engine_receipt(
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                engine="opa",
            )
            stale_pack = copy.deepcopy(pack)
            stale_pack["gate_decision"]["evaluated_at"] = "2026-01-01T00:00:00Z"
            stale_entry_types = {"runtime.attested", "soak_report.completed", "shadow_replay.completed"}
            for entry in stale_pack["chain"]["entries"]:
                if entry.get("entry_type") in stale_entry_types:
                    entry["timestamp"] = "2026-01-01T00:00:00Z"
            receipt["proof_pack"]["content_hash"] = content_hash(stale_pack)
            self._resign_receipt(receipt)

            result = verify_policy_engine_receipt(
                receipt,
                policy,
                action,
                stale_pack,
                policy_decision,
                policy_export=policy_export,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("receipt_id does not match canonical receipt body", result.errors)
            self.assertNotIn("policy engine receipt signature verification failed", result.errors)
            self.assertIn("policy decision does not replay from policy, action, proof pack, and proof decay", result.errors)


if __name__ == "__main__":
    unittest.main()
