import copy
import json
import tempfile
import unittest
from pathlib import Path

from trustai.approvals import APPROVAL_ENTRY_TYPE, append_approval, approval_entries_for_contract, load_approval
from trustai.chain import EvidenceChain
from trustai.contracts import contract_hash, load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
MODEL_RISK = ROOT / "examples" / "aitrade" / "approval-model-risk.json"
TRADING_OPS = ROOT / "examples" / "aitrade" / "approval-trading-ops.json"


class ApprovalEvidenceTests(unittest.TestCase):
    def _results_without_approvals(self) -> dict:
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        results.pop("approvals", None)
        return results

    def test_chain_backed_approvals_can_satisfy_gate_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            model_risk_entry = append_approval(chain, contract, load_approval(MODEL_RISK))
            trading_ops_entry = append_approval(chain, contract, load_approval(TRADING_OPS))
            approval_entries = approval_entries_for_contract(chain.entries, contract_hash(contract))

            eval_entry, gate_entry, decision = append_eval_and_gate(
                chain,
                contract,
                self._results_without_approvals(),
                approval_entries=approval_entries,
            )
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision)
            result = verify_proof_pack(pack)

            self.assertTrue(decision["passed"], decision["approvals"]["errors"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(APPROVAL_ENTRY_TYPE, model_risk_entry["entry_type"])
            self.assertEqual(APPROVAL_ENTRY_TYPE, trading_ops_entry["entry_type"])
            entry_types = [entry["entry_type"] for entry in pack["chain"]["entries"]]
            self.assertEqual(2, entry_types.count(APPROVAL_ENTRY_TYPE))
            actual_ids = {item.get("approval_entry_id") for item in decision["approvals"]["actual"]}
            self.assertIn(model_risk_entry["entry_id"], actual_ids)
            self.assertIn(trading_ops_entry["entry_id"], actual_ids)

    def test_verifier_rejects_pack_when_chain_approval_evidence_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            append_approval(chain, contract, load_approval(MODEL_RISK))
            append_approval(chain, contract, load_approval(TRADING_OPS))
            approval_entries = approval_entries_for_contract(chain.entries, contract_hash(contract))
            eval_entry, gate_entry, decision = append_eval_and_gate(
                chain,
                contract,
                self._results_without_approvals(),
                approval_entries=approval_entries,
            )
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision)
            tampered = copy.deepcopy(pack)
            tampered["chain"]["entries"] = [
                entry for entry in tampered["chain"]["entries"] if entry["entry_type"] != APPROVAL_ENTRY_TYPE
            ]

            result = verify_proof_pack(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("gate decision mismatch for approvals" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
