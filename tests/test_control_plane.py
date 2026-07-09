import json
import tempfile
import unittest
from pathlib import Path

from trustai.control_plane import ControlPlane
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.registry import append_inventory, load_inventory
from trustai.anchor import append_anchor


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"


class ControlPlaneTests(unittest.TestCase):
    def test_indexes_chain_and_proof_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            append_inventory(chain, load_inventory(INVENTORY))
            results = json.loads(RESULTS.read_text(encoding="utf-8"))
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
            append_anchor(chain)
            chain.save()
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

            control = ControlPlane(tmp / "control.sqlite")
            try:
                counts = control.index_chain(chain)
                control.index_proof_pack(pack, tmp / "pack.json")
                summary = control.summary()

                self.assertGreaterEqual(counts["chain_entries"], 5)
                self.assertEqual(1, summary["counts"]["contracts"])
                self.assertEqual(2, summary["counts"]["agents"])
                self.assertEqual(1, summary["counts"]["proof_packs"])
                self.assertEqual(1, summary["counts"]["anchors"])
                self.assertEqual("passed", summary["latest_proof_pack"]["outcome"])
                self.assertEqual(2, len(control.agents()))
                self.assertEqual(1, len(control.recent_proof_packs()))
            finally:
                control.close()


if __name__ == "__main__":
    unittest.main()
