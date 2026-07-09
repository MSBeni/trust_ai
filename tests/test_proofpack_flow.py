import json
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"


class ProofPackFlowTests(unittest.TestCase):
    def _build_pack(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
        chain.save()
        return compile_proof_pack(
            chain,
            contract,
            eval_entry,
            gate_entry,
            decision,
            out_path=tmp / "pack.json",
            pdf_path=tmp / "pack.pdf",
        )

    def test_end_to_end_pack_verifies_and_writes_pdf(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = self._build_pack(tmp)
            result = verify_proof_pack(pack)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual("passed", result.decision)
            self.assertTrue((tmp / "pack.json").exists())
            self.assertTrue((tmp / "pack.pdf").read_bytes().startswith(b"%PDF"))

    def test_contract_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            pack["contract"]["body"]["metrics"][0]["threshold"] = 0.50

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertIn("pack_id does not match canonical pack body", result.errors)

    def test_chain_payload_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            eval_entry = next(
                entry for entry in pack["chain"]["entries"] if entry["entry_type"] == "eval.completed"
            )
            eval_entry["payload"]["results"]["metrics"]["trade_policy_compliance_rate"] = 0.10

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertTrue(any("payload hash mismatch" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
