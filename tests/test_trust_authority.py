import copy
import json
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.keyring import local_dev_keyring
from trustai.proofpack import compile_proof_pack
from trustai.trust_authority import (
    TRUST_AUTHORITY_ENTRY_TYPE,
    TRUST_AUTHORITY_RECEIPT_SCHEMA,
    append_trust_authority_receipt,
    build_trust_authority_receipt,
    verify_trust_authority_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"


class TrustAuthorityReceiptTests(unittest.TestCase):
    def _build_chain_and_pack(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
        chain.save()
        pack = compile_proof_pack(
            chain,
            contract,
            eval_entry,
            gate_entry,
            decision,
            out_path=tmp / "pack.json",
        )
        return chain, pack

    def test_trust_authority_receipt_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack = self._build_chain_and_pack(Path(tmp_dir))
            keyring = local_dev_keyring(tenant_id="test")
            receipt = build_trust_authority_receipt(chain, keyring, proof_pack=pack)

            result = verify_trust_authority_receipt(receipt, chain=chain, keyring=keyring, proof_pack=pack)
            receipt_json = json.dumps(receipt, sort_keys=True)
            authority_chain = EvidenceChain.load(Path(tmp_dir) / "authority-chain.json", tenant_id="authority-test")
            entry = append_trust_authority_receipt(
                authority_chain,
                receipt,
                source_chain=chain,
                keyring=keyring,
                proof_pack=pack,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(TRUST_AUTHORITY_RECEIPT_SCHEMA, receipt["schema"])
            self.assertEqual("local-reference", receipt["authority"]["mode"])
            self.assertIn("local-kms:local-dev:HMAC-SHA256", receipt["providers"]["chain_entry_signatures"])
            self.assertIn("local-tsa", receipt["providers"]["timestamp_tokens"])
            self.assertNotIn("trustai-local-dev-key-change-me", receipt_json)
            self.assertEqual(TRUST_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertTrue(authority_chain.verify_all().ok)

    def test_trust_authority_receipt_detects_keyring_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack = self._build_chain_and_pack(Path(tmp_dir))
            keyring = local_dev_keyring(tenant_id="test")
            receipt = build_trust_authority_receipt(chain, keyring, proof_pack=pack)
            tampered_keyring = copy.deepcopy(keyring)
            next(key for key in tampered_keyring["keys"] if key["provider"] == "local-tsa")["secret"] = "wrong"

            result = verify_trust_authority_receipt(receipt, chain=chain, keyring=tampered_keyring, proof_pack=pack)

            self.assertFalse(result.ok)
            self.assertTrue(any("keyring content_hash" in error for error in result.errors))
            self.assertTrue(any("timestamp token invalid" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
