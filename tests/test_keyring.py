import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.keyring import local_dev_keyring, rotate_local_keyring, verify_chain_with_keyring
from trustai.proofpack import compile_proof_pack
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"


class KeyringTests(unittest.TestCase):
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

    def _tampered_keyring(self, provider: str, secret: str = "wrong-secret"):
        keyring = copy.deepcopy(local_dev_keyring(tenant_id="test"))
        key = next(item for item in keyring["keys"] if item["provider"] == provider)
        key["secret"] = secret
        return keyring

    def test_keyring_verifies_chain_and_proof_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack = self._build_chain_and_pack(Path(tmp_dir))
            keyring = local_dev_keyring(tenant_id="test")

            chain_result = verify_chain_with_keyring(chain, keyring)
            pack_result = verify_proof_pack(pack, keyring=keyring)

            self.assertTrue(chain_result.ok, chain_result.errors)
            self.assertTrue(pack_result.ok, pack_result.errors)
            self.assertEqual("passed", pack_result.decision)

    def test_keyring_rejects_wrong_evidence_signing_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, _pack = self._build_chain_and_pack(Path(tmp_dir))

            result = verify_chain_with_keyring(chain, self._tampered_keyring("local-kms"))

            self.assertFalse(result.ok)
            self.assertTrue(any("signature invalid" in error for error in result.errors))

    def test_keyring_rejects_wrong_timestamp_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, _pack = self._build_chain_and_pack(Path(tmp_dir))

            result = verify_chain_with_keyring(chain, self._tampered_keyring("local-tsa"))

            self.assertFalse(result.ok)
            self.assertTrue(any("timestamp token invalid" in error for error in result.errors))
    def test_keyring_rejects_declared_tree_header_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            self._build_chain_and_pack(tmp)
            chain_path = tmp / "chain.json"
            data = json.loads(chain_path.read_text(encoding="utf-8"))
            data["tree"]["root"] = "0" * 64
            chain_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            chain = EvidenceChain.load(chain_path)

            result = verify_chain_with_keyring(chain, local_dev_keyring(tenant_id="test"))

            self.assertFalse(result.ok)
            self.assertIn("declared chain tree root mismatch", result.errors)

    def test_keyring_rejects_wrong_proof_pack_signing_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _chain, pack = self._build_chain_and_pack(Path(tmp_dir))

            result = verify_proof_pack(pack, keyring=self._tampered_keyring("local-dev"))

            self.assertFalse(result.ok)
            self.assertIn("proof pack signature invalid", result.errors)

    def test_rotated_keyring_verifies_historical_and_new_entries(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            register_contract(chain, load_contract(CONTRACT))
            rotated = rotate_local_keyring(
                local_dev_keyring(tenant_id="test"),
                key_id="local-dev-v2",
                secret="trustai-rotated-local-secret",
                rotated_at="2026-07-04T00:00:00Z",
            )

            with patch.dict(os.environ, {"TRUSTAI_KEY_ID": "local-dev-v2"}):
                chain.append("test.rotated", {"ok": True}, key="trustai-rotated-local-secret")

            old_kms_key = next(
                key for key in rotated["keys"] if key["provider"] == "local-kms" and key["key_id"] == "local-dev"
            )
            rotated_result = verify_chain_with_keyring(chain, rotated)
            old_result = verify_chain_with_keyring(chain, local_dev_keyring(tenant_id="test"))

            self.assertEqual("retired", old_kms_key["status"])
            self.assertTrue(rotated_result.ok, rotated_result.errors)
            self.assertFalse(old_result.ok)
            self.assertTrue(any("signature invalid" in error for error in old_result.errors))


if __name__ == "__main__":
    unittest.main()
