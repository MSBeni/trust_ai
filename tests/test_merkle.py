import json
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.merkle import inclusion_proof, merkle_root, verify_inclusion


class MerkleTests(unittest.TestCase):
    def test_inclusion_proofs_verify_for_odd_tree(self):
        ids = [f"{index:064x}" for index in range(5)]
        root = merkle_root(ids)

        for index, entry_id in enumerate(ids):
            proof = inclusion_proof(ids, index)
            self.assertTrue(verify_inclusion(entry_id, proof, root))

    def test_tampered_leaf_fails_inclusion(self):
        ids = [f"{index:064x}" for index in range(4)]
        root = merkle_root(ids)
        proof = inclusion_proof(ids, 2)

        self.assertFalse(verify_inclusion("f" * 64, proof, root))


class EvidenceChainTreeHeaderTests(unittest.TestCase):
    def _saved_chain(self, tmp_dir: str) -> Path:
        path = Path(tmp_dir) / "chain.json"
        chain = EvidenceChain.load(path, tenant_id="tree-header-test")
        chain.append("contract.registered", {"contract_id": "vc-1"})
        chain.append("gate.decision", {"contract_id": "vc-1", "decision": "pass"})
        chain.save()
        return path

    def test_saved_chain_verifies_declared_tree_header(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = self._saved_chain(tmp_dir)

            chain = EvidenceChain.load(path, tenant_id="ignored")
            result = chain.verify_all()

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(chain.tree(), chain.declared_tree)

    def test_declared_tree_root_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = self._saved_chain(tmp_dir)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["tree"]["root"] = "0" * 64
            path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

            result = EvidenceChain.load(path).verify_all()

            self.assertFalse(result.ok)
            self.assertIn("declared chain tree root mismatch", result.errors)

    def test_declared_tree_size_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = self._saved_chain(tmp_dir)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["tree"]["size"] += 1
            path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

            result = EvidenceChain.load(path).verify_all()

            self.assertFalse(result.ok)
            self.assertIn("declared chain tree size mismatch", result.errors)

    def test_missing_declared_tree_is_rejected_for_loaded_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = self._saved_chain(tmp_dir)
            data = json.loads(path.read_text(encoding="utf-8"))
            del data["tree"]
            path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

            result = EvidenceChain.load(path).verify_all()

            self.assertFalse(result.ok)
            self.assertIn("declared chain tree missing", result.errors)

    def test_append_after_load_recomputes_tree_without_stale_declared_header(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "chain.json"
            chain = EvidenceChain.load(path, tenant_id="tree-header-test")
            chain.append("contract.registered", {"contract_id": "vc-1"})
            chain.save()

            chain = EvidenceChain.load(path)
            chain.append("gate.decision", {"contract_id": "vc-1", "decision": "pass"})
            result = chain.verify_all()
            self.assertTrue(result.ok, result.errors)

            chain.save()
            reloaded = EvidenceChain.load(path)
            self.assertTrue(reloaded.verify_all().ok)
            self.assertEqual(2, reloaded.tree()["size"])
            self.assertEqual(reloaded.tree(), reloaded.declared_tree)


if __name__ == "__main__":
    unittest.main()
