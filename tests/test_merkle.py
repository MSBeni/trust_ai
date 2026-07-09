import unittest

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


if __name__ == "__main__":
    unittest.main()
