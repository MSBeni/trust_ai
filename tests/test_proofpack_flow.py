import json
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.crypto import sign_value
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.registry import (
    AGENT_INVENTORY_ENTRY_TYPE,
    DELEGATION_GRAPH_ENTRY_TYPE,
    append_delegation,
    append_delegation_graph,
    append_inventory,
    build_delegation_graph,
    load_delegation,
    load_inventory,
)
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"
DELEGATION = ROOT / "examples" / "aitrade" / "delegation.json"


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

    def _build_pack_with_delegation_graph(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        append_inventory(chain, load_inventory(INVENTORY))
        delegation = load_delegation(DELEGATION)
        append_delegation(chain, delegation)
        graph = build_delegation_graph(
            chain,
            contract_hash=delegation["contract_hash"],
            generated_at="2026-07-03T12:04:00Z",
        )
        append_delegation_graph(chain, graph, source_chain=chain)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
        chain.save()
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        return pack, graph

    def _resign_pack(self, pack: dict) -> None:
        body = without_keys(pack, "pack_id", "signatures")
        pack_id = content_hash(body)
        pack["pack_id"] = pack_id
        pack["signatures"] = [sign_value({"pack_id": pack_id, "pack": body})]

    def test_end_to_end_pack_verifies_and_writes_pdf(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = self._build_pack(tmp)
            result = verify_proof_pack(pack)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual("passed", result.decision)
            self.assertTrue((tmp / "pack.json").exists())
            self.assertTrue((tmp / "pack.pdf").read_bytes().startswith(b"%PDF"))

    def test_compile_rejects_eval_entry_not_in_supplied_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            contract = load_contract(CONTRACT)
            results = json.loads(RESULTS.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            register_contract(chain, contract)
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)

            other_chain = EvidenceChain.load(tmp / "other-chain.json", tenant_id="other")
            register_contract(other_chain, contract)
            other_eval_entry, _other_gate_entry, _other_decision = append_eval_and_gate(other_chain, contract, results)
            out_path = tmp / "bad-pack.json"

            with self.assertRaisesRegex(ValueError, "eval_entry is not part of the supplied evidence chain"):
                compile_proof_pack(chain, contract, other_eval_entry, gate_entry, decision, out_path=out_path)
            self.assertFalse(out_path.exists())

    def test_compile_rejects_entries_for_different_contract(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            contract = load_contract(CONTRACT)
            other_contract = json.loads(json.dumps(contract))
            other_contract["id"] = f"{contract['id']}-other"
            results = json.loads(RESULTS.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            register_contract(chain, contract)
            append_eval_and_gate(chain, contract, results)
            register_contract(chain, other_contract)
            other_eval_entry, other_gate_entry, other_decision = append_eval_and_gate(chain, other_contract, results)

            with self.assertRaisesRegex(ValueError, "eval_entry contract_hash does not match contract"):
                compile_proof_pack(chain, contract, other_eval_entry, other_gate_entry, other_decision)

    def test_compile_rejects_decision_not_bound_to_gate_entry(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            results = json.loads(RESULTS.read_text(encoding="utf-8"))
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
            bad_decision = {**decision, "gate_entry_id": "not-the-gate-entry"}
            out_path = tmp / "bad-pack.json"

            with self.assertRaisesRegex(ValueError, "decision gate_entry_id does not match gate entry"):
                compile_proof_pack(chain, contract, eval_entry, gate_entry, bad_decision, out_path=out_path)
            self.assertFalse(out_path.exists())

    def test_proof_pack_includes_and_verifies_delegation_graph(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, graph = self._build_pack_with_delegation_graph(Path(tmp_dir))
            result = verify_proof_pack(pack)

            self.assertTrue(result.ok, result.errors)
            entry_types = [entry["entry_type"] for entry in pack["chain"]["entries"]]
            self.assertIn(DELEGATION_GRAPH_ENTRY_TYPE, entry_types)
            self.assertGreaterEqual(entry_types.count(AGENT_INVENTORY_ENTRY_TYPE), 2)
            graph_entry = next(entry for entry in pack["chain"]["entries"] if entry["entry_type"] == DELEGATION_GRAPH_ENTRY_TYPE)
            self.assertEqual(graph["delegation_graph_id"], graph_entry["payload"]["delegation_graph_id"])
            self.assertEqual(graph["delegation_graph_id"], graph_entry["payload"]["delegation_graph"]["delegation_graph_id"])
            self.assertEqual(1, graph_entry["payload"]["summary"]["edge_count"])

    def test_proof_pack_verifier_replays_embedded_delegation_graph(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, _graph = self._build_pack_with_delegation_graph(Path(tmp_dir))
            graph_entry = next(entry for entry in pack["chain"]["entries"] if entry["entry_type"] == DELEGATION_GRAPH_ENTRY_TYPE)
            graph_entry["payload"]["delegation_graph"]["edges"][0]["delegation"]["reason"] = "changed after graph signing"

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertTrue(any("delegation graph entry" in error for error in result.errors))

    def test_contract_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            pack["contract"]["body"]["metrics"][0]["threshold"] = 0.50

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertIn("pack_id does not match canonical pack body", result.errors)

    def test_subject_tamper_is_rejected_after_resign(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            pack["subject"]["agent"] = {
                **pack["subject"]["agent"],
                "version": "sha256:unregistered-agent-version",
            }
            pack["subject"]["environment"] = {
                **pack["subject"]["environment"],
                "model": "gpt-5-pro-unregistered",
            }
            self._resign_pack(pack)

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertNotIn("pack_id does not match canonical pack body", result.errors)
            self.assertNotIn("proof pack signature invalid", result.errors)
            self.assertIn("packed subject agent mismatch", result.errors)
            self.assertIn("packed subject environment mismatch", result.errors)

    def test_issued_at_is_required_after_resign(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            del pack["issued_at"]
            self._resign_pack(pack)

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertNotIn("pack_id does not match canonical pack body", result.errors)
            self.assertNotIn("proof pack signature invalid", result.errors)
            self.assertIn("proof pack issued_at missing", result.errors)

    def test_malformed_issued_at_is_rejected_after_resign(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            pack["issued_at"] = "not-a-rfc3339-timestamp"
            self._resign_pack(pack)

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertNotIn("pack_id does not match canonical pack body", result.errors)
            self.assertNotIn("proof pack signature invalid", result.errors)
            self.assertIn("proof pack issued_at invalid", result.errors)

    def test_framework_mapping_tamper_is_rejected_after_resign(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            pack["framework_mappings"][0]["controls"].append("Unregistered premium discount control")
            self._resign_pack(pack)

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertNotIn("pack_id does not match canonical pack body", result.errors)
            self.assertNotIn("proof pack signature invalid", result.errors)
            self.assertIn("framework mappings do not match gate decision", result.errors)

    def test_chain_tree_size_tamper_is_rejected_after_resign(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            pack["chain"]["tree"]["size"] = 1
            for proof in pack["chain"]["inclusion_proofs"].values():
                proof["tree_size"] = 1
            self._resign_pack(pack)

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertNotIn("pack_id does not match canonical pack body", result.errors)
            self.assertNotIn("proof pack signature invalid", result.errors)
            self.assertIn("chain tree size is smaller than packed entry count", result.errors)
            self.assertIn("chain tree size is smaller than packed entry indexes", result.errors)

    def test_complete_chain_tree_root_tamper_is_rejected_after_resign(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._build_pack(Path(tmp_dir))
            pack["chain"]["tree"]["root"] = "0" * 64
            for proof in pack["chain"]["inclusion_proofs"].values():
                proof["tree_root"] = "0" * 64
            self._resign_pack(pack)

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertNotIn("pack_id does not match canonical pack body", result.errors)
            self.assertNotIn("proof pack signature invalid", result.errors)
            self.assertIn("chain tree root does not match packed entries", result.errors)
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
