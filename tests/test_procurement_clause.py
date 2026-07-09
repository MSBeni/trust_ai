import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.procurement_clause import (
    PROCUREMENT_CLAUSE_ENTRY_TYPE,
    PROCUREMENT_CLAUSE_SCHEMA,
    append_procurement_clause_receipt,
    build_procurement_clause_receipt,
    verify_procurement_clause_receipt,
)
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.trust_network import build_trust_network_manifest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


class ProcurementClauseTests(unittest.TestCase):
    def _pack_and_manifest(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="procurement-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        append_runtime_attestation(chain, contract, load_action(ACTION))
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        manifest = build_trust_network_manifest(
            [pack],
            vendor_names=["aitrade"],
            buyer="finserv-buyer",
            required_frameworks=["ISO 42001", "NIST AI RMF"],
            accepted_risk_classes=["trading-prod-write"],
        )
        return chain, pack, manifest

    def test_procurement_clause_receipt_verifies_manifest_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack, manifest = self._pack_and_manifest(Path(tmp_dir))
            receipt = build_procurement_clause_receipt(
                manifest,
                contract_ref="MSA-2026-AITRADE-001",
                approver_ref="procurement@example.com",
                effective_at="2026-07-11T00:00:00Z",
                expires_at="2027-07-11T00:00:00Z",
                issued_at="2026-07-10T00:00:00Z",
            )

            result = verify_procurement_clause_receipt(receipt, trust_network_manifest=manifest, proof_packs=[pack])
            entry = append_procurement_clause_receipt(chain, receipt)

            self.assertEqual(PROCUREMENT_CLAUSE_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("finserv-buyer", receipt["buyer"]["name"])
            self.assertEqual(1, receipt["requirements"]["accepted_vendor_count"])
            self.assertEqual(PROCUREMENT_CLAUSE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_procurement_clause_receipt_detects_tampered_clause_hash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, manifest = self._pack_and_manifest(Path(tmp_dir))
            receipt = build_procurement_clause_receipt(
                manifest,
                contract_ref="MSA-2026-AITRADE-001",
                approver_ref="procurement@example.com",
                effective_at="2026-07-11T00:00:00Z",
                issued_at="2026-07-10T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["contract"]["clause_hash"] = "changed"

            result = verify_procurement_clause_receipt(tampered, trust_network_manifest=manifest, proof_packs=[pack])

            self.assertFalse(result.ok)
            self.assertIn("receipt_id does not match canonical procurement clause body", result.errors)
            self.assertIn("procurement clause hash does not match source manifest clause", result.errors)

    def test_procurement_clause_receipt_rejects_unsatisfied_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, manifest = self._pack_and_manifest(Path(tmp_dir))
            bad_manifest = build_trust_network_manifest(
                [pack],
                vendor_names=["aitrade"],
                buyer="finserv-buyer",
                required_frameworks=["Nonexistent Buyer Framework"],
            )
            receipt = build_procurement_clause_receipt(
                bad_manifest,
                contract_ref="MSA-2026-AITRADE-001",
                approver_ref="procurement@example.com",
                effective_at="2026-07-11T00:00:00Z",
                issued_at="2026-07-10T00:00:00Z",
            )

            result = verify_procurement_clause_receipt(receipt, trust_network_manifest=bad_manifest, proof_packs=[pack])

            self.assertFalse(result.ok)
            self.assertIn("procurement clause receipt requires at least one accepted vendor", result.errors)
            self.assertTrue(any("source trust-network manifest invalid" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
