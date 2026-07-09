import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.trust_network import build_trust_network_manifest
from trustai.vendor_identity import (
    VENDOR_IDENTITY_ENTRY_TYPE,
    VENDOR_IDENTITY_SCHEMA,
    append_vendor_identity_receipt,
    build_vendor_identity_receipt,
    verify_vendor_identity_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


class VendorIdentityTests(unittest.TestCase):
    def _proof_pack(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="vendor-identity-test")
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
        return compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

    def test_vendor_identity_receipt_verifies_with_manifest_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = self._proof_pack(tmp)
            manifest = build_trust_network_manifest(
                [pack],
                vendor_names=["Aitrade Vendor"],
                buyer="FinServ Buyer",
                required_frameworks=["ISO 42001", "NIST AI RMF"],
                accepted_risk_classes=["trading-prod-write"],
            )
            receipt = build_vendor_identity_receipt(
                [pack],
                vendor="Aitrade Vendor",
                legal_name="Aitrade Labs Inc.",
                subject_ref="did:web:aitrade.example",
                domain="aitrade.example",
                identity_provider="okta",
                identity_id="okta:agent-vendor-aitrade",
                issued_at="2026-07-10T00:00:00Z",
                expires_at="2027-07-10T00:00:00Z",
                trust_network_manifest=manifest,
            )

            result = verify_vendor_identity_receipt(receipt, proof_packs=[pack], trust_network_manifest=manifest)
            chain = EvidenceChain.load(tmp / "identity-chain.json", tenant_id="vendor-identity-local")
            entry = append_vendor_identity_receipt(chain, receipt, proof_packs=[pack], trust_network_manifest=manifest)

            self.assertEqual(VENDOR_IDENTITY_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(1, result.proof_pack_count)
            self.assertTrue(result.accepted_in_network)
            self.assertEqual(VENDOR_IDENTITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])

    def test_vendor_identity_detects_proof_pack_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = self._proof_pack(tmp)
            receipt = build_vendor_identity_receipt(
                [pack],
                vendor="Aitrade Vendor",
                legal_name="Aitrade Labs Inc.",
                subject_ref="did:web:aitrade.example",
                issued_at="2026-07-10T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["proof_packs"][0]["content_hash"] = "changed"

            result = verify_vendor_identity_receipt(tampered, proof_packs=[pack])

            self.assertFalse(result.ok)
            self.assertTrue(any("receipt_id" in error for error in result.errors))
            self.assertTrue(any("proof pack source hash mismatch" in error for error in result.errors))

    def test_vendor_identity_requires_matching_accepted_manifest_submission(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            manifest = build_trust_network_manifest([pack], vendor_names=["Other Vendor"])

            with self.assertRaisesRegex(ValueError, "trust-network manifest does not include accepted vendor submission"):
                build_vendor_identity_receipt(
                    [pack],
                    vendor="Aitrade Vendor",
                    legal_name="Aitrade Labs Inc.",
                    subject_ref="did:web:aitrade.example",
                    trust_network_manifest=manifest,
                )


if __name__ == "__main__":
    unittest.main()
