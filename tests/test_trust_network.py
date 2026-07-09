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
from trustai.trust_network import (
    TRUST_NETWORK_SCHEMA,
    build_trust_network_manifest,
    render_trust_network_markdown,
    verify_trust_network_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


class TrustNetworkTests(unittest.TestCase):
    def _proof_pack(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="vendor-test")
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

    def test_trust_network_manifest_deep_verifies_vendor_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            manifest = build_trust_network_manifest(
                [pack],
                vendor_names=["Aitrade Vendor"],
                buyer="FinServ Buyer",
                required_frameworks=["ISO 42001", "NIST AI RMF"],
                accepted_risk_classes=["trading-prod-write"],
            )

            result = verify_trust_network_manifest(manifest, proof_packs=[pack])
            markdown = render_trust_network_markdown(manifest)

            self.assertEqual(TRUST_NETWORK_SCHEMA, manifest["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(1, result.accepted_count)
            self.assertEqual(1, result.submission_count)
            self.assertTrue(manifest["submissions"][0]["accepted"])
            self.assertIn("TrustAI Vendor Trust Network Manifest", markdown)
            self.assertIn("Aitrade Vendor", markdown)

    def test_trust_network_manifest_detects_proof_pack_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            manifest = build_trust_network_manifest([pack], vendor_names=["Aitrade Vendor"])
            tampered = copy.deepcopy(manifest)
            tampered["submissions"][0]["proof_pack"]["content_hash"] = "changed"

            result = verify_trust_network_manifest(tampered, proof_packs=[pack])

            self.assertFalse(result.ok)
            self.assertTrue(any("manifest_id" in error for error in result.errors))
            self.assertTrue(any("proof pack source hash mismatch" in error for error in result.errors))

    def test_trust_network_manifest_rejects_missing_required_framework(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            manifest = build_trust_network_manifest(
                [pack],
                vendor_names=["Aitrade Vendor"],
                required_frameworks=["Nonexistent Buyer Framework"],
            )

            result = verify_trust_network_manifest(manifest, proof_packs=[pack])

            self.assertFalse(result.ok)
            self.assertFalse(manifest["submissions"][0]["accepted"])
            self.assertTrue(any("does not satisfy procurement clause" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
