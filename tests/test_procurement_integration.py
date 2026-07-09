import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.procurement_clause import build_procurement_clause_receipt
from trustai.procurement_integration import (
    PROCUREMENT_INTEGRATION_ENTRY_TYPE,
    PROCUREMENT_INTEGRATION_SCHEMA,
    append_procurement_integration_receipt,
    build_procurement_integration_receipt,
    verify_procurement_integration_receipt,
)
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.trust_network import build_trust_network_manifest
from trustai.vendor_identity import build_vendor_identity_receipt


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


class ProcurementIntegrationTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="procurement-integration-test")
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
        vendor = build_vendor_identity_receipt(
            [pack],
            vendor="aitrade",
            legal_name="Aitrade Labs Inc.",
            subject_ref="did:web:aitrade.example",
            domain="aitrade.example",
            issued_at="2026-07-10T00:00:00Z",
            expires_at="2027-07-10T00:00:00Z",
            trust_network_manifest=manifest,
        )
        procurement = build_procurement_clause_receipt(
            manifest,
            contract_ref="MSA-2026-AITRADE-001",
            approver_ref="procurement@example.com",
            effective_at="2026-07-11T00:00:00Z",
            expires_at="2027-07-11T00:00:00Z",
            issued_at="2026-07-10T00:00:00Z",
        )
        return pack, manifest, vendor, procurement

    def test_procurement_integration_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack, manifest, vendor, procurement = self._sources(tmp)
            receipt = build_procurement_integration_receipt(
                procurement,
                vendor,
                trust_network_manifest=manifest,
                proof_packs=[pack],
                procurement_system="servicenow",
                endpoint_base="https://procurement.example",
                credential_ref="env:PROCUREMENT_TOKEN",
                integration_ref="REQ-2026-TRUSTAI-001",
                delivered_at="2026-07-12T00:00:00Z",
            )

            result = verify_procurement_integration_receipt(
                receipt,
                procurement_receipt=procurement,
                vendor_identity_receipt=vendor,
                trust_network_manifest=manifest,
                proof_packs=[pack],
            )
            chain = EvidenceChain.load(tmp / "integration-chain.json", tenant_id="procurement-integration-local")
            entry = append_procurement_integration_receipt(
                chain,
                receipt,
                procurement_receipt=procurement,
                vendor_identity_receipt=vendor,
                trust_network_manifest=manifest,
                proof_packs=[pack],
            )

            self.assertEqual(PROCUREMENT_INTEGRATION_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(PROCUREMENT_INTEGRATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["integration_id"], entry["payload"]["integration_id"])
            self.assertTrue(receipt["request"]["body"]["decision"]["accepted"])

    def test_procurement_integration_detects_request_body_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, manifest, vendor, procurement = self._sources(Path(tmp_dir))
            receipt = build_procurement_integration_receipt(
                procurement,
                vendor,
                trust_network_manifest=manifest,
                proof_packs=[pack],
                delivered_at="2026-07-12T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["request"]["body"]["vendor"]["subject_ref"] = "did:web:attacker.example"

            result = verify_procurement_integration_receipt(
                tampered,
                procurement_receipt=procurement,
                vendor_identity_receipt=vendor,
                trust_network_manifest=manifest,
                proof_packs=[pack],
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("integration_id" in error for error in result.errors))
            self.assertTrue(any("body_hash" in error for error in result.errors))
            self.assertTrue(any("request body does not match source receipts" in error for error in result.errors))

    def test_procurement_integration_requires_matching_manifest_ids(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, manifest, vendor, procurement = self._sources(Path(tmp_dir))
            mismatched = copy.deepcopy(procurement)
            mismatched["requirements"]["trust_network_manifest_id"] = "changed"
            mismatched["receipt_id"] = "changed"

            with self.assertRaisesRegex(ValueError, "invalid procurement clause receipt"):
                build_procurement_integration_receipt(
                    mismatched,
                    vendor,
                    trust_network_manifest=manifest,
                    proof_packs=[pack],
                )


if __name__ == "__main__":
    unittest.main()
