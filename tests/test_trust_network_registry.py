import copy
import json
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.identity_provider_attestation import build_identity_provider_attestation
from trustai.procurement_clause import build_procurement_clause_receipt
from trustai.procurement_integration import build_procurement_integration_receipt
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.trust_network import build_trust_network_manifest
from trustai.trust_network_registry import (
    TRUST_NETWORK_REGISTRY_ENTRY_TYPE,
    TRUST_NETWORK_REGISTRY_SCHEMA,
    append_trust_network_registry_receipt,
    build_trust_network_registry_receipt,
    verify_trust_network_registry_receipt,
)
from trustai.vendor_identity import build_vendor_identity_receipt


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
IDENTITY = ROOT / "examples" / "aitrade" / "identity-inventory.json"


class TrustNetworkRegistryTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="trust-network-registry-test")
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
            identity_provider="okta",
            identity_id="okta-agent-aitrade-risk",
            issued_at="2026-07-10T00:00:00Z",
            expires_at="2027-07-10T00:00:00Z",
            trust_network_manifest=manifest,
        )
        identity_payload = json.loads(IDENTITY.read_text(encoding="utf-8"))
        identity_attestation = build_identity_provider_attestation(
            identity_payload,
            vendor_identity_receipt=vendor,
            proof_packs=[pack],
            trust_network_manifest=manifest,
            provider="okta",
            identity_id="okta-agent-aitrade-risk",
            issuer="trustai-local",
            tenant_ref="okta:example-org",
            issued_at="2026-07-10T01:00:00Z",
            expires_at="2027-07-10T01:00:00Z",
        )
        procurement = build_procurement_clause_receipt(
            manifest,
            contract_ref="MSA-2026-AITRADE-001",
            approver_ref="procurement@example.com",
            effective_at="2026-07-11T00:00:00Z",
            expires_at="2027-07-11T00:00:00Z",
            issued_at="2026-07-10T00:00:00Z",
        )
        integration = build_procurement_integration_receipt(
            procurement,
            vendor,
            trust_network_manifest=manifest,
            proof_packs=[pack],
            procurement_system="servicenow",
            endpoint_base="https://procurement.example",
            credential_ref="env:PROCUREMENT_TOKEN",
            integration_ref="REQ-2026-TRUSTAI-001",
            delivered_at="2026-07-12T12:00:00Z",
        )
        return pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration

    def test_trust_network_registry_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration = self._sources(tmp)
            receipt = build_trust_network_registry_receipt(
                manifest,
                vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
                registry_name="TrustAI Local Registry",
                registry_endpoint="https://registry.example",
                namespace="finserv-buyer",
                registration_ref="TRUST-NET-2026-AITRADE-001",
                published_at="2026-07-13T00:00:00Z",
                expires_at="2027-07-13T00:00:00Z",
            )

            result = verify_trust_network_registry_receipt(
                receipt,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            )
            chain = EvidenceChain.load(tmp / "registry-chain.json", tenant_id="trust-network-registry-local")
            entry = append_trust_network_registry_receipt(
                chain,
                receipt,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            )

            self.assertEqual(TRUST_NETWORK_REGISTRY_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("active", result.status)
            self.assertEqual(TRUST_NETWORK_REGISTRY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["registration_id"], entry["payload"]["registration_id"])
            self.assertEqual(integration["integration_id"], receipt["procurement"]["integration_id"])

    def test_trust_network_registry_detects_source_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration = self._sources(Path(tmp_dir))
            receipt = build_trust_network_registry_receipt(
                manifest,
                vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
                published_at="2026-07-13T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][1]["content_hash"] = "changed"

            result = verify_trust_network_registry_receipt(
                tampered,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("registration_id" in error for error in result.errors))
            self.assertTrue(any("vendor_identity_receipt content_hash mismatch" in error for error in result.errors))

    def test_trust_network_registry_requires_accepted_vendor_binding(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, manifest, _, _, _, _, _ = self._sources(Path(tmp_dir))
            vendor_without_network = build_vendor_identity_receipt(
                [pack],
                vendor="aitrade",
                legal_name="Aitrade Labs Inc.",
                subject_ref="did:web:aitrade.example",
                issued_at="2026-07-10T00:00:00Z",
            )

            with self.assertRaisesRegex(ValueError, "accepted trust-network binding"):
                build_trust_network_registry_receipt(
                    manifest,
                    vendor_without_network,
                    proof_packs=[pack],
                    published_at="2026-07-13T00:00:00Z",
                )


if __name__ == "__main__":
    unittest.main()
