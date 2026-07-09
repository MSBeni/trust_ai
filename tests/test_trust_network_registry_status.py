import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.trust_network_registry import build_trust_network_registry_receipt
from trustai.trust_network_registry_status import (
    TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE,
    TRUST_NETWORK_REGISTRY_STATUS_SCHEMA,
    append_trust_network_registry_status_receipt,
    build_trust_network_registry_status_receipt,
    verify_trust_network_registry_status_receipt,
)

import tests.test_trust_network_registry as registry_test_helpers


class TrustNetworkRegistryStatusTests(unittest.TestCase):
    def _registry_sources(self, tmp: Path):
        pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration = registry_test_helpers.TrustNetworkRegistryTests()._sources(tmp)
        registry = build_trust_network_registry_receipt(
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
        return pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry

    def test_registry_status_receipt_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry = self._registry_sources(tmp)
            receipt = build_trust_network_registry_status_receipt(
                registry,
                new_status="suspended",
                reason="Buyer dispute opened after procurement review.",
                reason_code="buyer-dispute",
                actor_ref="oidc:buyer.example/procurement-reviewer",
                actor_role="buyer-procurement",
                decided_at="2026-07-14T00:00:00Z",
                effective_at="2026-07-14T01:00:00Z",
                dispute_ref="DISPUTE-2026-AITRADE-001",
                dispute_window_until="2026-08-14T00:00:00Z",
                evidence_refs=["ticket:SNOW-1234", "email:procurement@example.com/thread/42"],
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            )

            result = verify_trust_network_registry_status_receipt(
                receipt,
                registry_receipt=registry,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            )
            chain = EvidenceChain.load(tmp / "registry-status-chain.json", tenant_id="trust-network-registry-status-local")
            entry = append_trust_network_registry_status_receipt(
                chain,
                receipt,
                registry_receipt=registry,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            )

            self.assertEqual(TRUST_NETWORK_REGISTRY_STATUS_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("active", result.previous_status)
            self.assertEqual("suspended", result.new_status)
            self.assertEqual(TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["status_id"], entry["payload"]["status_id"])

    def test_registry_status_detects_source_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry = self._registry_sources(Path(tmp_dir))
            receipt = build_trust_network_registry_status_receipt(
                registry,
                new_status="revoked",
                reason="Vendor proof-pack registration revoked by buyer.",
                reason_code="buyer-revocation",
                actor_ref="oidc:buyer.example/procurement-admin",
                decided_at="2026-07-14T00:00:00Z",
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            )
            tampered = copy.deepcopy(receipt)
            tampered["source_artifacts"][0]["content_hash"] = "changed"

            result = verify_trust_network_registry_status_receipt(
                tampered,
                registry_receipt=registry,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("status_id" in error for error in result.errors))
            self.assertTrue(any("trust_network_registry_receipt content_hash mismatch" in error for error in result.errors))

    def test_registry_status_rejects_noop_status_change(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, _, _, _, _, _, _, registry = self._registry_sources(Path(tmp_dir))

            with self.assertRaisesRegex(ValueError, "must differ"):
                build_trust_network_registry_status_receipt(
                    registry,
                    new_status="active",
                    reason="No-op status update.",
                    actor_ref="oidc:registry.example/operator",
                    decided_at="2026-07-14T00:00:00Z",
                )


if __name__ == "__main__":
    unittest.main()
