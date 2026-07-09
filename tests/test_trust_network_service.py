import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.identity_provider_attestation import write_identity_provider_attestation
from trustai.marketplace import build_marketplace_catalog, build_marketplace_distribution, write_marketplace_catalog, write_marketplace_distribution
from trustai.procurement_clause import write_procurement_clause_receipt
from trustai.procurement_integration import write_procurement_integration_receipt
from trustai.trust_network import write_trust_network_manifest
from trustai.trust_network_registry import build_trust_network_registry_receipt, write_trust_network_registry_receipt
from trustai.trust_network_registry_status import build_trust_network_registry_status_receipt, write_trust_network_registry_status_receipt
from trustai.trust_network_service import (
    TRUST_NETWORK_SERVICE_ENTRY_TYPE,
    TRUST_NETWORK_SERVICE_SCHEMA,
    append_trust_network_service_attestation,
    build_trust_network_service_attestation,
    verify_trust_network_service_attestation,
    write_trust_network_service_attestation,
)
from trustai.vendor_identity import write_vendor_identity_receipt

import tests.test_trust_network_registry as registry_test_helpers


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "examples/aitrade/verification-contract.yaml"
POLICY = "examples/aitrade/policy-pack.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class TrustNetworkServiceTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration = registry_test_helpers.TrustNetworkRegistryTests()._sources(tmp)
        registry = build_trust_network_registry_receipt(
            manifest,
            vendor,
            identity_provider_attestation=identity_attestation,
            identity_payload=identity_payload,
            procurement_receipt=procurement,
            procurement_integration_receipt=integration,
            proof_packs=[pack],
            registry_name="TrustAI Hosted Registry",
            registry_endpoint="https://registry.example",
            namespace="finserv-buyer",
            registration_ref="TRUST-NET-2026-AITRADE-001",
            published_at="2026-07-13T00:00:00Z",
            expires_at="2027-07-13T00:00:00Z",
        )
        status = build_trust_network_registry_status_receipt(
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
            evidence_refs=["ticket:SNOW-1234"],
            trust_network_manifest=manifest,
            vendor_identity_receipt=vendor,
            identity_provider_attestation=identity_attestation,
            identity_payload=identity_payload,
            procurement_receipt=procurement,
            procurement_integration_receipt=integration,
            proof_packs=[pack],
        )
        catalog = build_marketplace_catalog(
            root=ROOT,
            contract_templates=[CONTRACT],
            policy_packs=[POLICY],
            publisher="trustai-local",
            author="trustai-core-team",
            verticals=["trading"],
            regulations=["SR 11-7", "ISO 42001"],
            status="published",
        )
        distribution = build_marketplace_distribution(
            catalog,
            root=ROOT,
            channel="marketplace-api",
            target="https://marketplace.example/catalogs/trustai",
            subscriber="finserv-buyer",
            subscriber_ref="oidc:buyer.example/procurement",
            distributed_at="2026-07-14T02:00:00Z",
        )
        frontend_bundle_path = tmp / "trust-network.bundle.js"
        frontend_bundle_path.write_text(
            "export const trustNetworkPortal = {kind: 'registry-marketplace', channel: 'buyer'};\n",
            encoding="utf-8",
        )
        frontend_bundle_hash = _sha256_ref(frontend_bundle_path)
        return pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry, status, catalog, distribution, frontend_bundle_path, frontend_bundle_hash

    def _attestation(self, registry, status, catalog, distribution, **overrides):
        values = {
            "registry_receipt": registry,
            "registry_status_receipt": status,
            "marketplace_catalog": catalog,
            "marketplace_distribution": distribution,
            "root": ROOT,
            "environment": "aitrade-prod",
            "service_kind": "registry-marketplace",
            "service_ref": "trust-network:trustai/hosted-prod",
            "service_version": "0.1.0",
            "registry_endpoint": "https://registry.example",
            "marketplace_endpoint": "https://marketplace.example/catalogs/trustai",
            "service_image": "ghcr.io/trustai/trust-network-service:0.1.0",
            "service_image_digest": "sha256:trustai-trust-network-service-image",
            "service_binary_hash": "sha256:trustai-trust-network-service-binary",
            "frontend_bundle_ref": "bundle:trust-network/portal",
            "frontend_bundle_hash": "sha256:trustai-trust-network-frontend",
            "api_ref": "api:trust-network/v0",
            "registry_store_ref": "postgres:trustai/trust-network-registry",
            "search_index_ref": "opensearch:trustai/trust-network-marketplace",
            "entitlement_store_ref": "postgres:trustai/marketplace-entitlements",
            "subscription_queue_ref": "queue:trust-network/subscriptions",
            "auth_provider_ref": "oidc:trust-network/idp",
            "vendor_auth_policy_ref": "policy:trust-network/vendor-auth-v0.1",
            "buyer_auth_policy_ref": "policy:trust-network/buyer-auth-v0.1",
            "subscriber_auth_policy_ref": "policy:trust-network/subscriber-auth-v0.1",
            "rbac_policy_ref": "policy:trust-network/rbac-v0.1",
            "identity_federation_policy_ref": "policy:trust-network/identity-federation-v0.1",
            "procurement_sync_policy_ref": "policy:trust-network/procurement-sync-v0.1",
            "entitlement_policy_ref": "policy:trust-network/entitlements-v0.1",
            "catalog_review_policy_ref": "policy:trust-network/catalog-review-v0.1",
            "revocation_policy_ref": "policy:trust-network/revocation-v0.1",
            "cache_invalidation_policy_ref": "policy:trust-network/cache-invalidation-v0.1",
            "tenant_isolation_ref": "tenant-isolation:trust-network/finserv-buyer",
            "rate_limit_policy_ref": "rate-limit:trust-network/tenant",
            "request_signing_ref": "sigv4:trust-network/service",
            "network_policy_ref": "netpol:trust-network/deny-by-default",
            "egress_policy_ref": "egress:trust-network/idp-procurement-marketplace-only",
            "encryption_key_ref": "kms:trust-network/customer-data",
            "replicas_min": 3,
            "replicas_max": 9,
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "registry_audit_log_ref": "audit-log:trust-network/registry",
            "registry_audit_log_root": "sha256:trust-network-registry-audit-root",
            "marketplace_audit_log_ref": "audit-log:trust-network/marketplace",
            "marketplace_audit_log_root": "sha256:trust-network-marketplace-audit-root",
            "access_log_ref": "access-log:trust-network/sessions",
            "access_log_root": "sha256:trust-network-access-root",
            "publication_log_ref": "publication-log:trust-network/registry-marketplace",
            "publication_log_root": "sha256:trust-network-publication-root",
            "metrics_ref": "metrics:trust-network/service",
            "alert_policy_ref": "alert:trust-network/service",
            "retention_until": "2033-07-14T00:00:00Z",
            "actor_ref": "oidc:trustai.example/trust-network-operator",
            "credential_ref": "env:TRUST_NETWORK_SERVICE_TOKEN",
            "marketplace_credential_ref": "env:MARKETPLACE_API_TOKEN",
            "evidence_refs": ["evidence:trust-network/service"],
            "attested_at": "2026-07-14T06:00:00Z",
            "now": "2026-07-15T00:00:00Z",
        }
        values.update(overrides)
        if values.get("frontend_bundle_path") is not None and "frontend_bundle_hash" not in overrides:
            values["frontend_bundle_hash"] = _sha256_ref(Path(values["frontend_bundle_path"]))
        return build_trust_network_service_attestation(**values)

    def test_trust_network_service_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry, status, catalog, distribution, frontend_bundle_path, frontend_bundle_hash = self._sources(tmp)
            attestation = self._attestation(
                registry,
                status,
                catalog,
                distribution,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            frontend_bundle_path=frontend_bundle_path,
            )

            result = verify_trust_network_service_attestation(
                attestation,
                registry,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
                registry_status_receipt=status,
                marketplace_catalog=catalog,
                marketplace_distribution=distribution,
                frontend_bundle_path=frontend_bundle_path,
                root=ROOT,
                now="2026-07-15T00:00:00Z",
            )
            chain = EvidenceChain.load(tmp / "trust-network-service-chain.json", tenant_id="trust-network-service-local")
            entry = append_trust_network_service_attestation(
                chain,
                attestation,
                registry,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
                registry_status_receipt=status,
                marketplace_catalog=catalog,
                marketplace_distribution=distribution,
                frontend_bundle_path=frontend_bundle_path,
                root=ROOT,
                now="2026-07-15T00:00:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(TRUST_NETWORK_SERVICE_SCHEMA, attestation["schema"])
            self.assertEqual("hosted-service-attested", attestation["mode"])
            self.assertEqual(status["status_id"], attestation["registry"]["status_id"])
            self.assertEqual(distribution["distribution_id"], attestation["marketplace"]["distribution_id"])
            self.assertEqual("env:MARKETPLACE_API_TOKEN", attestation["operation_actor"]["marketplace_credential"]["ref"])
            self.assertEqual(frontend_bundle_hash, attestation["service"]["frontend_bundle_hash"])
            self.assertEqual(frontend_bundle_hash, attestation["service"]["frontend_bundle_artifact_hash"])
            self.assertIn("frontend-bundle", attestation["source"]["required_types"])
            self.assertEqual(TRUST_NETWORK_SERVICE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_trust_network_service_rejects_frontend_bundle_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry, status, catalog, distribution, frontend_bundle_path, _ = self._sources(Path(tmp_dir))
            with self.assertRaisesRegex(ValueError, "frontend_bundle_hash does not match supplied trust-network frontend bundle"):
                self._attestation(
                    registry,
                    status,
                    catalog,
                    distribution,
                    trust_network_manifest=manifest,
                    vendor_identity_receipt=vendor,
                    identity_provider_attestation=identity_attestation,
                    identity_payload=identity_payload,
                    procurement_receipt=procurement,
                    procurement_integration_receipt=integration,
                    proof_packs=[pack],
                    frontend_bundle_path=frontend_bundle_path,
                    frontend_bundle_hash="sha256:not-the-trust-network-bundle",
                )

            attestation = self._attestation(
                registry,
                status,
                catalog,
                distribution,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
                frontend_bundle_path=frontend_bundle_path,
            )
            frontend_bundle_path.write_text("export const trustNetworkPortal = {tampered: true};\n", encoding="utf-8")

            result = verify_trust_network_service_attestation(
                attestation,
                registry,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
                registry_status_receipt=status,
                marketplace_catalog=catalog,
                marketplace_distribution=distribution,
                frontend_bundle_path=frontend_bundle_path,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertIn("trust-network service service.frontend_bundle_hash does not match supplied frontend bundle", result.errors)

    def test_trust_network_service_rejects_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry, status, catalog, distribution, frontend_bundle_path, frontend_bundle_hash = self._sources(Path(tmp_dir))
            attestation = self._attestation(
                registry,
                status,
                catalog,
                distribution,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
            frontend_bundle_path=frontend_bundle_path,
            )
            tampered = copy.deepcopy(distribution)
            tampered["subscriber"]["organization"] = "different-buyer"

            result = verify_trust_network_service_attestation(
                attestation,
                registry,
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
                proof_packs=[pack],
                registry_status_receipt=status,
                marketplace_catalog=catalog,
                marketplace_distribution=tampered,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertIn("trust-network service source artifact mismatch for marketplace-distribution", result.errors)
            self.assertIn("marketplace distribution source: distribution_id does not match canonical distribution body", result.errors)

    def test_trust_network_service_rejects_insecure_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry, status, catalog, distribution, frontend_bundle_path, frontend_bundle_hash = self._sources(Path(tmp_dir))
            attestation = self._attestation(
                registry,
                status,
                catalog,
                distribution,
                registry_endpoint="http://registry.example",
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
            frontend_bundle_path=frontend_bundle_path,
            )

            result = verify_trust_network_service_attestation(attestation, registry, registry_status_receipt=status, marketplace_catalog=catalog, marketplace_distribution=distribution, root=ROOT)

            self.assertFalse(result.ok)
            self.assertIn("trust-network service service.registry_endpoint must use HTTPS", result.errors)

    def test_trust_network_service_rejects_weak_replicas(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry, status, catalog, distribution, frontend_bundle_path, frontend_bundle_hash = self._sources(Path(tmp_dir))
            attestation = self._attestation(
                registry,
                status,
                catalog,
                distribution,
                replicas_min=1,
                availability_zones=["us-east-1a"],
                trust_network_manifest=manifest,
                vendor_identity_receipt=vendor,
                identity_provider_attestation=identity_attestation,
                identity_payload=identity_payload,
                procurement_receipt=procurement,
                procurement_integration_receipt=integration,
            frontend_bundle_path=frontend_bundle_path,
            )

            result = verify_trust_network_service_attestation(attestation, registry, registry_status_receipt=status, marketplace_catalog=catalog, marketplace_distribution=distribution, root=ROOT)

            self.assertFalse(result.ok)
            self.assertIn("trust-network service service.replicas_min must be an integer >= 2", result.errors)
            self.assertIn("trust-network service service.availability_zones must include at least two zones", result.errors)

    def test_cli_trust_network_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry, status, catalog, distribution, frontend_bundle_path, frontend_bundle_hash = self._sources(tmp)
            pack_path = tmp / "pack.json"
            manifest_path = tmp / "trust-network-manifest.json"
            vendor_path = tmp / "vendor-identity.json"
            identity_payload_path = tmp / "identity-payload.json"
            identity_attestation_path = tmp / "identity-attestation.json"
            procurement_path = tmp / "procurement-clause.json"
            integration_path = tmp / "procurement-integration.json"
            registry_path = tmp / "trust-network-registry.json"
            status_path = tmp / "trust-network-registry-status.json"
            catalog_path = tmp / "marketplace-catalog.json"
            distribution_path = tmp / "marketplace-distribution.json"
            attestation_path = tmp / "trust-network-service-attestation.json"
            entry_path = tmp / "trust-network-service-entry.json"
            state_path = tmp / "trust-network-service-chain.json"

            _write_json(pack_path, pack)
            write_trust_network_manifest(manifest_path, manifest)
            write_vendor_identity_receipt(vendor_path, vendor)
            _write_json(identity_payload_path, identity_payload)
            write_identity_provider_attestation(identity_attestation_path, identity_attestation)
            write_procurement_clause_receipt(procurement_path, procurement)
            write_procurement_integration_receipt(integration_path, integration)
            write_trust_network_registry_receipt(registry_path, registry)
            write_trust_network_registry_status_receipt(status_path, status)
            write_marketplace_catalog(catalog_path, catalog)
            write_marketplace_distribution(distribution_path, distribution)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(registry_path),
                "--manifest", str(manifest_path),
                "--vendor-identity", str(vendor_path),
                "--identity-attestation", str(identity_attestation_path),
                "--identity-payload", str(identity_payload_path),
                "--procurement-receipt", str(procurement_path),
                "--procurement-integration", str(integration_path),
                "--pack", str(pack_path),
                "--registry-status", str(status_path),
                "--marketplace-catalog", str(catalog_path),
                "--marketplace-distribution", str(distribution_path),
                "--frontend-bundle", str(frontend_bundle_path),
                "--root", str(ROOT),
                "--now", "2026-07-15T00:00:00Z",
            ]
            service_args = [
                "--environment", "aitrade-prod",
                "--service-kind", "registry-marketplace",
                "--service-ref", "trust-network:trustai/hosted-prod",
                "--service-version", "0.1.0",
                "--registry-endpoint", "https://registry.example",
                "--marketplace-endpoint", "https://marketplace.example/catalogs/trustai",
                "--service-image", "ghcr.io/trustai/trust-network-service:0.1.0",
                "--service-image-digest", "sha256:trustai-trust-network-service-image",
                "--service-binary-hash", "sha256:trustai-trust-network-service-binary",
                "--frontend-bundle-ref", "bundle:trust-network/portal",
                "--frontend-bundle-hash", frontend_bundle_hash,
                "--api-ref", "api:trust-network/v0",
                "--registry-store-ref", "postgres:trustai/trust-network-registry",
                "--search-index-ref", "opensearch:trustai/trust-network-marketplace",
                "--entitlement-store-ref", "postgres:trustai/marketplace-entitlements",
                "--subscription-queue-ref", "queue:trust-network/subscriptions",
                "--auth-provider-ref", "oidc:trust-network/idp",
                "--vendor-auth-policy-ref", "policy:trust-network/vendor-auth-v0.1",
                "--buyer-auth-policy-ref", "policy:trust-network/buyer-auth-v0.1",
                "--subscriber-auth-policy-ref", "policy:trust-network/subscriber-auth-v0.1",
                "--rbac-policy-ref", "policy:trust-network/rbac-v0.1",
                "--identity-federation-policy-ref", "policy:trust-network/identity-federation-v0.1",
                "--procurement-sync-policy-ref", "policy:trust-network/procurement-sync-v0.1",
                "--entitlement-policy-ref", "policy:trust-network/entitlements-v0.1",
                "--catalog-review-policy-ref", "policy:trust-network/catalog-review-v0.1",
                "--revocation-policy-ref", "policy:trust-network/revocation-v0.1",
                "--cache-invalidation-policy-ref", "policy:trust-network/cache-invalidation-v0.1",
                "--tenant-isolation-ref", "tenant-isolation:trust-network/finserv-buyer",
                "--rate-limit-policy-ref", "rate-limit:trust-network/tenant",
                "--request-signing-ref", "sigv4:trust-network/service",
                "--network-policy-ref", "netpol:trust-network/deny-by-default",
                "--egress-policy-ref", "egress:trust-network/idp-procurement-marketplace-only",
                "--encryption-key-ref", "kms:trust-network/customer-data",
                "--replicas-min", "3",
                "--replicas-max", "9",
                "--availability-zone", "us-east-1a",
                "--availability-zone", "us-east-1b",
                "--registry-audit-log-ref", "audit-log:trust-network/registry",
                "--registry-audit-log-root", "sha256:trust-network-registry-audit-root",
                "--marketplace-audit-log-ref", "audit-log:trust-network/marketplace",
                "--marketplace-audit-log-root", "sha256:trust-network-marketplace-audit-root",
                "--access-log-ref", "access-log:trust-network/sessions",
                "--access-log-root", "sha256:trust-network-access-root",
                "--publication-log-ref", "publication-log:trust-network/registry-marketplace",
                "--publication-log-root", "sha256:trust-network-publication-root",
                "--metrics-ref", "metrics:trust-network/service",
                "--alert-policy-ref", "alert:trust-network/service",
                "--retention-until", "2033-07-14T00:00:00Z",
                "--actor-ref", "oidc:trustai.example/trust-network-operator",
                "--credential-ref", "env:TRUST_NETWORK_SERVICE_TOKEN",
                "--marketplace-credential-ref", "env:MARKETPLACE_API_TOKEN",
                "--evidence-ref", "evidence:trust-network/service",
                "--attested-at", "2026-07-14T06:00:00Z",
            ]
            subprocess.run(
                [sys.executable, "-m", "trustai", "trust-network-service-attestation", *source_args, *service_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "trust-network-service-verify", str(attestation_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "trust-network-service-append",
                    str(attestation_path),
                    *source_args,
                    "--state", str(state_path),
                    "--tenant", "trust-network-service-local",
                    "--out", str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            self.assertTrue(attestation_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
