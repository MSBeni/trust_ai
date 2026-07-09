import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.identity_provider_attestation import write_identity_provider_attestation
from trustai.marketplace import write_marketplace_catalog, write_marketplace_distribution
from trustai.marketplace_author import build_marketplace_author_governance, write_marketplace_author_governance
from trustai.marketplace_settlement import build_marketplace_settlement, write_marketplace_settlement
from trustai.procurement_clause import write_procurement_clause_receipt
from trustai.procurement_integration import write_procurement_integration_receipt
from trustai.trust_network import write_trust_network_manifest
from trustai.trust_network_registry import write_trust_network_registry_receipt
from trustai.trust_network_registry_status import write_trust_network_registry_status_receipt
from trustai.trust_network_service import write_trust_network_service_attestation
from trustai.trust_network_worker import (
    TRUST_NETWORK_WORKER_ENTRY_TYPE,
    TRUST_NETWORK_WORKER_SCHEMA,
    append_trust_network_worker_receipt,
    build_trust_network_worker_receipt,
    verify_trust_network_worker_receipt,
    write_trust_network_worker_receipt,
)
from trustai.vendor_identity import write_vendor_identity_receipt

import tests.test_trust_network_service as service_test_helpers


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class TrustNetworkWorkerTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = service_test_helpers.TrustNetworkServiceTests()
        pack, manifest, vendor, identity_payload, identity_attestation, procurement, integration, registry, status, catalog, distribution = helper._sources(tmp)
        service = helper._attestation(
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
        )
        author = build_marketplace_author_governance(
            catalog,
            distribution=distribution,
            root=ROOT,
            mode="platform-governed",
            author_name="Example Audit Templates",
            author_ref="did:web:templates.example",
            author_kind="third-party",
            author_organization="Example Audit LLP",
            contact_ref="mailto:templates@example.com",
            identity_provider="okta",
            identity_subject="okta:user/example-audit-templates",
            identity_assurance="phishing-resistant-mfa",
            onboarding_status="approved",
            agreement_ref="agreement:marketplace-author/EXAMPLE-2026-001",
            terms_ref="terms:trustai-marketplace-author-v0.1",
            license_ref="license:apache-2.0",
            ip_attestation_ref="ip-attestation:EXAMPLE-2026-001",
            review_ticket_ref="review:marketplace/EXAMPLE-2026-001",
            review_policy_ref="policy:marketplace-review-v0.1",
            reviewer_ref="oidc:trustai.example/marketplace-reviewer-1",
            reviewer_role="marketplace-reviewer",
            billing_mode="entitlement-recorded",
            billing_account_ref="billing:acct/example-audit",
            entitlement_policy_ref="policy:marketplace-entitlements-v0.1",
            payout_account_ref="vault:payout/example-audit",
            revenue_share_bps=2500,
            tax_form_ref="tax-form:w9/example-audit-2026",
            revocation_policy_ref="policy:marketplace-revocation-v0.1",
            support_contact_ref="mailto:support@example.com",
            security_contact_ref="mailto:security@example.com",
            audit_log_ref="audit-log:marketplace/authors",
            audit_log_root="sha256:marketplace-author-audit-root",
            retention_until="2033-07-12T00:00:00Z",
            evidence_refs=["evidence:marketplace/author-review"],
            issued_at="2026-07-12T01:00:00Z",
        )
        settlement = build_marketplace_settlement(
            author,
            catalog=catalog,
            distribution=distribution,
            root=ROOT,
            mode="provider-settled",
            settlement_ref="settlement:marketplace/EXAMPLE-2026-001",
            subscriber_ref="oidc:buyer.example/procurement",
            entitlement_check_ref="entitlement-check:marketplace/EXAMPLE-2026-001",
            entitlement_decision="allowed",
            entitlement_checked_at="2026-07-12T02:00:00Z",
            period_start="2026-07-12T00:00:00Z",
            period_end="2026-08-12T00:00:00Z",
            invoice_ref="invoice:marketplace/EXAMPLE-2026-001",
            gross_amount_usd=1000.0,
            tax_withholding_bps=1000,
            invoice_status="paid",
            payout_ref="payout:marketplace/EXAMPLE-2026-001",
            payout_provider_ref="stripe:transfer/tr_EXAMPLE",
            payout_status="settled",
            payout_executed_at="2026-07-12T02:30:00Z",
            payout_trace_ref="trace:marketplace-payout/EXAMPLE-2026-001",
            idempotency_key_ref="vault:idempotency/marketplace/EXAMPLE-2026-001",
            tax_profile_ref="tax-profile:example-audit/us",
            tax_jurisdiction="US",
            tax_document_custody_ref="vault:tax-documents/example-audit/w9-2026",
            tax_document_hash="sha256:marketplace-tax-document-hash",
            audit_log_ref="audit-log:marketplace/settlements",
            audit_log_root="sha256:marketplace-settlement-audit-root",
            retention_until="2033-08-12T00:00:00Z",
            evidence_refs=["evidence:marketplace/settlement"],
            issued_at="2026-07-12T03:00:00Z",
        )
        return {
            "pack": pack,
            "manifest": manifest,
            "vendor": vendor,
            "identity_payload": identity_payload,
            "identity_attestation": identity_attestation,
            "procurement": procurement,
            "integration": integration,
            "registry": registry,
            "status": status,
            "catalog": catalog,
            "distribution": distribution,
            "service": service,
            "author": author,
            "settlement": settlement,
        }

    def _receipt(self, sources: dict, **overrides):
        values = {
            "service_attestation": sources["service"],
            "registry_receipt": sources["registry"],
            "trust_network_manifest": sources["manifest"],
            "vendor_identity_receipt": sources["vendor"],
            "identity_provider_attestation": sources["identity_attestation"],
            "identity_payload": sources["identity_payload"],
            "procurement_receipt": sources["procurement"],
            "procurement_integration_receipt": sources["integration"],
            "proof_packs": [sources["pack"]],
            "registry_status_receipt": sources["status"],
            "marketplace_catalog": sources["catalog"],
            "marketplace_distribution": sources["distribution"],
            "marketplace_author_governance": sources["author"],
            "marketplace_settlement": sources["settlement"],
            "root": ROOT,
            "mode": "hosted-worker",
            "environment": "aitrade-prod",
            "worker_ref": "worker:trust-network/marketplace-settlement-reconciler",
            "run_ref": "worker-run:trust-network/marketplace-settlement/2026-07-12T03:05:00Z",
            "operation_kind": "marketplace_settlement_reconcile",
            "actor_ref": "oidc:trustai.example/trust-network-worker",
            "schedule_ref": "schedule:trust-network/marketplace-settlement/5m",
            "cadence_seconds": 300,
            "lease_ref": "lease:trust-network/marketplace-settlement/2026-07-12T03:05:00Z",
            "checkpoint_ref": "checkpoint:trust-network/marketplace-settlement",
            "checkpoint_hash": "sha256:trust-network-worker-checkpoint",
            "previous_cursor_ref": "cursor:trust-network/marketplace-settlement/start",
            "next_cursor_ref": "cursor:trust-network/marketplace-settlement/next",
            "attempt": 1,
            "max_attempts": 3,
            "queue_ref": "queue:trust-network/subscriptions",
            "queue_message_ref": "queue-message:trust-network/settlement/EXAMPLE-2026-001",
            "destination_ref": "marketplace:https://marketplace.example/catalogs/trustai",
            "publication_log_ref": "publication-log:trust-network/registry-marketplace",
            "publication_log_root": "sha256:trust-network-worker-publication-root",
            "cache_invalidation_ref": "cache-invalidation:trust-network/EXAMPLE-2026-001",
            "external_callback_ref": "callback:marketplace/settlement/EXAMPLE-2026-001",
            "provider_invoice_log_ref": "stripe:invoice/in_EXAMPLE",
            "provider_invoice_log_hash": "sha256:provider-invoice-log-hash",
            "provider_payout_log_ref": "stripe:transfer/tr_EXAMPLE",
            "provider_payout_log_hash": "sha256:provider-payout-log-hash",
            "provider_tax_custody_ref": "vault:tax-documents/example-audit/w9-2026",
            "provider_tax_document_hash": "sha256:marketplace-tax-document-hash",
            "request_hash": "sha256:trust-network-worker-request",
            "response_status": 202,
            "response_hash": "sha256:trust-network-worker-response",
            "metrics_ref": "metrics:trust-network/workers",
            "audit_log_ref": "audit-log:trust-network/workers",
            "audit_log_root": "sha256:trust-network-worker-audit-root",
            "credential_ref": "env:TRUST_NETWORK_WORKER_TOKEN",
            "evidence_refs": ["evidence:trust-network/worker"],
            "started_at": "2026-07-12T03:05:00Z",
            "completed_at": "2026-07-12T03:06:00Z",
            "next_run_at": "2026-07-12T03:10:00Z",
        }
        values.update(overrides)
        return build_trust_network_worker_receipt(**values)

    def test_trust_network_worker_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            result = verify_trust_network_worker_receipt(
                receipt,
                service_attestation=sources["service"],
                registry_receipt=sources["registry"],
                trust_network_manifest=sources["manifest"],
                vendor_identity_receipt=sources["vendor"],
                identity_provider_attestation=sources["identity_attestation"],
                identity_payload=sources["identity_payload"],
                procurement_receipt=sources["procurement"],
                procurement_integration_receipt=sources["integration"],
                proof_packs=[sources["pack"]],
                registry_status_receipt=sources["status"],
                marketplace_catalog=sources["catalog"],
                marketplace_distribution=sources["distribution"],
                marketplace_author_governance=sources["author"],
                marketplace_settlement=sources["settlement"],
                root=ROOT,
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "worker-chain.json", tenant_id="trust-network-worker-test")
            entry = append_trust_network_worker_receipt(
                chain,
                receipt,
                service_attestation=sources["service"],
                registry_receipt=sources["registry"],
                trust_network_manifest=sources["manifest"],
                vendor_identity_receipt=sources["vendor"],
                identity_provider_attestation=sources["identity_attestation"],
                identity_payload=sources["identity_payload"],
                procurement_receipt=sources["procurement"],
                procurement_integration_receipt=sources["integration"],
                proof_packs=[sources["pack"]],
                registry_status_receipt=sources["status"],
                marketplace_catalog=sources["catalog"],
                marketplace_distribution=sources["distribution"],
                marketplace_author_governance=sources["author"],
                marketplace_settlement=sources["settlement"],
                root=ROOT,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(TRUST_NETWORK_WORKER_SCHEMA, receipt["schema"])
            self.assertEqual("hosted-worker", receipt["mode"])
            self.assertEqual(sources["settlement"]["settlement_id"], receipt["marketplace"]["settlement_id"])
            self.assertEqual("env:TRUST_NETWORK_WORKER_TOKEN", receipt["credential"]["ref"])
            self.assertNotIn("worker-token-secret", json.dumps(receipt, sort_keys=True))
            self.assertEqual(TRUST_NETWORK_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_trust_network_worker_detects_settlement_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            tampered = copy.deepcopy(sources["settlement"])
            tampered["invoice"]["status"] = "void"

            result = verify_trust_network_worker_receipt(
                receipt,
                service_attestation=sources["service"],
                registry_receipt=sources["registry"],
                trust_network_manifest=sources["manifest"],
                vendor_identity_receipt=sources["vendor"],
                identity_provider_attestation=sources["identity_attestation"],
                identity_payload=sources["identity_payload"],
                procurement_receipt=sources["procurement"],
                procurement_integration_receipt=sources["integration"],
                proof_packs=[sources["pack"]],
                registry_status_receipt=sources["status"],
                marketplace_catalog=sources["catalog"],
                marketplace_distribution=sources["distribution"],
                marketplace_author_governance=sources["author"],
                marketplace_settlement=tampered,
                root=ROOT,
            )

            self.assertFalse(result.ok)
            self.assertIn("trust-network worker source hash mismatch for marketplace-settlement", result.errors)

    def test_cli_trust_network_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            paths = {
                "pack": tmp / "pack.json",
                "manifest": tmp / "manifest.json",
                "vendor": tmp / "vendor.json",
                "identity_payload": tmp / "identity-payload.json",
                "identity_attestation": tmp / "identity-attestation.json",
                "procurement": tmp / "procurement.json",
                "integration": tmp / "integration.json",
                "registry": tmp / "registry.json",
                "status": tmp / "status.json",
                "catalog": tmp / "catalog.json",
                "distribution": tmp / "distribution.json",
                "service": tmp / "service.json",
                "author": tmp / "author.json",
                "settlement": tmp / "settlement.json",
                "worker": tmp / "worker.json",
                "entry": tmp / "worker-entry.json",
                "chain": tmp / "chain.json",
            }
            _write_json(paths["pack"], sources["pack"])
            write_trust_network_manifest(paths["manifest"], sources["manifest"])
            write_vendor_identity_receipt(paths["vendor"], sources["vendor"])
            write_identity_provider_attestation(paths["identity_attestation"], sources["identity_attestation"])
            _write_json(paths["identity_payload"], sources["identity_payload"])
            write_procurement_clause_receipt(paths["procurement"], sources["procurement"])
            write_procurement_integration_receipt(paths["integration"], sources["integration"])
            write_trust_network_registry_receipt(paths["registry"], sources["registry"])
            write_trust_network_registry_status_receipt(paths["status"], sources["status"])
            write_marketplace_catalog(paths["catalog"], sources["catalog"])
            write_marketplace_distribution(paths["distribution"], sources["distribution"])
            write_trust_network_service_attestation(paths["service"], sources["service"])
            write_marketplace_author_governance(paths["author"], sources["author"])
            write_marketplace_settlement(paths["settlement"], sources["settlement"])

            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            base_sources = [
                "--service-attestation",
                str(paths["service"]),
                str(paths["registry"]),
                "--manifest",
                str(paths["manifest"]),
                "--vendor-identity",
                str(paths["vendor"]),
                "--identity-attestation",
                str(paths["identity_attestation"]),
                "--identity-payload",
                str(paths["identity_payload"]),
                "--procurement-receipt",
                str(paths["procurement"]),
                "--procurement-integration",
                str(paths["integration"]),
                "--pack",
                str(paths["pack"]),
                "--registry-status",
                str(paths["status"]),
                "--marketplace-catalog",
                str(paths["catalog"]),
                "--marketplace-distribution",
                str(paths["distribution"]),
                "--marketplace-author-governance",
                str(paths["author"]),
                "--marketplace-settlement",
                str(paths["settlement"]),
                "--root",
                str(ROOT),
            ]
            build_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "trust-network-worker",
                *base_sources,
                "--mode",
                "hosted-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:trust-network/marketplace-settlement-reconciler",
                "--run-ref",
                "worker-run:trust-network/marketplace-settlement/2026-07-12T03:05:00Z",
                "--operation-kind",
                "marketplace_settlement_reconcile",
                "--actor-ref",
                "oidc:trustai.example/trust-network-worker",
                "--schedule-ref",
                "schedule:trust-network/marketplace-settlement/5m",
                "--cadence-seconds",
                "300",
                "--lease-ref",
                "lease:trust-network/marketplace-settlement/2026-07-12T03:05:00Z",
                "--checkpoint-ref",
                "checkpoint:trust-network/marketplace-settlement",
                "--checkpoint-hash",
                "sha256:trust-network-worker-checkpoint",
                "--previous-cursor-ref",
                "cursor:trust-network/marketplace-settlement/start",
                "--next-cursor-ref",
                "cursor:trust-network/marketplace-settlement/next",
                "--queue-ref",
                "queue:trust-network/subscriptions",
                "--queue-message-ref",
                "queue-message:trust-network/settlement/EXAMPLE-2026-001",
                "--destination-ref",
                "marketplace:https://marketplace.example/catalogs/trustai",
                "--publication-log-ref",
                "publication-log:trust-network/registry-marketplace",
                "--publication-log-root",
                "sha256:trust-network-worker-publication-root",
                "--cache-invalidation-ref",
                "cache-invalidation:trust-network/EXAMPLE-2026-001",
                "--external-callback-ref",
                "callback:marketplace/settlement/EXAMPLE-2026-001",
                "--provider-invoice-log-ref",
                "stripe:invoice/in_EXAMPLE",
                "--provider-invoice-log-hash",
                "sha256:provider-invoice-log-hash",
                "--provider-payout-log-ref",
                "stripe:transfer/tr_EXAMPLE",
                "--provider-payout-log-hash",
                "sha256:provider-payout-log-hash",
                "--provider-tax-custody-ref",
                "vault:tax-documents/example-audit/w9-2026",
                "--provider-tax-document-hash",
                "sha256:marketplace-tax-document-hash",
                "--request-hash",
                "sha256:trust-network-worker-request",
                "--response-status",
                "202",
                "--response-hash",
                "sha256:trust-network-worker-response",
                "--metrics-ref",
                "metrics:trust-network/workers",
                "--audit-log-ref",
                "audit-log:trust-network/workers",
                "--audit-log-root",
                "sha256:trust-network-worker-audit-root",
                "--credential-ref",
                "env:TRUST_NETWORK_WORKER_TOKEN",
                "--evidence-ref",
                "evidence:trust-network/worker",
                "--started-at",
                "2026-07-12T03:05:00Z",
                "--completed-at",
                "2026-07-12T03:06:00Z",
                "--next-run-at",
                "2026-07-12T03:10:00Z",
                "--out",
                str(paths["worker"]),
            ]
            subprocess.run(build_cmd, cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            verify_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "trust-network-worker-verify",
                str(paths["worker"]),
                *base_sources,
            ]
            subprocess.run(verify_cmd, cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            append_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "trust-network-worker-append",
                str(paths["worker"]),
                *base_sources,
                "--state",
                str(paths["chain"]),
                "--tenant",
                "trust-network-worker-test",
                "--out",
                str(paths["entry"]),
            ]
            subprocess.run(append_cmd, cwd=ROOT, env=env, check=True, capture_output=True, text=True)

            receipt = json.loads(paths["worker"].read_text(encoding="utf-8"))
            entry = json.loads(paths["entry"].read_text(encoding="utf-8"))
            self.assertEqual(TRUST_NETWORK_WORKER_SCHEMA, receipt["schema"])
            self.assertEqual(TRUST_NETWORK_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])


if __name__ == "__main__":
    unittest.main()
