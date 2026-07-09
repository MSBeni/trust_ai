import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.marketplace import (
    build_marketplace_catalog,
    build_marketplace_distribution,
    write_marketplace_catalog,
    write_marketplace_distribution,
)
from trustai.marketplace_author import (
    build_marketplace_author_governance,
    write_marketplace_author_governance,
)
from trustai.marketplace_settlement import (
    MARKETPLACE_SETTLEMENT_ENTRY_TYPE,
    MARKETPLACE_SETTLEMENT_SCHEMA,
    append_marketplace_settlement,
    build_marketplace_settlement,
    verify_marketplace_settlement,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "examples/aitrade/verification-contract.yaml"
POLICY = "examples/aitrade/policy-pack.json"


class MarketplaceSettlementTests(unittest.TestCase):
    def _sources(self):
        catalog = build_marketplace_catalog(
            root=ROOT,
            contract_templates=[CONTRACT],
            policy_packs=[POLICY],
            publisher="trustai-local",
            author="example-audit-templates",
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
            distributed_at="2026-07-12T00:00:00Z",
        )
        governance = build_marketplace_author_governance(
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
        return catalog, distribution, governance

    def _receipt(self, governance, catalog, distribution, **overrides):
        values = {
            "author_governance": governance,
            "catalog": catalog,
            "distribution": distribution,
            "root": ROOT,
            "mode": "provider-settled",
            "settlement_ref": "settlement:marketplace/EXAMPLE-2026-001",
            "subscriber_ref": "oidc:buyer.example/procurement",
            "entitlement_check_ref": "entitlement-check:marketplace/EXAMPLE-2026-001",
            "entitlement_decision": "allowed",
            "entitlement_checked_at": "2026-07-12T02:00:00Z",
            "period_start": "2026-07-12T00:00:00Z",
            "period_end": "2026-08-12T00:00:00Z",
            "invoice_ref": "invoice:marketplace/EXAMPLE-2026-001",
            "gross_amount_usd": 1000.0,
            "tax_withholding_bps": 1000,
            "invoice_status": "paid",
            "payout_ref": "payout:marketplace/EXAMPLE-2026-001",
            "payout_provider_ref": "stripe:transfer/tr_EXAMPLE",
            "payout_status": "settled",
            "payout_executed_at": "2026-07-12T02:30:00Z",
            "payout_trace_ref": "trace:marketplace-payout/EXAMPLE-2026-001",
            "idempotency_key_ref": "vault:idempotency/marketplace/EXAMPLE-2026-001",
            "tax_profile_ref": "tax-profile:example-audit/us",
            "tax_jurisdiction": "US",
            "tax_document_custody_ref": "vault:tax-documents/example-audit/w9-2026",
            "tax_document_hash": "sha256:marketplace-tax-document-hash",
            "audit_log_ref": "audit-log:marketplace/settlements",
            "audit_log_root": "sha256:marketplace-settlement-audit-root",
            "retention_until": "2033-08-12T00:00:00Z",
            "evidence_refs": ["evidence:marketplace/settlement"],
            "issued_at": "2026-07-12T03:00:00Z",
        }
        values.update(overrides)
        return build_marketplace_settlement(**values)

    def test_marketplace_settlement_verifies_and_appends(self):
        catalog, distribution, governance = self._sources()
        receipt = self._receipt(governance, catalog, distribution)
        result = verify_marketplace_settlement(
            receipt,
            author_governance=governance,
            catalog=catalog,
            distribution=distribution,
            root=ROOT,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="marketplace-settlement-test")
            entry = append_marketplace_settlement(
                chain,
                receipt,
                author_governance=governance,
                catalog=catalog,
                distribution=distribution,
                root=ROOT,
            )
            chain_result = chain.verify_all()

        self.assertEqual(MARKETPLACE_SETTLEMENT_SCHEMA, receipt["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(250.0, receipt["revenue_share"]["author_gross_amount_usd"])
        self.assertEqual(25.0, receipt["tax"]["withholding_amount_usd"])
        self.assertEqual(225.0, receipt["payout"]["amount_usd"])
        self.assertEqual("vault:payout/example-audit", receipt["payout"]["payout_account"]["ref"])
        self.assertEqual(MARKETPLACE_SETTLEMENT_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["settlement_id"], entry["payload"]["settlement_id"])
        self.assertIn("governed", entry["payload"]["control_summary"])
        self.assertTrue(chain_result.ok, chain_result.errors)

    def test_marketplace_settlement_detects_amount_tamper(self):
        catalog, distribution, governance = self._sources()
        receipt = self._receipt(governance, catalog, distribution)
        tampered = copy.deepcopy(receipt)
        tampered["payout"]["amount_usd"] = 500.0

        result = verify_marketplace_settlement(
            tampered,
            author_governance=governance,
            catalog=catalog,
            distribution=distribution,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("settlement_id does not match canonical marketplace settlement body", result.errors)
        self.assertIn("marketplace settlement payout.amount_usd does not match deterministic settlement math", result.errors)

    def test_marketplace_settlement_rejects_source_author_tamper(self):
        catalog, distribution, governance = self._sources()
        receipt = self._receipt(governance, catalog, distribution)
        tampered_source = copy.deepcopy(governance)
        tampered_source["billing"]["entitlement_policy_ref"] = "policy:marketplace-entitlements-v9"

        result = verify_marketplace_settlement(
            receipt,
            author_governance=tampered_source,
            catalog=catalog,
            distribution=distribution,
            root=ROOT,
        )

        self.assertFalse(result.ok)
        self.assertIn("marketplace settlement governance binding mismatch", result.errors)
        self.assertIn("marketplace settlement entitlement policy does not match author governance", result.errors)

    def test_cli_marketplace_settlement_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            catalog, distribution, governance = self._sources()
            catalog_path = tmp / "marketplace-catalog.json"
            distribution_path = tmp / "marketplace-distribution.json"
            governance_path = tmp / "marketplace-author-governance.json"
            settlement_path = tmp / "marketplace-settlement.json"
            entry_path = tmp / "marketplace-settlement-entry.json"
            state_path = tmp / "marketplace-settlement-chain.json"
            write_marketplace_catalog(catalog_path, catalog)
            write_marketplace_distribution(distribution_path, distribution)
            write_marketplace_author_governance(governance_path, governance)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            args = [
                str(governance_path),
                "--catalog",
                str(catalog_path),
                "--distribution",
                str(distribution_path),
                "--root",
                str(ROOT),
                "--mode",
                "provider-settled",
                "--settlement-ref",
                "settlement:marketplace/EXAMPLE-2026-001",
                "--subscriber-ref",
                "oidc:buyer.example/procurement",
                "--entitlement-check-ref",
                "entitlement-check:marketplace/EXAMPLE-2026-001",
                "--entitlement-decision",
                "allowed",
                "--entitlement-checked-at",
                "2026-07-12T02:00:00Z",
                "--period-start",
                "2026-07-12T00:00:00Z",
                "--period-end",
                "2026-08-12T00:00:00Z",
                "--invoice-ref",
                "invoice:marketplace/EXAMPLE-2026-001",
                "--gross-amount-usd",
                "1000.0",
                "--tax-withholding-bps",
                "1000",
                "--invoice-status",
                "paid",
                "--payout-ref",
                "payout:marketplace/EXAMPLE-2026-001",
                "--payout-provider-ref",
                "stripe:transfer/tr_EXAMPLE",
                "--payout-status",
                "settled",
                "--payout-executed-at",
                "2026-07-12T02:30:00Z",
                "--payout-trace-ref",
                "trace:marketplace-payout/EXAMPLE-2026-001",
                "--idempotency-key-ref",
                "vault:idempotency/marketplace/EXAMPLE-2026-001",
                "--tax-profile-ref",
                "tax-profile:example-audit/us",
                "--tax-jurisdiction",
                "US",
                "--tax-document-custody-ref",
                "vault:tax-documents/example-audit/w9-2026",
                "--tax-document-hash",
                "sha256:marketplace-tax-document-hash",
                "--audit-log-ref",
                "audit-log:marketplace/settlements",
                "--audit-log-root",
                "sha256:marketplace-settlement-audit-root",
                "--retention-until",
                "2033-08-12T00:00:00Z",
                "--evidence-ref",
                "evidence:marketplace/settlement",
                "--issued-at",
                "2026-07-12T03:00:00Z",
            ]

            subprocess.run(
                base + ["marketplace-settlement", *args, "--out", str(settlement_path)],
                check=True,
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                base
                + [
                    "marketplace-settlement-verify",
                    str(settlement_path),
                    "--author-governance",
                    str(governance_path),
                    "--catalog",
                    str(catalog_path),
                    "--distribution",
                    str(distribution_path),
                    "--root",
                    str(ROOT),
                ],
                check=True,
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                base
                + [
                    "marketplace-settlement-append",
                    str(settlement_path),
                    "--author-governance",
                    str(governance_path),
                    "--catalog",
                    str(catalog_path),
                    "--distribution",
                    str(distribution_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "marketplace-settlement-cli",
                    "--out",
                    str(entry_path),
                ],
                check=True,
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )

            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(state_path)
            self.assertEqual(MARKETPLACE_SETTLEMENT_ENTRY_TYPE, entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)


if __name__ == "__main__":
    unittest.main()
