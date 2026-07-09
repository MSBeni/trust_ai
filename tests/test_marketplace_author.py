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
    MARKETPLACE_AUTHOR_ENTRY_TYPE,
    MARKETPLACE_AUTHOR_SCHEMA,
    append_marketplace_author_governance,
    build_marketplace_author_governance,
    verify_marketplace_author_governance,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "examples/aitrade/verification-contract.yaml"
POLICY = "examples/aitrade/policy-pack.json"


class MarketplaceAuthorGovernanceTests(unittest.TestCase):
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
        return catalog, distribution

    def _receipt(self, catalog, distribution=None, **overrides):
        values = {
            "catalog": catalog,
            "distribution": distribution,
            "root": ROOT,
            "mode": "platform-governed",
            "author_name": "Example Audit Templates",
            "author_ref": "did:web:templates.example",
            "author_kind": "third-party",
            "author_organization": "Example Audit LLP",
            "contact_ref": "mailto:templates@example.com",
            "identity_provider": "okta",
            "identity_subject": "okta:user/example-audit-templates",
            "identity_assurance": "phishing-resistant-mfa",
            "onboarding_status": "approved",
            "agreement_ref": "agreement:marketplace-author/EXAMPLE-2026-001",
            "terms_ref": "terms:trustai-marketplace-author-v0.1",
            "license_ref": "license:apache-2.0",
            "ip_attestation_ref": "ip-attestation:EXAMPLE-2026-001",
            "review_ticket_ref": "review:marketplace/EXAMPLE-2026-001",
            "review_policy_ref": "policy:marketplace-review-v0.1",
            "reviewer_ref": "oidc:trustai.example/marketplace-reviewer-1",
            "reviewer_role": "marketplace-reviewer",
            "billing_mode": "entitlement-recorded",
            "billing_account_ref": "billing:acct/example-audit",
            "entitlement_policy_ref": "policy:marketplace-entitlements-v0.1",
            "payout_account_ref": "vault:payout/example-audit",
            "revenue_share_bps": 2500,
            "tax_form_ref": "tax-form:w9/example-audit-2026",
            "revocation_policy_ref": "policy:marketplace-revocation-v0.1",
            "support_contact_ref": "mailto:support@example.com",
            "security_contact_ref": "mailto:security@example.com",
            "audit_log_ref": "audit-log:marketplace/authors",
            "audit_log_root": "sha256:marketplace-author-audit-root",
            "retention_until": "2033-07-12T00:00:00Z",
            "evidence_refs": ["evidence:marketplace/author-review"],
            "issued_at": "2026-07-12T01:00:00Z",
        }
        values.update(overrides)
        return build_marketplace_author_governance(**values)

    def test_marketplace_author_governance_verifies_and_appends(self):
        catalog, distribution = self._sources()
        receipt = self._receipt(catalog, distribution)
        result = verify_marketplace_author_governance(receipt, catalog=catalog, distribution=distribution, root=ROOT)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="marketplace-author-test")
            entry = append_marketplace_author_governance(chain, receipt, catalog=catalog, distribution=distribution, root=ROOT)
            chain_result = chain.verify_all()

        self.assertEqual(MARKETPLACE_AUTHOR_SCHEMA, receipt["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("vault:payout/example-audit", receipt["billing"]["payout_account"]["ref"])
        self.assertEqual(MARKETPLACE_AUTHOR_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["governance_id"], entry["payload"]["governance_id"])
        self.assertIn("governed", entry["payload"]["control_summary"])
        self.assertTrue(chain_result.ok, chain_result.errors)

    def test_marketplace_author_governance_detects_billing_tamper(self):
        catalog, distribution = self._sources()
        receipt = self._receipt(catalog, distribution)
        tampered = copy.deepcopy(receipt)
        tampered["billing"]["revenue_share_bps"] = 12000

        result = verify_marketplace_author_governance(tampered, catalog=catalog, distribution=distribution, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("governance_id does not match canonical marketplace author body", result.errors)
        self.assertIn("marketplace author billing.revenue_share_bps must be between 0 and 10000", result.errors)

    def test_marketplace_author_governance_rejects_missing_asset(self):
        catalog, distribution = self._sources()

        with self.assertRaises(ValueError) as ctx:
            self._receipt(catalog, distribution, asset_ids=["missing-asset"])

        self.assertIn("governed marketplace assets not found", str(ctx.exception))

    def test_cli_marketplace_author_governance_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            catalog, distribution = self._sources()
            catalog_path = tmp / "marketplace-catalog.json"
            distribution_path = tmp / "marketplace-distribution.json"
            receipt_path = tmp / "marketplace-author-governance.json"
            entry_path = tmp / "marketplace-author-governance-entry.json"
            state_path = tmp / "marketplace-author-chain.json"
            write_marketplace_catalog(catalog_path, catalog)
            write_marketplace_distribution(distribution_path, distribution)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            args = [
                str(catalog_path),
                "--distribution",
                str(distribution_path),
                "--root",
                str(ROOT),
                "--mode",
                "platform-governed",
                "--author-name",
                "Example Audit Templates",
                "--author-ref",
                "did:web:templates.example",
                "--author-kind",
                "third-party",
                "--author-organization",
                "Example Audit LLP",
                "--contact-ref",
                "mailto:templates@example.com",
                "--identity-provider",
                "okta",
                "--identity-subject",
                "okta:user/example-audit-templates",
                "--identity-assurance",
                "phishing-resistant-mfa",
                "--onboarding-status",
                "approved",
                "--agreement-ref",
                "agreement:marketplace-author/EXAMPLE-2026-001",
                "--terms-ref",
                "terms:trustai-marketplace-author-v0.1",
                "--license-ref",
                "license:apache-2.0",
                "--ip-attestation-ref",
                "ip-attestation:EXAMPLE-2026-001",
                "--review-ticket-ref",
                "review:marketplace/EXAMPLE-2026-001",
                "--review-policy-ref",
                "policy:marketplace-review-v0.1",
                "--reviewer-ref",
                "oidc:trustai.example/marketplace-reviewer-1",
                "--billing-mode",
                "entitlement-recorded",
                "--billing-account-ref",
                "billing:acct/example-audit",
                "--entitlement-policy-ref",
                "policy:marketplace-entitlements-v0.1",
                "--payout-account-ref",
                "vault:payout/example-audit",
                "--revenue-share-bps",
                "2500",
                "--tax-form-ref",
                "tax-form:w9/example-audit-2026",
                "--revocation-policy-ref",
                "policy:marketplace-revocation-v0.1",
                "--support-contact-ref",
                "mailto:support@example.com",
                "--security-contact-ref",
                "mailto:security@example.com",
                "--audit-log-ref",
                "audit-log:marketplace/authors",
                "--audit-log-root",
                "sha256:marketplace-author-audit-root",
                "--retention-until",
                "2033-07-12T00:00:00Z",
                "--evidence-ref",
                "evidence:marketplace/author-review",
                "--issued-at",
                "2026-07-12T01:00:00Z",
            ]

            subprocess.run(
                base + ["marketplace-author-governance", *args, "--out", str(receipt_path)],
                check=True,
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                base
                + [
                    "marketplace-author-verify",
                    str(receipt_path),
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
                    "marketplace-author-append",
                    str(receipt_path),
                    "--catalog",
                    str(catalog_path),
                    "--distribution",
                    str(distribution_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "marketplace-author-cli",
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
            self.assertEqual(MARKETPLACE_AUTHOR_ENTRY_TYPE, entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)


if __name__ == "__main__":
    unittest.main()
