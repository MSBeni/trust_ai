import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.marketplace import (
    CONTRACT_TEMPLATE_TYPE,
    MARKETPLACE_DISTRIBUTION_ENTRY_TYPE,
    MARKETPLACE_DISTRIBUTION_SCHEMA,
    MARKETPLACE_SCHEMA,
    POLICY_PACK_TYPE,
    append_marketplace_distribution,
    build_marketplace_catalog,
    build_marketplace_distribution,
    render_marketplace_markdown,
    verify_marketplace_catalog,
    verify_marketplace_distribution,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "examples/aitrade/verification-contract.yaml"
POLICY = "examples/aitrade/policy-pack.json"


class MarketplaceCatalogTests(unittest.TestCase):
    def test_marketplace_catalog_verifies_contract_template_and_policy_pack(self):
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

        result = verify_marketplace_catalog(catalog, root=ROOT)
        markdown = render_marketplace_markdown(catalog)
        types = {asset["type"] for asset in catalog["assets"]}

        self.assertEqual(MARKETPLACE_SCHEMA, catalog["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(2, result.asset_count)
        self.assertEqual({CONTRACT_TEMPLATE_TYPE, POLICY_PACK_TYPE}, types)
        self.assertIn("TrustAI Marketplace Catalog", markdown)
        self.assertIn("trading-runtime-policy-v0", markdown)

    def test_marketplace_catalog_detects_content_hash_tamper(self):
        catalog = build_marketplace_catalog(
            root=ROOT,
            contract_templates=[CONTRACT],
            policy_packs=[POLICY],
            verticals=["trading"],
            regulations=["SR 11-7"],
            status="published",
        )
        tampered = copy.deepcopy(catalog)
        tampered["assets"][0]["content_hash"] = "changed"

        result = verify_marketplace_catalog(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("catalog_id" in error for error in result.errors))
        self.assertTrue(any("content_hash mismatch" in error for error in result.errors))
        self.assertTrue(any("asset_id mismatch" in error for error in result.errors))

    def test_marketplace_catalog_requires_vertical_and_regulation_metadata(self):
        catalog = build_marketplace_catalog(
            root=ROOT,
            contract_templates=[CONTRACT],
            policy_packs=[POLICY],
            status="published",
        )

        result = verify_marketplace_catalog(catalog, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("missing vertical metadata" in error for error in result.errors))
        self.assertTrue(any("missing regulation metadata" in error for error in result.errors))

    def test_marketplace_distribution_verifies_and_appends(self):
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
            distributed_at="2026-07-12T00:00:00Z",
        )
        result = verify_marketplace_distribution(distribution, catalog=catalog, root=ROOT)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="marketplace-test")
            entry = append_marketplace_distribution(chain, distribution, catalog=catalog, root=ROOT)
            chain_result = chain.verify_all()

        self.assertEqual(MARKETPLACE_DISTRIBUTION_SCHEMA, distribution["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(2, len(distribution["assets"]))
        self.assertEqual(MARKETPLACE_DISTRIBUTION_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(distribution["distribution_id"], entry["payload"]["distribution_id"])
        self.assertTrue(chain_result.ok, chain_result.errors)

    def test_marketplace_distribution_detects_catalog_binding_tamper(self):
        catalog = build_marketplace_catalog(
            root=ROOT,
            contract_templates=[CONTRACT],
            policy_packs=[POLICY],
            verticals=["trading"],
            regulations=["SR 11-7"],
            status="published",
        )
        distribution = build_marketplace_distribution(catalog, root=ROOT)
        tampered = copy.deepcopy(distribution)
        tampered["catalog"]["catalog_hash"] = "changed"

        result = verify_marketplace_distribution(tampered, catalog=catalog, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("distribution_id does not match canonical distribution body", result.errors)
        self.assertIn("marketplace distribution catalog binding mismatch", result.errors)


if __name__ == "__main__":
    unittest.main()