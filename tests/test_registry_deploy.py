import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.identity import load_identity_inventory
from trustai.registry import (
    AGENT_INVENTORY_ENTRY_TYPE,
    DELEGATION_ENTRY_TYPE,
    append_delegation,
    append_inventory,
    load_delegation,
    load_inventory,
)


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"
IDENTITY_INVENTORY = ROOT / "examples" / "aitrade" / "identity-inventory.json"
DELEGATION = ROOT / "examples" / "aitrade" / "delegation.json"


class RegistryDeployTests(unittest.TestCase):
    def test_inventory_and_delegation_are_chain_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")

            inventory_entries = append_inventory(chain, load_inventory(INVENTORY))
            delegation_entry = append_delegation(chain, load_delegation(DELEGATION))
            chain.save()

            self.assertEqual(2, len(inventory_entries))
            self.assertEqual(AGENT_INVENTORY_ENTRY_TYPE, inventory_entries[0]["entry_type"])
            self.assertEqual(DELEGATION_ENTRY_TYPE, delegation_entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)

    def test_identity_inventory_adapters_append_chain_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")

            inventory = load_identity_inventory(IDENTITY_INVENTORY)
            entries = append_inventory(chain, inventory)

            providers = {entry["payload"]["agent"]["identity_provider"] for entry in entries}
            names = {entry["payload"]["agent"]["name"] for entry in entries}

            self.assertEqual(3, len(entries))
            self.assertEqual({"okta", "entra", "servicenow"}, providers)
            self.assertIn("aitrade-risk-agent", names)
            self.assertTrue(entries[0]["payload"]["agent"]["governed"])
            self.assertTrue(chain.verify_all().ok)

    def test_byoc_scaffold_exists(self):
        self.assertTrue((ROOT / "deploy" / "docker" / "Dockerfile").exists())
        self.assertTrue((ROOT / "deploy" / "helm" / "trustai" / "Chart.yaml").exists())
        self.assertTrue((ROOT / "deploy" / "helm" / "trustai" / "templates" / "demo-job.yaml").exists())


if __name__ == "__main__":
    unittest.main()
