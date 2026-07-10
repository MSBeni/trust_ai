import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.identity import load_identity_inventory
from trustai.registry import (
    AGENT_INVENTORY_ENTRY_TYPE,
    DELEGATION_ENTRY_TYPE,
    DELEGATION_GRAPH_ENTRY_TYPE,
    append_delegation,
    append_delegation_graph,
    append_inventory,
    build_delegation_graph,
    load_delegation,
    load_inventory,
    verify_delegation_graph,
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

    def test_delegation_graph_binds_multi_hop_edges_to_source_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            inventory = copy.deepcopy(load_inventory(INVENTORY))
            inventory["agents"].append(
                {
                    "name": "aitrade-sentiment-classifier",
                    "version": "sha256:22223333444455556666777788889999aaaabbbbccccddddeeeeffff11112222",
                    "owner": "research",
                    "risk_class": "research-read-only",
                    "environment": "dev",
                    "governed": False,
                }
            )
            append_inventory(chain, inventory)
            first = load_delegation(DELEGATION)
            second = copy.deepcopy(first)
            second["timestamp"] = "2026-07-03T12:02:00Z"
            second["parent_agent"] = first["child_agent"]
            second["child_agent"] = {
                "name": "aitrade-sentiment-classifier",
                "version": "sha256:22223333444455556666777788889999aaaabbbbccccddddeeeeffff11112222",
            }
            second["reason"] = "summarizer delegates sentiment scoring before the risk agent decides"
            second["scope"] = {"max_depth": 0, "allowed_tools": ["sentiment-score"], "data_classification": "market-news"}
            append_delegation(chain, first)
            append_delegation(chain, second)

            graph = build_delegation_graph(
                chain,
                contract_hash=first["contract_hash"],
                root_agent="aitrade-risk-agent",
                generated_at="2026-07-03T12:03:00Z",
            )
            result = verify_delegation_graph(graph, source_chain=chain)
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(3, graph["summary"]["node_count"])
            self.assertEqual(2, graph["summary"]["edge_count"])
            self.assertEqual(2, graph["summary"]["max_depth"])
            self.assertFalse(graph["summary"]["missing_inventory"])

            entry = append_delegation_graph(chain, graph, source_chain=chain)
            self.assertEqual(DELEGATION_GRAPH_ENTRY_TYPE, entry["entry_type"])
            self.assertTrue(verify_delegation_graph(graph, source_chain=chain).ok)
            self.assertTrue(chain.verify_all().ok)

    def test_delegation_graph_detects_tampered_edge_body(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            append_inventory(chain, load_inventory(INVENTORY))
            delegation = load_delegation(DELEGATION)
            append_delegation(chain, delegation)
            graph = build_delegation_graph(chain, contract_hash=delegation["contract_hash"], generated_at="2026-07-03T12:03:00Z")

            tampered = copy.deepcopy(graph)
            tampered["edges"][0]["delegation"]["reason"] = "changed after signing"
            result = verify_delegation_graph(tampered, source_chain=chain)

            self.assertFalse(result.ok)
            self.assertTrue(any("delegation_hash mismatch" in error for error in result.errors))

    def test_delegation_graph_rejects_cycles(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            append_inventory(chain, load_inventory(INVENTORY))
            first = load_delegation(DELEGATION)
            second = copy.deepcopy(first)
            second["timestamp"] = "2026-07-03T12:02:00Z"
            second["parent_agent"] = first["child_agent"]
            second["child_agent"] = first["parent_agent"]
            second["reason"] = "cycle used only to prove verifier rejection"
            append_delegation(chain, first)
            append_delegation(chain, second)

            graph = build_delegation_graph(chain, contract_hash=first["contract_hash"], generated_at="2026-07-03T12:03:00Z")
            result = verify_delegation_graph(graph, source_chain=chain)

            self.assertTrue(graph["summary"]["cycle_detected"])
            self.assertFalse(result.ok)
            self.assertTrue(any("contains a cycle" in error for error in result.errors))

    def test_delegation_graph_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            state = Path(tmp_dir) / "chain.json"
            graph = Path(tmp_dir) / "delegation-graph.json"
            entry = Path(tmp_dir) / "delegation-graph-entry.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            contract_hash = load_delegation(DELEGATION)["contract_hash"]

            def run(*args: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, "-m", "trustai", *args],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )

            run("inventory", str(INVENTORY), "--state", str(state), "--tenant", "cli-graph-test")
            run("delegation", str(DELEGATION), "--state", str(state), "--tenant", "cli-graph-test")
            run(
                "delegation-graph",
                "--state",
                str(state),
                "--tenant",
                "cli-graph-test",
                "--contract-hash",
                contract_hash,
                "--generated-at",
                "2026-07-03T12:03:00Z",
                "--out",
                str(graph),
            )
            run("delegation-graph-verify", str(graph), "--state", str(state), "--tenant", "cli-graph-test")
            run("delegation-graph-append", str(graph), "--state", str(state), "--tenant", "cli-graph-test", "--out", str(entry))
            run("delegation-graph-verify", str(graph), "--state", str(state), "--tenant", "cli-graph-test")

            entry_doc = json.loads(entry.read_text(encoding="utf-8"))
            self.assertEqual(DELEGATION_GRAPH_ENTRY_TYPE, entry_doc["entry_type"])
            self.assertEqual(1, entry_doc["payload"]["summary"]["edge_count"])

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
