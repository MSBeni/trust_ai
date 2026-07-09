import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.collector_topology import (
    COLLECTOR_TOPOLOGY_ENTRY_TYPE,
    COLLECTOR_TOPOLOGY_SCHEMA,
    append_collector_topology,
    build_collector_topology,
    render_collector_topology_markdown,
    verify_collector_topology,
)


ROOT = Path(__file__).resolve().parents[1]


class CollectorTopologyTests(unittest.TestCase):
    def test_collector_topology_verifies_sources_and_appends(self):
        topology = build_collector_topology(ROOT, environment="test-local")
        result = verify_collector_topology(topology, root=ROOT)
        markdown = render_collector_topology_markdown(topology)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="collector-test")
            entry = append_collector_topology(chain, topology, root=ROOT)

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(COLLECTOR_TOPOLOGY_SCHEMA, topology["schema"])
            self.assertEqual("otel-genai-to-evidence-chain", topology["topology"]["ingest_model"])
            self.assertIn("src/trustai/ingest.py", {source["path"] for source in topology["source_files"]})
            self.assertIn("http-otlp-v1-traces", {endpoint["id"] for endpoint in topology["endpoints"]})
            self.assertIn("planned-production", entry["payload"]["component_summary"])
            self.assertIn("# TrustAI Collector Topology", markdown)
            self.assertEqual(COLLECTOR_TOPOLOGY_ENTRY_TYPE, entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)

    def test_collector_topology_detects_source_hash_tamper(self):
        topology = build_collector_topology(ROOT)
        tampered = copy.deepcopy(topology)
        tampered["source_files"][0]["sha256"] = "0" * 64

        result = verify_collector_topology(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("topology_id does not match canonical topology body", result.errors)
        self.assertTrue(any("sha256 mismatch" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
