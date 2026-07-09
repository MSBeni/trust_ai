import json
import tempfile
import unittest
from pathlib import Path

from trustai.adapters import append_framework_events, framework_payload_to_events, load_framework_events
from trustai.chain import EvidenceChain
from trustai.ingest import INGEST_ENTRY_TYPE


ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK_TRACES = ROOT / "examples" / "aitrade" / "framework-traces.json"


class FrameworkAdapterTests(unittest.TestCase):
    def test_framework_traces_normalize_to_otel_events(self):
        events = load_framework_events(FRAMEWORK_TRACES)

        self.assertEqual(12, len(events))
        frameworks = {event["attributes"]["trustai.adapter.framework"] for event in events}
        self.assertEqual(
            {"langgraph", "openai_agents", "claude_agent", "crewai", "bedrock", "vertex"},
            frameworks,
        )
        event_names = [event["event_name"] for event in events]
        self.assertIn("gen_ai.agent.decision", event_names)
        self.assertIn("gen_ai.tool.call", event_names)
        self.assertIn("gen_ai.agent.message", event_names)
        tool_events = [event for event in events if event["event_name"] == "gen_ai.tool.call"]
        self.assertTrue(any(event["attributes"].get("tool.name") == "place_shadow_order" for event in tool_events))
        self.assertTrue(all(event["schema_url"] == "trustai.framework-adapter/0.1" for event in events))

    def test_framework_events_append_to_verifiable_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            entries = append_framework_events(chain, json.loads(FRAMEWORK_TRACES.read_text(encoding="utf-8")))

            self.assertEqual(12, len(entries))
            self.assertTrue(all(entry["entry_type"] == INGEST_ENTRY_TYPE for entry in entries))
            self.assertTrue(chain.verify_all().ok)

    def test_framework_trace_requires_known_framework(self):
        with self.assertRaisesRegex(ValueError, "unsupported framework"):
            framework_payload_to_events(
                {
                    "framework": "unknown",
                    "contract_hash": "abc",
                    "agent": {"name": "agent", "version": "v1"},
                    "events": [{"timestamp": "2026-07-03T12:00:00Z"}],
                }
            )


if __name__ == "__main__":
    unittest.main()
