import json
import tempfile
import unittest
from pathlib import Path

from trustai.adapters import (
    ADAPTER_EVENT_CHAIN_SCHEMA,
    append_framework_events,
    framework_payload_to_events,
    load_framework_events,
    verify_framework_event_chains,
)
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
        self.assertTrue(all(len(event["trace_id"]) == 32 for event in events))
        self.assertTrue(all(len(event["span_id"]) == 16 for event in events))
        langgraph_events = [event for event in events if event["attributes"]["trustai.adapter.framework"] == "langgraph"]
        self.assertEqual({"lg-trace-001"}, {event["attributes"]["trustai.adapter.source_trace_id"] for event in langgraph_events})
        self.assertIn("lg-risk-001", {event["attributes"]["trustai.adapter.source_span_id"] for event in langgraph_events})
        self.assertEqual([], verify_framework_event_chains(events))
        for framework in frameworks:
            framework_events = [
                event for event in events if event["attributes"]["trustai.adapter.framework"] == framework
            ]
            roots = {event["attributes"]["trustai.adapter.trace_root"] for event in framework_events}
            self.assertEqual(1, len(roots))
            self.assertEqual(
                list(range(len(framework_events))),
                [event["attributes"]["trustai.adapter.event_sequence"] for event in framework_events],
            )
            self.assertTrue(
                all(
                    event["attributes"]["trustai.adapter.event_chain_schema"] == ADAPTER_EVENT_CHAIN_SCHEMA
                    for event in framework_events
                )
            )
            self.assertEqual(
                framework_events[-1]["attributes"]["trustai.adapter.event_node_hash"],
                framework_events[-1]["attributes"]["trustai.adapter.trace_root"],
            )

    def test_framework_event_chain_tamper_is_rejected(self):
        events = load_framework_events(FRAMEWORK_TRACES)
        tampered = json.loads(json.dumps(events))
        tampered[1]["attributes"]["trustai.adapter.event_sequence"] = 99
        tampered[1]["event_name"] = "gen_ai.agent.tampered"

        errors = verify_framework_event_chains(tampered)

        self.assertTrue(any("event_sequence mismatch" in error for error in errors))
        self.assertTrue(any("event_node_hash mismatch" in error for error in errors))

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
