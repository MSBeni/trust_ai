import copy
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

    def test_framework_event_chain_verifies_parent_span_integrity(self):
        payload = {
            "framework": "openai_agents",
            "trace_id": "parent-trace-001",
            "contract_hash": "a" * 64,
            "agent": {
                "name": "aitrade-risk-agent",
                "version": "sha256:" + "b" * 64,
                "risk_class": "trading-prod-write",
            },
            "items": [
                {
                    "type": "message",
                    "id": "msg-parent-001",
                    "timestamp": "2026-07-03T12:00:12Z",
                    "role": "assistant",
                    "content": "I will check policy before the tool call.",
                },
                {
                    "type": "function_call",
                    "id": "call-child-001",
                    "parent_id": "msg-parent-001",
                    "timestamp": "2026-07-03T12:00:13Z",
                    "name": "place_shadow_order",
                    "arguments": {"symbol": "BTCUSDT"},
                },
            ],
        }

        events = framework_payload_to_events(payload)

        self.assertEqual([], verify_framework_event_chains(events))
        self.assertEqual(events[0]["span_id"], events[1]["parent_span_id"])
        self.assertEqual("msg-parent-001", events[1]["attributes"]["trustai.adapter.source_parent_span_id"])

        tampered_parent = copy.deepcopy(events)
        tampered_parent[1]["parent_span_id"] = "f" * 16
        errors = verify_framework_event_chains(tampered_parent)
        self.assertTrue(any("parent_span_id mismatch" in error for error in errors), errors)

        orphaned_parent = copy.deepcopy(events)
        orphaned_parent[1]["attributes"]["trustai.adapter.source_parent_span_id"] = "missing-parent"
        errors = verify_framework_event_chains(orphaned_parent)
        self.assertTrue(any("missing or later parent" in error for error in errors), errors)

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

    def test_framework_trace_requires_content_addressed_contract_and_agent_metadata(self):
        payload = {
            "framework": "openai_agents",
            "trace_id": "openai-run-001",
            "contract_hash": "a" * 64,
            "agent": {
                "name": "aitrade-risk-agent",
                "version": "sha256:" + "b" * 64,
                "risk_class": "trading-prod-write",
            },
            "items": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": "shadow run complete",
                    "timestamp": "2026-07-03T12:00:00Z",
                }
            ],
        }

        events = framework_payload_to_events(payload)

        self.assertEqual(1, len(events))
        self.assertEqual("a" * 64, events[0]["contract_hash"])
        self.assertEqual("trading-prod-write", events[0]["risk_class"])
        self.assertEqual("sha256:" + "b" * 64, events[0]["agent"]["version"])

        invalid_contract = copy.deepcopy(payload)
        invalid_contract["contract_hash"] = "not-a-contract-hash"
        with self.assertRaisesRegex(ValueError, "contract_hash must be"):
            framework_payload_to_events(invalid_contract)

        invalid_agent_version = copy.deepcopy(payload)
        invalid_agent_version["agent"]["version"] = "v1"
        with self.assertRaisesRegex(ValueError, "agent version"):
            framework_payload_to_events(invalid_agent_version)

        missing_agent_name = copy.deepcopy(payload)
        missing_agent_name["agent"].pop("name")
        with self.assertRaisesRegex(ValueError, "agent missing name"):
            framework_payload_to_events(missing_agent_name)

        missing_risk_class = copy.deepcopy(payload)
        missing_risk_class["agent"].pop("risk_class")
        with self.assertRaisesRegex(ValueError, "missing risk_class"):
            framework_payload_to_events(missing_risk_class)

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
