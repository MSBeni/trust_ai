import json
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.ingest import (
    INGEST_ENTRY_TYPE,
    append_events,
    append_otlp_traces,
    load_events,
    load_otlp_traces,
    normalize_event,
    otlp_traces_to_events,
)
from trustai.runtime import RUNTIME_ENTRY_TYPE, append_runtime_attestation, load_action


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
EVENTS = ROOT / "examples" / "aitrade" / "otel-events.json"
OTLP = ROOT / "examples" / "aitrade" / "otlp-traces.json"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"


class IngestRuntimeTests(unittest.TestCase):
    def test_ingested_events_and_runtime_attestation_are_chain_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)

            events = load_events(EVENTS)
            event_entries = append_events(chain, events)
            action_entry = append_runtime_attestation(chain, contract, load_action(ACTION))
            chain.save()

            self.assertEqual(2, len(event_entries))
            self.assertEqual(INGEST_ENTRY_TYPE, event_entries[0]["entry_type"])
            self.assertEqual(RUNTIME_ENTRY_TYPE, action_entry["entry_type"])
            self.assertTrue(action_entry["payload"]["passed"])
            self.assertTrue(chain.verify_all().ok)

    def test_runtime_attestation_fails_when_blast_radius_is_exceeded(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            action = json.loads(ACTION.read_text(encoding="utf-8"))
            action["notional_usd"] = 50000

            entry = append_runtime_attestation(chain, contract, action)

            self.assertFalse(entry["payload"]["passed"])


    def test_otlp_trace_payload_is_ingested_as_chain_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            events = load_otlp_traces(OTLP)

            entries = append_otlp_traces(chain, json.loads(OTLP.read_text(encoding="utf-8")))

            self.assertEqual(2, len(events))
            self.assertEqual(2, len(entries))
            self.assertEqual("gen_ai.agent.decision", events[0]["event_name"])
            self.assertEqual("2026-07-03T12:00:10Z", events[0]["timestamp"])
            self.assertEqual("trading-prod-write", events[1]["risk_class"])
            self.assertEqual(7500, events[1]["attributes"]["notional_usd"])
            self.assertEqual(INGEST_ENTRY_TYPE, entries[0]["entry_type"])
            self.assertEqual("gen_ai.tool.call", entries[1]["payload"]["event"]["event_name"])
            self.assertTrue(chain.verify_all().ok)

    def test_otlp_trace_payload_requires_trust_metadata(self):
        payload = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "4f0c98cf84fa44df9b8ad8f354d2f0a1",
                                    "spanId": "7b1c4d2e9f001122",
                                    "name": "gen_ai.agent.decision",
                                    "startTimeUnixNano": "1783080010000000000",
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        with self.assertRaisesRegex(ValueError, "contract_hash"):
            otlp_traces_to_events(payload)

    def test_event_normalization_requires_canonical_evidence_identifiers(self):
        event = {
            "trace_id": "4F0C98CF84FA44DF9B8AD8F354D2F0A1",
            "span_id": "7B1C4D2E9F001122",
            "parent_span_id": "8C2D5E3F00112233",
            "timestamp": "2026-07-03T12:00:10Z",
            "event_name": "gen_ai.agent.decision",
            "contract_hash": "22A3727B124CE6664031037939CF391CE724158D681DB3A55E9A0F0C51BCC7A2",
            "agent": {
                "name": "aitrade-risk-agent",
                "version": "sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234",
            },
        }

        normalized = normalize_event(event)

        self.assertEqual("4f0c98cf84fa44df9b8ad8f354d2f0a1", normalized["trace_id"])
        self.assertEqual("7b1c4d2e9f001122", normalized["span_id"])
        self.assertEqual("8c2d5e3f00112233", normalized["parent_span_id"])
        self.assertEqual(
            "22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2",
            normalized["contract_hash"],
        )

        for field, value in {
            "trace_id": "trace-local",
            "span_id": "span-local",
            "parent_span_id": "parent-local",
            "contract_hash": "abc123",
        }.items():
            bad = dict(event)
            bad[field] = value
            with self.assertRaisesRegex(ValueError, field):
                normalize_event(bad)

        zero_trace = dict(event)
        zero_trace["trace_id"] = "0" * 32
        with self.assertRaisesRegex(ValueError, "trace_id.*all zeros"):
            normalize_event(zero_trace)
if __name__ == "__main__":
    unittest.main()
