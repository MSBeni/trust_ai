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

if __name__ == "__main__":
    unittest.main()
