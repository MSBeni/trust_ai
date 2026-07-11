import tempfile
import threading
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract
from trustai.ingest import INGEST_ENTRY_TYPE
from trustai.sdk import TrustAIClient
from trustai.server import serve


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"


class SDKTests(unittest.TestCase):
    def test_local_client_records_decision_into_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "sdk-chain.json"
            contract = load_contract(CONTRACT)
            client = TrustAIClient.from_contract(contract, state_path=state_path, tenant_id="sdk-test")

            result = client.record_decision(
                "allow_shadow_order",
                attributes={"symbol": "BTCUSDT"},
                trace_id="4f0c98cf84fa44df9b8ad8f354d2f0a1",
                span_id="7b1c4d2e9f001122",
                timestamp="2026-07-03T12:00:10Z",
            )
            chain = EvidenceChain.load(state_path, tenant_id="sdk-test")

            self.assertEqual(INGEST_ENTRY_TYPE, result.entry["entry_type"])
            self.assertEqual("gen_ai.agent.decision", result.event["event_name"])
            self.assertEqual(1, len(chain.entries))
            self.assertTrue(chain.verify_all().ok)

    def test_trace_capture_and_tool_decorator_emit_tool_events(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "sdk-chain.json"
            contract = load_contract(CONTRACT)
            client = TrustAIClient.from_contract(contract, state_path=state_path, tenant_id="sdk-test")

            with client.trace("4f0c98cf84fa44df9b8ad8f354d2f0a1") as trace:
                trace.tool_call(
                    "place_shadow_order",
                    attributes={"tool.mode": "shadow", "notional_usd": 7500},
                    span_id="8c2d5e3f00112233",
                    timestamp="2026-07-03T12:00:11Z",
                )

            @client.instrument_tool("risk_limit_check")
            def check_limit(value: int) -> bool:
                return value < 10000

            self.assertTrue(check_limit(7500, trustai_trace_id="4f0c98cf84fa44df9b8ad8f354d2f0a1", trustai_span_id="9d3e6f4011223344"))
            chain = EvidenceChain.load(state_path, tenant_id="sdk-test")
            event_names = [entry["payload"]["event"]["event_name"] for entry in chain.entries]
            tool_names = [entry["payload"]["event"]["attributes"]["tool.name"] for entry in chain.entries]

            self.assertEqual(["gen_ai.tool.call", "gen_ai.tool.call"], event_names)
            self.assertEqual(["place_shadow_order", "risk_limit_check"], tool_names)
            self.assertTrue(chain.verify_all().ok)

    def test_http_client_posts_to_ingest_api(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "server-chain.json"
            httpd = serve("127.0.0.1", 0, str(state_path), "sdk-server")
            host, port = httpd.server_address
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                contract = load_contract(CONTRACT)
                client = TrustAIClient.from_contract(
                    contract,
                    endpoint=f"http://{host}:{port}",
                    tenant_id="sdk-server",
                )
                result = client.record_tool_call(
                    "place_shadow_order",
                    attributes={"tool.mode": "shadow"},
                    trace_id="4f0c98cf84fa44df9b8ad8f354d2f0a1",
                    span_id="8c2d5e3f00112233",
                    timestamp="2026-07-03T12:00:11Z",
                )
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)

            chain = EvidenceChain.load(state_path, tenant_id="sdk-server")
            self.assertEqual(1, len(result.response["entries"]))
            self.assertEqual(1, len(chain.entries))
            self.assertEqual(INGEST_ENTRY_TYPE, chain.entries[0]["entry_type"])
            self.assertTrue(chain.verify_all().ok)


if __name__ == "__main__":
    unittest.main()
