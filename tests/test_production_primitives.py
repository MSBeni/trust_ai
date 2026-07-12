import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from trustai.anchor import append_anchor, verify_anchor
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.ingest import load_events
from trustai.object_store import WORMStore
from trustai.server import serve
from trustai.timestamping import issue_timestamp_token, verify_timestamp_token


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
EVENTS = ROOT / "examples" / "aitrade" / "otel-events.json"
OTLP = ROOT / "examples" / "aitrade" / "otlp-traces.json"


class ProductionPrimitiveTests(unittest.TestCase):
    def test_timestamp_token_rejects_message_tamper(self):
        message = {"entry_id": "abc", "payload_hash": "def"}
        token = issue_timestamp_token(message)

        self.assertTrue(verify_timestamp_token(message, token))
        self.assertFalse(verify_timestamp_token({"entry_id": "abc", "payload_hash": "tampered"}, token))

    def test_chain_entries_include_timestamp_tokens_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            register_contract(chain, load_contract(CONTRACT))
            chain.save()

            self.assertIn("timestamp_token", chain.entries[0])
            self.assertTrue(chain.verify_all().ok)

    def test_anchor_and_worm_receipt_verify(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            register_contract(chain, load_contract(CONTRACT))
            anchor_entry = append_anchor(chain)
            chain.save()

            self.assertEqual([], verify_anchor(anchor_entry["payload"]))
            store = WORMStore(tmp / "worm")
            receipt = store.store_json({"chain": chain.tree(), "anchor": anchor_entry}, "chain-anchor")
            audit = store.audit_receipt(receipt, now="2026-07-04T00:00:00Z")
            expired = store.audit_receipt(receipt, now="2034-01-01T00:00:00Z")
            tampered = {**receipt, "size_bytes": receipt["size_bytes"] + 1}
            tampered_audit = store.audit_receipt(tampered, now="2026-07-04T00:00:00Z")

            self.assertTrue(store.verify_receipt(receipt))
            self.assertTrue(audit.ok, audit.errors)
            self.assertTrue(audit.retention_active)
            self.assertTrue(expired.ok, expired.errors)
            self.assertFalse(expired.retention_active)
            self.assertIn("retention period has expired", expired.warnings)
            self.assertFalse(tampered_audit.ok)
            self.assertTrue(any("receipt_id" in error or "size" in error for error in tampered_audit.errors))

    def test_http_service_health_ingest_and_control_plane_index(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            control_path = tmp / "control.sqlite"
            server = serve(
                "127.0.0.1",
                0,
                str(state_path),
                "server-test",
                control_db_path=str(control_path),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request("GET", "/health")
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                response.read()

                events = {"events": load_events(EVENTS)}
                conn.request(
                    "POST",
                    "/v0/ingest",
                    body=json.dumps(events),
                    headers={"Content-Type": "application/json"},
                )
                ingest_response = conn.getresponse()
                body = json.loads(ingest_response.read().decode("utf-8"))
                self.assertEqual(200, ingest_response.status)
                self.assertEqual(2, len(body["entries"]))

                conn.request(
                    "POST",
                    "/v1/traces",
                    body=OTLP.read_text(encoding="utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                otlp_response = conn.getresponse()
                otlp_body = json.loads(otlp_response.read().decode("utf-8"))
                self.assertEqual(200, otlp_response.status)
                self.assertEqual(2, len(otlp_body["entries"]))

                conn.request(
                    "POST",
                    "/v0/control/index",
                    body=json.dumps({"state_path": str(state_path)}),
                    headers={"Content-Type": "application/json"},
                )
                index_response = conn.getresponse()
                index_body = json.loads(index_response.read().decode("utf-8"))
                self.assertEqual(200, index_response.status)
                self.assertEqual(4, index_body["summary"]["counts"]["chain_entries"])
                self.assertEqual(4, index_body["summary"]["counts"]["ingest_events"])

                conn.request("GET", "/v0/control/summary")
                summary_response = conn.getresponse()
                summary_body = json.loads(summary_response.read().decode("utf-8"))
                self.assertEqual(200, summary_response.status)
                self.assertEqual(4, summary_body["counts"]["chain_entries"])
                self.assertEqual(4, summary_body["counts"]["ingest_events"])

                conn.request("GET", "/v0/ingest-events")
                ingest_events_response = conn.getresponse()
                ingest_events_body = json.loads(ingest_events_response.read().decode("utf-8"))
                self.assertEqual(200, ingest_events_response.status)
                self.assertEqual(4, len(ingest_events_body["ingest_events"]))
                self.assertEqual("gen_ai.tool.call", ingest_events_body["ingest_events"][0]["event_name"])

                conn.request("GET", "/v0/runtime-evidence")
                runtime_response = conn.getresponse()
                runtime_body = json.loads(runtime_response.read().decode("utf-8"))
                self.assertEqual(200, runtime_response.status)
                self.assertEqual([], runtime_body["runtime_attestations"])
                self.assertEqual([], runtime_body["policy_decisions"])
                self.assertEqual([], runtime_body["policy_engine_receipts"])
                self.assertEqual([], runtime_body["incidents"])
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
