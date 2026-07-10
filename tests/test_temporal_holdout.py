import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.verifier import verify_proof_pack
from trustai.shadow import (
    SHADOW_REPLAY_ENTRY_TYPE,
    TEMPORAL_HOLDOUT_ENTRY_TYPE,
    TEMPORAL_HOLDOUT_SCHEMA,
    TRAFFIC_COMPLETENESS_ENTRY_TYPE,
    TRAFFIC_COMPLETENESS_SCHEMA,
    TRAFFIC_HOLDOUT_EXPORT_ENTRY_TYPE,
    TRAFFIC_HOLDOUT_EXPORT_SCHEMA,
    append_shadow_replay,
    append_temporal_holdout_manifest,
    append_traffic_completeness_receipt,
    append_traffic_holdout_export,
    build_temporal_holdout_manifest,
    build_traffic_completeness_receipt,
    build_traffic_holdout_export,
    evaluate_shadow_replay,
    load_shadow_replay,
    shadow_replay_to_eval_results,
    verify_temporal_holdout_manifest,
    verify_traffic_completeness_receipt,
    verify_traffic_holdout_export,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"

SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"


class TemporalHoldoutTests(unittest.TestCase):
    def _contract(self) -> dict:
        return load_contract(CONTRACT)

    def _replay(self) -> dict:
        return load_shadow_replay(SHADOW)

    def _traffic_export(self) -> dict:
        return build_traffic_holdout_export(
            self._contract(),
            self._replay(),
            export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
            source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
            exporter_ref="oidc:trustai.example/traffic-exporter",
            window_start="2026-07-02T00:00:00Z",
            window_end="2026-07-03T23:59:59Z",
            query_ref="query:shadow-holdout/btcusdt-prod-write",
            cursor_start="redpanda:0:100",
            cursor_end="redpanda:0:102",
            produced_at="2026-07-03T12:20:00Z",
        )

    def _provider_export(self, traffic_export: dict) -> dict:
        stream_records = []
        for offset, record in enumerate(traffic_export["records"], start=100):
            stream_records.append(
                {
                    "record_id": record["record_id"],
                    "timestamp": record["timestamp"],
                    "record_hash": record["record_hash"],
                    "export_record_hash": record["export_record_hash"],
                    "previous_export_record_hash": record["previous_export_record_hash"],
                    "cursor_ref": f"redpanda:0:{offset}",
                    "partition": 0,
                    "offset": offset,
                    "source_ref": traffic_export["source_ref"],
                }
            )
        return {
            "schema": "trustai.traffic-completeness-provider-export/0.1",
            "export_ref": "provider-export:aitrade/prod-traffic-holdout-20260702",
            "provider": "redpanda-clickhouse-cloudtrail",
            "environment": "aitrade-prod",
            "source_ref": traffic_export["source_ref"],
            "collector_ref": "collector:aitrade-prod/redpanda/trustai.otel.events",
            "stream_ref": "redpanda:aitrade-prod/trustai.otel.events",
            "topic": "trustai.otel.events",
            "window_start": traffic_export["extraction_window"]["started_at"],
            "window_end": traffic_export["extraction_window"]["ended_at"],
            "cursor_start": traffic_export["cursor_start"],
            "cursor_end": traffic_export["cursor_end"],
            "traffic_records_root": traffic_export["records_root"],
            "traffic_record_count": traffic_export["record_count"],
            "stream_records": stream_records,
            "audit_log_ref": "audit-log:collector/traffic-holdout-export",
            "audit_log_root": "sha256:traffic-holdout-audit-root",
            "audit_records": [
                {
                    "event_type": "traffic_holdout_export_completed",
                    "export_ref": traffic_export["export_ref"],
                    "traffic_export_id": traffic_export["export_id"],
                    "records_root": traffic_export["records_root"],
                    "record_count": traffic_export["record_count"],
                    "window_start": traffic_export["extraction_window"]["started_at"],
                    "window_end": traffic_export["extraction_window"]["ended_at"],
                    "cursor_start": traffic_export["cursor_start"],
                    "cursor_end": traffic_export["cursor_end"],
                    "actor_ref": "oidc:trustai.example/traffic-completeness-worker",
                    "timestamp": "2026-07-03T12:23:00Z",
                }
            ],
        }

    def test_traffic_holdout_export_binds_source_window_and_replay_hashes(self):
        receipt = build_traffic_holdout_export(
            self._contract(),
            self._replay(),
            export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
            source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
            exporter_ref="oidc:trustai.example/traffic-exporter",
            window_start="2026-07-02T00:00:00Z",
            window_end="2026-07-03T23:59:59Z",
            query_ref="query:shadow-holdout/btcusdt-prod-write",
            cursor_start="redpanda:0:100",
            cursor_end="redpanda:0:102",
            produced_at="2026-07-03T12:20:00Z",
        )
        result = verify_traffic_holdout_export(receipt, contract=self._contract(), replay=self._replay())

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(TRAFFIC_HOLDOUT_EXPORT_SCHEMA, receipt["schema"])
        self.assertEqual(3, receipt["record_count"])
        self.assertTrue(receipt["passed"])
        self.assertEqual([], receipt["violations"])
        self.assertFalse(receipt["privacy"]["raw_payloads_embedded"])
        self.assertEqual(receipt["records"][-1]["export_record_hash"], receipt["records_root"])
        self.assertIsNone(receipt["records"][0]["previous_export_record_hash"])
        self.assertEqual(receipt["records"][0]["export_record_hash"], receipt["records"][1]["previous_export_record_hash"])

    def test_traffic_holdout_export_appends_to_chain(self):
        receipt = build_traffic_holdout_export(
            self._contract(),
            self._replay(),
            export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
            source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
            exporter_ref="oidc:trustai.example/traffic-exporter",
            window_start="2026-07-02T00:00:00Z",
            window_end="2026-07-03T23:59:59Z",
            produced_at="2026-07-03T12:20:00Z",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="traffic-holdout-test")
            entry = append_traffic_holdout_export(chain, receipt, contract=self._contract(), replay=self._replay())

            self.assertEqual(TRAFFIC_HOLDOUT_EXPORT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["export_id"], entry["payload"]["export_id"])
            self.assertEqual(receipt["records_root"], entry["payload"]["records_root"])
            self.assertTrue(chain.verify_all().ok)

    def test_traffic_holdout_export_detects_source_replay_tamper(self):
        receipt = build_traffic_holdout_export(
            self._contract(),
            self._replay(),
            export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
            source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
            exporter_ref="oidc:trustai.example/traffic-exporter",
            window_start="2026-07-02T00:00:00Z",
            window_end="2026-07-03T23:59:59Z",
            produced_at="2026-07-03T12:20:00Z",
        )
        tampered_replay = self._replay()
        tampered_replay["records"][0]["latency_ms"] = 1

        result = verify_traffic_holdout_export(receipt, contract=self._contract(), replay=tampered_replay)

        self.assertFalse(result.ok)
        self.assertTrue(any("replay hash mismatch" in error for error in result.errors))
        self.assertTrue(any("replay record hash mismatch" in error for error in result.errors))

    def test_traffic_holdout_export_records_window_violations(self):
        receipt = build_traffic_holdout_export(
            self._contract(),
            self._replay(),
            export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
            source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
            exporter_ref="oidc:trustai.example/traffic-exporter",
            window_start="2026-07-02T04:00:00Z",
            window_end="2026-07-03T23:59:59Z",
            produced_at="2026-07-03T12:20:00Z",
        )
        result = verify_traffic_holdout_export(receipt, contract=self._contract(), replay=self._replay())

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(receipt["passed"])
        self.assertTrue(any("outside production traffic export window" in item["violation"] for item in receipt["violations"]))
        self.assertTrue(result.warnings)

    def test_cli_traffic_holdout_export_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt_path = tmp / "traffic-holdout-export.json"
            entry_path = tmp / "traffic-holdout-export-entry.json"
            state_path = tmp / "evidence-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "traffic-holdout-export",
                    str(CONTRACT),
                    str(SHADOW),
                    "--export-ref",
                    "traffic-export:aitrade/prod-traffic-holdout-20260702",
                    "--source-ref",
                    "collector:aitrade-prod/redpanda/trustai.otel.events",
                    "--exporter-ref",
                    "oidc:trustai.example/traffic-exporter",
                    "--window-start",
                    "2026-07-02T00:00:00Z",
                    "--window-end",
                    "2026-07-03T23:59:59Z",
                    "--produced-at",
                    "2026-07-03T12:20:00Z",
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "traffic-holdout-export-verify",
                    str(receipt_path),
                    "--contract",
                    str(CONTRACT),
                    "--replay",
                    str(SHADOW),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "traffic-holdout-export-append",
                    str(receipt_path),
                    "--contract",
                    str(CONTRACT),
                    "--replay",
                    str(SHADOW),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "traffic-holdout-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        self.assertEqual(receipt["export_id"], entry["payload"]["export_id"])

    def test_traffic_completeness_binds_provider_stream_and_audit_evidence(self):
        traffic_export = self._traffic_export()
        provider_export = self._provider_export(traffic_export)
        receipt = build_traffic_completeness_receipt(
            traffic_export,
            provider_export,
            mode="production-export",
            authority_ref="authority:traffic-completeness/aitrade-prod",
            endpoint_url="https://provider.example/aitrade/traffic-holdout/export",
            request_hash="sha256:traffic-completeness-request",
            response_status=200,
            response_hash="sha256:traffic-completeness-response",
            actor_ref="oidc:trustai.example/traffic-completeness-worker",
            produced_at="2026-07-03T12:25:00Z",
        )
        result = verify_traffic_completeness_receipt(receipt, traffic_export=traffic_export, provider_export=provider_export)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(TRAFFIC_COMPLETENESS_SCHEMA, receipt["schema"])
        self.assertTrue(receipt["passed"])
        self.assertEqual(3, receipt["source_completeness"]["matched_record_count"])
        self.assertEqual(0, receipt["source_completeness"]["missing_record_count"])
        self.assertEqual(0, receipt["source_completeness"]["extra_provider_record_count"])
        self.assertTrue(receipt["source_completeness"]["records_root_matches"])
        self.assertTrue(receipt["source_completeness"]["audit_records_bound"])
        self.assertFalse(receipt["privacy"]["raw_payloads_embedded"])

    def test_traffic_completeness_appends_to_chain(self):
        traffic_export = self._traffic_export()
        provider_export = self._provider_export(traffic_export)
        receipt = build_traffic_completeness_receipt(
            traffic_export,
            provider_export,
            mode="production-export",
            authority_ref="authority:traffic-completeness/aitrade-prod",
            endpoint_url="https://provider.example/aitrade/traffic-holdout/export",
            request_hash="sha256:traffic-completeness-request",
            response_status=200,
            response_hash="sha256:traffic-completeness-response",
            actor_ref="oidc:trustai.example/traffic-completeness-worker",
            produced_at="2026-07-03T12:25:00Z",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="traffic-completeness-test")
            entry = append_traffic_completeness_receipt(chain, receipt, traffic_export=traffic_export, provider_export=provider_export)

            self.assertEqual(TRAFFIC_COMPLETENESS_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["completeness_id"], entry["payload"]["completeness_id"])
            self.assertTrue(entry["payload"]["source_completeness"]["records_root_matches"])
            self.assertTrue(chain.verify_all().ok)

    def test_traffic_completeness_detects_provider_export_tamper(self):
        traffic_export = self._traffic_export()
        provider_export = self._provider_export(traffic_export)
        receipt = build_traffic_completeness_receipt(
            traffic_export,
            provider_export,
            mode="production-export",
            authority_ref="authority:traffic-completeness/aitrade-prod",
            endpoint_url="https://provider.example/aitrade/traffic-holdout/export",
            request_hash="sha256:traffic-completeness-request",
            response_status=200,
            response_hash="sha256:traffic-completeness-response",
            actor_ref="oidc:trustai.example/traffic-completeness-worker",
            produced_at="2026-07-03T12:25:00Z",
        )
        tampered_provider = copy.deepcopy(provider_export)
        tampered_provider["stream_records"][0]["record_hash"] = "sha256:tampered"

        result = verify_traffic_completeness_receipt(receipt, traffic_export=traffic_export, provider_export=tampered_provider)

        self.assertFalse(result.ok)
        self.assertTrue(any("provider_export binding mismatch" in error for error in result.errors))
        self.assertTrue(any("source_completeness mismatch" in error or "matched_records mismatch" in error for error in result.errors))

    def test_traffic_completeness_records_extra_provider_records(self):
        traffic_export = self._traffic_export()
        provider_export = self._provider_export(traffic_export)
        provider_export["stream_records"].append(
            {
                "record_id": "traffic-extra",
                "timestamp": "2026-07-03T06:00:00Z",
                "record_hash": "sha256:extra-record",
                "export_record_hash": "sha256:extra-export-record",
                "previous_export_record_hash": traffic_export["records"][-1]["export_record_hash"],
                "cursor_ref": "redpanda:0:103",
                "partition": 0,
                "offset": 103,
                "source_ref": traffic_export["source_ref"],
            }
        )
        receipt = build_traffic_completeness_receipt(
            traffic_export,
            provider_export,
            mode="production-export",
            authority_ref="authority:traffic-completeness/aitrade-prod",
            endpoint_url="https://provider.example/aitrade/traffic-holdout/export",
            request_hash="sha256:traffic-completeness-request",
            response_status=200,
            response_hash="sha256:traffic-completeness-response",
            actor_ref="oidc:trustai.example/traffic-completeness-worker",
            produced_at="2026-07-03T12:25:00Z",
        )
        result = verify_traffic_completeness_receipt(receipt, traffic_export=traffic_export, provider_export=provider_export)

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(receipt["passed"])
        self.assertEqual(1, receipt["source_completeness"]["extra_provider_record_count"])
        self.assertTrue(any(item["check"] == "extra_provider_records" for item in receipt["violations"]))
        self.assertTrue(result.warnings)

    def test_cli_traffic_completeness_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            traffic_export = self._traffic_export()
            provider_export = self._provider_export(traffic_export)
            traffic_export_path = tmp / "traffic-holdout-export.json"
            provider_export_path = tmp / "traffic-completeness-provider-export.json"
            receipt_path = tmp / "traffic-completeness.json"
            entry_path = tmp / "traffic-completeness-entry.json"
            state_path = tmp / "evidence-chain.json"
            traffic_export_path.write_text(json.dumps(traffic_export, indent=2, sort_keys=True), encoding="utf-8")
            provider_export_path.write_text(json.dumps(provider_export, indent=2, sort_keys=True), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "traffic-completeness",
                    str(traffic_export_path),
                    str(provider_export_path),
                    "--mode",
                    "production-export",
                    "--authority-ref",
                    "authority:traffic-completeness/aitrade-prod",
                    "--endpoint-url",
                    "https://provider.example/aitrade/traffic-holdout/export",
                    "--request-hash",
                    "sha256:traffic-completeness-request",
                    "--response-status",
                    "200",
                    "--response-hash",
                    "sha256:traffic-completeness-response",
                    "--actor-ref",
                    "oidc:trustai.example/traffic-completeness-worker",
                    "--produced-at",
                    "2026-07-03T12:25:00Z",
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "traffic-completeness-verify",
                    str(receipt_path),
                    "--traffic-export",
                    str(traffic_export_path),
                    "--provider-export",
                    str(provider_export_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "traffic-completeness-append",
                    str(receipt_path),
                    "--traffic-export",
                    str(traffic_export_path),
                    "--provider-export",
                    str(provider_export_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "traffic-completeness-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        self.assertEqual(receipt["completeness_id"], entry["payload"]["completeness_id"])

    def test_temporal_holdout_manifest_hash_chains_records(self):
        manifest = build_temporal_holdout_manifest(
            self._contract(),
            self._replay(),
            generated_at="2026-07-03T12:30:00Z",
        )
        result = verify_temporal_holdout_manifest(manifest, contract=self._contract(), replay=self._replay())

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(TEMPORAL_HOLDOUT_SCHEMA, manifest["schema"])
        self.assertEqual(3, manifest["record_count"])
        self.assertTrue(manifest["passed"])
        self.assertEqual([], manifest["violations"])
        self.assertEqual(manifest["records"][-1]["record_node_hash"], manifest["records_root"])
        self.assertIsNone(manifest["records"][0]["previous_record_node_hash"])
        self.assertEqual(
            manifest["records"][0]["record_node_hash"],
            manifest["records"][1]["previous_record_node_hash"],
        )

    def test_temporal_holdout_manifest_appends_to_chain(self):
        manifest = build_temporal_holdout_manifest(
            self._contract(),
            self._replay(),
            generated_at="2026-07-03T12:30:00Z",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="temporal-holdout-test")
            entry = append_temporal_holdout_manifest(chain, manifest, contract=self._contract(), replay=self._replay())

            self.assertEqual(TEMPORAL_HOLDOUT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(manifest["manifest_id"], entry["payload"]["manifest_id"])
            self.assertEqual(manifest["records_root"], entry["payload"]["records_root"])
            self.assertTrue(chain.verify_all().ok)

    def test_shadow_replay_entry_embeds_temporal_holdout_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="shadow-holdout-test")
            entry = append_shadow_replay(chain, self._contract(), self._replay())

            payload = entry["payload"]
            result = verify_temporal_holdout_manifest(
                payload["temporal_holdout_manifest"],
                contract=self._contract(),
                replay=self._replay(),
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(payload["temporal_holdout_manifest"]["manifest_id"], payload["temporal_holdout"]["manifest_id"])
            self.assertEqual(payload["temporal_holdout_manifest"]["records_root"], payload["temporal_holdout"]["records_root"])
            self.assertTrue(payload["temporal_holdout"]["passed"])

    def test_temporal_holdout_manifest_records_boundary_violations(self):
        replay = self._replay()
        replay["records"][0]["timestamp"] = "2026-06-30T23:59:00Z"

        manifest = build_temporal_holdout_manifest(
            self._contract(),
            replay,
            generated_at="2026-07-03T12:30:00Z",
        )
        result = verify_temporal_holdout_manifest(manifest, contract=self._contract(), replay=replay)

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(manifest["passed"])
        self.assertTrue(manifest["violations"])
        self.assertTrue(any("post-freeze" in item["violation"] for item in manifest["violations"]))
        self.assertTrue(result.warnings)

    def test_temporal_holdout_manifest_rejects_source_replay_tamper(self):
        manifest = build_temporal_holdout_manifest(
            self._contract(),
            self._replay(),
            generated_at="2026-07-03T12:30:00Z",
        )
        tampered_replay = self._replay()
        tampered_replay["records"][1]["candidate_action"] = "allow_shadow_order"

        result = verify_temporal_holdout_manifest(manifest, contract=self._contract(), replay=tampered_replay)

        self.assertFalse(result.ok)
        self.assertTrue(any("replay_hash mismatch" in error for error in result.errors))
        self.assertTrue(any("replay record hash mismatch" in error for error in result.errors))

    def test_temporal_holdout_manifest_rejects_manifest_tamper(self):
        manifest = build_temporal_holdout_manifest(
            self._contract(),
            self._replay(),
            generated_at="2026-07-03T12:30:00Z",
        )
        tampered = copy.deepcopy(manifest)
        tampered["records"][0]["timestamp"] = "2026-07-04T00:00:00Z"

        result = verify_temporal_holdout_manifest(tampered, contract=self._contract(), replay=self._replay())

        self.assertFalse(result.ok)
        self.assertTrue(any("manifest_id" in error or "signature" in error for error in result.errors))
        self.assertTrue(any("node hash mismatch" in error for error in result.errors))

    def test_proof_pack_verifier_replays_embedded_temporal_holdout_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="temporal-holdout-pack-test")
            contract = self._contract()
            register_contract(chain, contract)
            replay = self._replay()
            manifest = build_temporal_holdout_manifest(
                contract,
                replay,
                generated_at="2026-07-03T12:30:00Z",
            )
            tampered_replay = self._replay()
            tampered_replay["records"][1]["candidate_action"] = "allow_shadow_order"
            evaluation = evaluate_shadow_replay(contract, tampered_replay)
            chain.append(
                SHADOW_REPLAY_ENTRY_TYPE,
                {
                    **evaluation,
                    "replay_hash": content_hash(tampered_replay),
                    "temporal_holdout_manifest": manifest,
                    "temporal_holdout": {
                        "manifest_id": manifest["manifest_id"],
                        "manifest_hash": content_hash(manifest),
                        "records_root": manifest["records_root"],
                        "record_count": manifest["record_count"],
                        "passed": manifest["passed"],
                    },
                    "replay": tampered_replay,
                },
                timestamp=evaluation["evaluated_at"],
            )
            eval_entry, gate_entry, decision = append_eval_and_gate(
                chain,
                contract,
                shadow_replay_to_eval_results(contract, tampered_replay),
            )
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertTrue(
                any("temporal holdout: temporal holdout replay_hash mismatch" in error for error in result.errors)
            )
            self.assertTrue(any("temporal holdout replay record hash mismatch" in error for error in result.errors))

    def test_cli_temporal_holdout_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest_path = tmp / "temporal-holdout-manifest.json"
            entry_path = tmp / "temporal-holdout-entry.json"
            state_path = tmp / "evidence-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "temporal-holdout-manifest",
                    str(CONTRACT),
                    str(SHADOW),
                    "--generated-at",
                    "2026-07-03T12:30:00Z",
                    "--out",
                    str(manifest_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "temporal-holdout-verify",
                    str(manifest_path),
                    "--contract",
                    str(CONTRACT),
                    "--replay",
                    str(SHADOW),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "temporal-holdout-append",
                    str(manifest_path),
                    "--contract",
                    str(CONTRACT),
                    "--replay",
                    str(SHADOW),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "temporal-holdout-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["manifest_id"], entry["payload"]["manifest_id"])


if __name__ == "__main__":
    unittest.main()
