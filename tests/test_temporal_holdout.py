import copy
import hashlib
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
from trustai.shadow_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENTS,
    SHADOW_AUTHORITY_ENTRY_TYPE,
    SHADOW_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
    SHADOW_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA,
    SHADOW_AUTHORITY_SCHEMA,
    append_shadow_authority_dossier,
    append_shadow_authority_evidence_bundle,
    build_shadow_authority_dossier,
    build_shadow_authority_evidence_bundle,
    shadow_authority_evidence_from_bundle,
    verify_shadow_authority_dossier,
    verify_shadow_authority_evidence_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"

SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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

    def _traffic_completeness_receipt(self, traffic_export: dict | None = None, provider_export: dict | None = None) -> dict:
        traffic_export = traffic_export or self._traffic_export()
        provider_export = provider_export or self._provider_export(traffic_export)
        return build_traffic_completeness_receipt(
            traffic_export,
            provider_export,
            mode="production-export",
            authority_ref="authority:shadow-holdout/provider-completeness-prod",
            endpoint_url="https://authority.trustai.ai/shadow/traffic-completeness",
            request_hash="sha256:traffic-completeness-request",
            response_status=200,
            response_hash="sha256:traffic-completeness-response",
            actor_ref="oidc:trustai.example/traffic-completeness-worker",
            produced_at="2026-07-03T12:25:00Z",
        )

    def _complete_shadow_authority_evidence(self) -> list[dict]:
        rows = []
        for requirement in PRODUCTION_AUTHORITY_REQUIREMENTS:
            requirement_id = requirement["id"]
            authority_kind = requirement["authority_kinds"][0]
            rows.append(
                {
                    "requirement_id": requirement_id,
                    "authority_kind": authority_kind,
                    "evidence_ref": f"authority:shadow/{requirement_id}",
                    "evidence_hash": "sha256:" + content_hash({"shadow_authority_requirement": requirement_id, "authority_kind": authority_kind}),
                    "description": f"Production shadow replay authority evidence for {requirement_id}",
                    "issuer": "TrustAI authority exporter",
                    "subject": f"aitrade shadow temporal holdout {requirement_id}",
                    "source_uri": f"https://authority.trustai.ai/shadow/{requirement_id}",
                    "issued_at": "2026-07-12T00:00:00Z",
                    "expires_at": "2026-08-12T00:00:00Z",
                }
            )
        return rows

    def _shadow_authority_evidence_cli_args(self, evidence: list[dict]) -> list[str]:
        args: list[str] = []
        for item in evidence:
            value = (
                f"{item['requirement_id']},{item['authority_kind']},{item['evidence_ref']},{item['evidence_hash']},"
                f"{item['description']};issuer={item['issuer']};subject={item['subject']};"
                f"source_uri={item['source_uri']};issued_at={item['issued_at']};expires_at={item['expires_at']}"
            )
            args.extend(["--authority-evidence", value])
        return args

    def test_shadow_authority_bundle_drives_complete_production_dossier(self):
        contract = self._contract()
        replay = self._replay()
        temporal = build_temporal_holdout_manifest(contract, replay, generated_at="2026-07-03T12:10:00Z")
        traffic_export = self._traffic_export()
        provider_export = self._provider_export(traffic_export)
        completeness = self._traffic_completeness_receipt(traffic_export, provider_export)
        bundle = build_shadow_authority_evidence_bundle(
            authority_evidence=self._complete_shadow_authority_evidence(),
            mode="production-export",
            environment="aitrade-prod",
            bundle_ref="bundle:shadow/aitrade-prod/20260703",
            issuer_ref="authority:trustai/shadow-exporter",
            subject_ref="agent:aitrade-risk-shadow@2026.07.03",
            authority_ref="authority:shadow-holdout/provider-completeness-prod",
            generated_at="2026-07-19T00:00:00Z",
        )
        bundle_result = verify_shadow_authority_evidence_bundle(
            bundle,
            require_complete=True,
            require_fresh=True,
            now="2026-07-19T00:00:00Z",
        )
        self.assertTrue(bundle_result.ok, bundle_result.errors)
        self.assertEqual(SHADOW_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA, bundle["schema"])

        dossier = build_shadow_authority_dossier(
            contract,
            replay,
            temporal,
            traffic_export,
            completeness,
            provider_export=provider_export,
            mode="production-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:shadow/aitrade-prod/20260703",
            authority_ref="authority:shadow-holdout/provider-completeness-prod",
            producer_ref="service:trustai-shadow-authority",
            authority_evidence=shadow_authority_evidence_from_bundle(
                bundle,
                require_complete=True,
                require_fresh=True,
                now="2026-07-19T00:00:00Z",
            ),
            generated_at="2026-07-19T00:05:00Z",
        )
        result = verify_shadow_authority_dossier(
            dossier,
            contract=contract,
            replay=replay,
            temporal_holdout=temporal,
            traffic_export=traffic_export,
            traffic_completeness=completeness,
            provider_export=provider_export,
            require_complete=True,
            require_fresh=True,
            now="2026-07-19T00:05:00Z",
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(SHADOW_AUTHORITY_SCHEMA, dossier["schema"])
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENTS), result.covered_count)
        self.assertTrue(dossier["source_binding"]["passed"])
        self.assertEqual({"passed": 8}, {control["status"]: sum(1 for item in dossier["controls"] if item["status"] == control["status"]) for control in dossier["controls"]})

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="shadow-authority-test")
            bundle_entry = append_shadow_authority_evidence_bundle(
                chain,
                bundle,
                require_complete=True,
                require_fresh=True,
                now="2026-07-19T00:00:00Z",
            )
            dossier_entry = append_shadow_authority_dossier(
                chain,
                dossier,
                contract=contract,
                replay=replay,
                temporal_holdout=temporal,
                traffic_export=traffic_export,
                traffic_completeness=completeness,
                provider_export=provider_export,
                require_complete=True,
                require_fresh=True,
                now="2026-07-19T00:05:00Z",
            )
            self.assertEqual(SHADOW_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE, bundle_entry["entry_type"])
            self.assertEqual(SHADOW_AUTHORITY_ENTRY_TYPE, dossier_entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)

    def test_shadow_authority_evidence_bundle_detects_placeholder_source_uri(self):
        bundle = build_shadow_authority_evidence_bundle(
            authority_evidence=self._complete_shadow_authority_evidence(),
            mode="production-export",
            environment="aitrade-prod",
            bundle_ref="bundle:shadow/aitrade-prod/placeholder",
            issuer_ref="authority:trustai/shadow-exporter",
            subject_ref="agent:aitrade-risk-shadow@2026.07.03",
            authority_ref="authority:shadow-holdout/provider-completeness-prod",
            generated_at="2026-07-19T00:00:00Z",
        )
        tampered = copy.deepcopy(bundle)
        tampered["authority_evidence"][0]["source_uri"] = "TODO://authority/shadow/placeholder"

        result = verify_shadow_authority_evidence_bundle(
            tampered,
            require_complete=True,
            require_fresh=True,
            now="2026-07-19T00:00:00Z",
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("bundle_id" in error for error in result.errors))
        self.assertTrue(any("live source_uri" in error for error in result.errors))

    def test_cli_shadow_authority_bundle_round_trip(self):
        contract = self._contract()
        replay = self._replay()
        temporal = build_temporal_holdout_manifest(contract, replay, generated_at="2026-07-03T12:10:00Z")
        traffic_export = self._traffic_export()
        provider_export = self._provider_export(traffic_export)
        completeness = self._traffic_completeness_receipt(traffic_export, provider_export)
        evidence = self._complete_shadow_authority_evidence()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            temporal_path = tmp / "temporal-holdout.json"
            traffic_path = tmp / "traffic-export.json"
            provider_path = tmp / "provider-export.json"
            completeness_path = tmp / "traffic-completeness.json"
            bundle_path = tmp / "shadow-authority-bundle.json"
            dossier_path = tmp / "shadow-authority.json"
            entry_path = tmp / "shadow-authority-entry.json"
            state_path = tmp / "evidence-chain.json"
            temporal_path.write_text(json.dumps(temporal, indent=2, sort_keys=True), encoding="utf-8")
            traffic_path.write_text(json.dumps(traffic_export, indent=2, sort_keys=True), encoding="utf-8")
            provider_path.write_text(json.dumps(provider_export, indent=2, sort_keys=True), encoding="utf-8")
            completeness_path.write_text(json.dumps(completeness, indent=2, sort_keys=True), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "shadow-authority-evidence-bundle",
                    "--mode",
                    "production-export",
                    "--environment",
                    "aitrade-prod",
                    "--bundle-ref",
                    "bundle:shadow/cli",
                    "--issuer-ref",
                    "authority:trustai/shadow-exporter",
                    "--subject-ref",
                    "agent:aitrade-risk-shadow@2026.07.03",
                    "--authority-ref",
                    "authority:shadow-holdout/provider-completeness-prod",
                    "--generated-at",
                    "2026-07-19T00:00:00Z",
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-19T00:00:00Z",
                    *self._shadow_authority_evidence_cli_args(evidence),
                    "--out",
                    str(bundle_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "shadow-authority",
                    str(CONTRACT),
                    str(SHADOW),
                    str(temporal_path),
                    str(traffic_path),
                    str(completeness_path),
                    "--provider-export",
                    str(provider_path),
                    "--mode",
                    "production-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:shadow/cli",
                    "--authority-ref",
                    "authority:shadow-holdout/provider-completeness-prod",
                    "--producer-ref",
                    "service:trustai-shadow-authority",
                    "--generated-at",
                    "2026-07-19T00:05:00Z",
                    "--authority-evidence-bundle",
                    str(bundle_path),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-19T00:05:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "shadow-authority-append",
                    str(dossier_path),
                    "--contract",
                    str(CONTRACT),
                    "--replay",
                    str(SHADOW),
                    "--temporal-holdout",
                    str(temporal_path),
                    "--traffic-export",
                    str(traffic_path),
                    "--traffic-completeness",
                    str(completeness_path),
                    "--provider-export",
                    str(provider_path),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-19T00:05:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "shadow-authority-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            self.assertEqual(SHADOW_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(SHADOW_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENTS), dossier["summary"]["covered_requirement_count"])

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

    def test_traffic_holdout_export_replays_retained_source_bytes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            replay_path = Path(tmp_dir) / "shadow-replay.json"
            replay_path.write_text(json.dumps(self._replay(), indent=2, sort_keys=True), encoding="utf-8")
            replay = load_shadow_replay(replay_path)
            receipt = build_traffic_holdout_export(
                self._contract(),
                replay,
                export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
                source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
                exporter_ref="oidc:trustai.example/traffic-exporter",
                window_start="2026-07-02T00:00:00Z",
                window_end="2026-07-03T23:59:59Z",
                produced_at="2026-07-03T12:20:00Z",
                replay_source_path=replay_path,
            )
            result = verify_traffic_holdout_export(receipt, contract=self._contract(), replay=replay, replay_source_path=replay_path)
            artifact_sha = _sha256_ref(replay_path)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(artifact_sha, receipt["replay_source_artifact"]["sha256"])
        self.assertEqual(content_hash(replay), receipt["replay_source_artifact"]["replay_hash"])

    def test_traffic_holdout_export_detects_retained_source_byte_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            replay_path = Path(tmp_dir) / "shadow-replay.json"
            replay_body = self._replay()
            replay_path.write_text(json.dumps(replay_body, indent=2, sort_keys=True), encoding="utf-8")
            replay = load_shadow_replay(replay_path)
            receipt = build_traffic_holdout_export(
                self._contract(),
                replay,
                export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
                source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
                exporter_ref="oidc:trustai.example/traffic-exporter",
                window_start="2026-07-02T00:00:00Z",
                window_end="2026-07-03T23:59:59Z",
                produced_at="2026-07-03T12:20:00Z",
                replay_source_path=replay_path,
            )
            replay_path.write_text(json.dumps(replay_body, indent=4, sort_keys=True), encoding="utf-8")
            result = verify_traffic_holdout_export(receipt, contract=self._contract(), replay=load_shadow_replay(replay_path), replay_source_path=replay_path)

        self.assertFalse(result.ok)
        errors = "\n".join(result.errors)
        self.assertIn("replay_source_artifact", errors)
        self.assertIn("bytes", errors)

    def test_traffic_holdout_export_appends_to_chain(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            replay_path = tmp / "shadow-replay.json"
            replay_path.write_text(json.dumps(self._replay(), indent=2, sort_keys=True), encoding="utf-8")
            replay = load_shadow_replay(replay_path)
            receipt = build_traffic_holdout_export(
                self._contract(),
                replay,
                export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
                source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
                exporter_ref="oidc:trustai.example/traffic-exporter",
                window_start="2026-07-02T00:00:00Z",
                window_end="2026-07-03T23:59:59Z",
                produced_at="2026-07-03T12:20:00Z",
                replay_source_path=replay_path,
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="traffic-holdout-test")
            entry = append_traffic_holdout_export(chain, receipt, contract=self._contract(), replay=replay, replay_source_path=replay_path)

            self.assertEqual(TRAFFIC_HOLDOUT_EXPORT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["export_id"], entry["payload"]["export_id"])
            self.assertEqual(receipt["replay_source_artifact"], entry["payload"]["replay_source_artifact"])
            self.assertEqual(receipt["records_root"], entry["payload"]["records_root"])
            self.assertTrue(chain.verify_all().ok)

    def test_traffic_holdout_export_records_duplicate_replay_ids(self):
        replay = self._replay()
        replay["records"][2]["id"] = replay["records"][0]["id"]
        receipt = build_traffic_holdout_export(
            self._contract(),
            replay,
            export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
            source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
            exporter_ref="oidc:trustai.example/traffic-exporter",
            window_start="2026-07-02T00:00:00Z",
            window_end="2026-07-03T23:59:59Z",
            produced_at="2026-07-03T12:20:00Z",
        )
        result = verify_traffic_holdout_export(receipt, contract=self._contract(), replay=replay)

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(receipt["passed"])
        self.assertTrue(any("duplicate traffic export record id" in item["violation"] for item in receipt["violations"]))
        self.assertTrue(result.warnings)

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

    def test_traffic_completeness_replays_provider_export_artifact_bytes(self):
        traffic_export = self._traffic_export()
        provider_export = self._provider_export(traffic_export)

        with tempfile.TemporaryDirectory() as tmp_dir:
            provider_export_path = Path(tmp_dir) / "traffic-completeness-provider-export.json"
            provider_export_path.write_text(json.dumps(provider_export, indent=2, sort_keys=True), encoding="utf-8")
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
                provider_export_path=provider_export_path,
            )
            result = verify_traffic_completeness_receipt(
                receipt,
                traffic_export=traffic_export,
                provider_export=provider_export,
                provider_export_path=provider_export_path,
            )
            artifact_sha = _sha256_ref(provider_export_path)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(artifact_sha, receipt["provider_export_artifact"]["sha256"])
        self.assertEqual(content_hash(provider_export), receipt["provider_export_artifact"]["content_hash"])
        controls = {control["id"]: control["status"] for control in receipt["controls"]}
        self.assertEqual("passed", controls["provider-export-artifact-replayed"])

    def test_traffic_completeness_detects_provider_export_artifact_byte_tamper(self):
        traffic_export = self._traffic_export()
        provider_export = self._provider_export(traffic_export)

        with tempfile.TemporaryDirectory() as tmp_dir:
            provider_export_path = Path(tmp_dir) / "traffic-completeness-provider-export.json"
            provider_export_path.write_text(json.dumps(provider_export, indent=2, sort_keys=True), encoding="utf-8")
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
                provider_export_path=provider_export_path,
            )
            provider_export_path.write_text(json.dumps(provider_export, indent=4, sort_keys=True), encoding="utf-8")
            result = verify_traffic_completeness_receipt(
                receipt,
                traffic_export=traffic_export,
                provider_export=provider_export,
                provider_export_path=provider_export_path,
            )

        self.assertFalse(result.ok)
        errors = "\n".join(result.errors)
        self.assertIn("provider_export_artifact", errors)
        self.assertIn("bytes", errors)

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
        self.assertEqual(receipt["provider_export_artifact"]["sha256"], entry["payload"]["provider_export_artifact"]["sha256"])

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

    def test_temporal_holdout_manifest_replays_retained_source_bytes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            replay_path = Path(tmp_dir) / "shadow-replay.json"
            replay_path.write_text(json.dumps(self._replay(), indent=2, sort_keys=True), encoding="utf-8")
            replay = load_shadow_replay(replay_path)
            manifest = build_temporal_holdout_manifest(
                self._contract(),
                replay,
                generated_at="2026-07-03T12:30:00Z",
                replay_source_path=replay_path,
            )
            result = verify_temporal_holdout_manifest(
                manifest,
                contract=self._contract(),
                replay=replay,
                replay_source_path=replay_path,
            )
            artifact_sha = _sha256_ref(replay_path)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(artifact_sha, manifest["replay_source_artifact"]["sha256"])
        self.assertEqual(content_hash(replay), manifest["replay_source_artifact"]["replay_hash"])
        self.assertEqual(manifest["record_count"], manifest["replay_source_artifact"]["record_count"])

    def test_temporal_holdout_manifest_detects_retained_source_byte_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            replay_path = Path(tmp_dir) / "shadow-replay.json"
            replay_body = self._replay()
            replay_path.write_text(json.dumps(replay_body, indent=2, sort_keys=True), encoding="utf-8")
            replay = load_shadow_replay(replay_path)
            manifest = build_temporal_holdout_manifest(
                self._contract(),
                replay,
                generated_at="2026-07-03T12:30:00Z",
                replay_source_path=replay_path,
            )
            replay_path.write_text(json.dumps(replay_body, indent=4, sort_keys=True), encoding="utf-8")
            result = verify_temporal_holdout_manifest(
                manifest,
                contract=self._contract(),
                replay=load_shadow_replay(replay_path),
                replay_source_path=replay_path,
            )

        self.assertFalse(result.ok)
        errors = "\n".join(result.errors)
        self.assertIn("replay_source_artifact", errors)
        self.assertIn("bytes", errors)

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

    def test_temporal_holdout_manifest_records_duplicate_replay_ids(self):
        replay = self._replay()
        replay["records"][1]["id"] = replay["records"][0]["id"]

        manifest = build_temporal_holdout_manifest(
            self._contract(),
            replay,
            generated_at="2026-07-03T12:30:00Z",
        )
        result = verify_temporal_holdout_manifest(manifest, contract=self._contract(), replay=replay)
        evaluation = evaluate_shadow_replay(self._contract(), replay)

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(manifest["passed"])
        self.assertFalse(evaluation["holdout"]["passed"])
        self.assertFalse(evaluation["passed"])
        self.assertTrue(any("duplicate replay record id" in item["violation"] for item in manifest["violations"]))
        self.assertTrue(any("duplicate replay record id" in error for error in evaluation["holdout"]["errors"]))
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
        self.assertIn("replay_source_artifact", manifest)
        self.assertEqual(_sha256_ref(SHADOW), manifest["replay_source_artifact"]["sha256"])
        self.assertEqual(manifest["replay_source_artifact"], entry["payload"]["replay_source_artifact"])


if __name__ == "__main__":
    unittest.main()
