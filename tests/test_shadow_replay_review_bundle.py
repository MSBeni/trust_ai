import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.lifecycle import append_soak_failure_demotion, build_soak_demotion_receipt
from trustai.reexecution import build_reexecution_report, load_eval_results, write_reexecution_report
from trustai.shadow import (
    append_soak_report,
    build_temporal_holdout_manifest,
    build_traffic_completeness_receipt,
    build_traffic_holdout_export,
    load_shadow_replay,
    load_soak_window,
    load_traffic_completeness_provider_export,
    write_temporal_holdout_manifest,
    write_traffic_completeness_receipt,
    write_traffic_holdout_export,
)
from trustai.shadow_replay_review_bundle import (
    SHADOW_REPLAY_REVIEW_BUNDLE_ENTRY_TYPE,
    SHADOW_REPLAY_REVIEW_BUNDLE_SCHEMA,
    append_shadow_replay_review_bundle,
    build_shadow_replay_review_bundle,
    extract_shadow_replay_review_bundle_sources,
    render_shadow_replay_review_bundle_markdown,
    verify_shadow_replay_review_bundle,
    write_shadow_replay_review_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
PROVIDER_EXPORT = ROOT / "examples" / "aitrade" / "traffic-completeness-provider-export.json"
FAILED_SOAK = ROOT / "examples" / "aitrade" / "failed-soak-window.json"
RUNS = [
    ROOT / "examples" / "aitrade" / "eval-results.json",
    ROOT / "examples" / "aitrade" / "eval-results-reexecution-2.json",
    ROOT / "examples" / "aitrade" / "eval-results-reexecution-3.json",
]


class ShadowReplayReviewBundleTests(unittest.TestCase):
    def _write_json(self, path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")

    def _sources(self, tmp: Path) -> dict:
        contract = load_contract(CONTRACT)
        replay = load_shadow_replay(SHADOW)
        temporal = build_temporal_holdout_manifest(
            contract,
            replay,
            generated_at="2026-07-03T12:10:00Z",
            replay_source_path=SHADOW,
        )
        traffic = build_traffic_holdout_export(
            contract,
            replay,
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
        provider_export = load_traffic_completeness_provider_export(PROVIDER_EXPORT)
        completeness = build_traffic_completeness_receipt(
            traffic,
            provider_export,
            mode="production-export",
            authority_ref="authority:shadow-holdout/provider-completeness-prod",
            endpoint_url="https://authority.trustai.ai/shadow/traffic-completeness",
            request_hash="sha256:traffic-completeness-request",
            response_status=200,
            response_hash="sha256:traffic-completeness-response",
            actor_ref="oidc:trustai.example/traffic-completeness-worker",
            produced_at="2026-07-03T12:25:00Z",
            provider_export_path=PROVIDER_EXPORT,
        )
        report = build_reexecution_report(
            contract,
            [load_eval_results(path) for path in RUNS],
            temperature=0,
            required_pass_rate=1.0,
            generated_at="2026-07-03T12:30:00Z",
        )

        chain = EvidenceChain.load(tmp / "soak-chain.json", tenant_id="shadow-review-soak")
        register_contract(chain, contract)
        soak_entry = append_soak_report(chain, contract, load_soak_window(FAILED_SOAK))
        demotion_entry = append_soak_failure_demotion(chain, contract, soak_entry)
        soak_demotion = build_soak_demotion_receipt(
            contract,
            soak_entry,
            demotion_entry,
            attested_at="2026-07-04T01:00:00Z",
        )

        paths = {
            "contract": CONTRACT,
            "replay": SHADOW,
            "temporal_holdout": tmp / "temporal-holdout.json",
            "traffic_export": tmp / "traffic-holdout-export.json",
            "traffic_completeness": tmp / "traffic-completeness.json",
            "provider_export": PROVIDER_EXPORT,
            "reexecution_report": tmp / "reexecution-report.json",
            "soak_entry": tmp / "soak-entry.json",
            "demotion_entry": tmp / "demotion-entry.json",
            "soak_demotion": tmp / "soak-demotion.json",
        }
        write_temporal_holdout_manifest(paths["temporal_holdout"], temporal)
        write_traffic_holdout_export(paths["traffic_export"], traffic)
        write_traffic_completeness_receipt(paths["traffic_completeness"], completeness)
        write_reexecution_report(paths["reexecution_report"], report)
        self._write_json(paths["soak_entry"], soak_entry)
        self._write_json(paths["demotion_entry"], demotion_entry)
        self._write_json(paths["soak_demotion"], soak_demotion)
        return {
            "contract": contract,
            "replay": replay,
            "temporal_holdout": temporal,
            "traffic_export": traffic,
            "traffic_completeness": completeness,
            "provider_export": provider_export,
            "reexecution_report": report,
            "soak_entry": soak_entry,
            "demotion_entry": demotion_entry,
            "soak_demotion": soak_demotion,
            "paths": paths,
        }

    def test_shadow_replay_review_bundle_replays_embedded_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)

            bundle = build_shadow_replay_review_bundle(
                sources["contract"],
                sources["replay"],
                sources["temporal_holdout"],
                sources["traffic_export"],
                sources["traffic_completeness"],
                sources["provider_export"],
                artifact_paths=sources["paths"],
                reexecution_report=sources["reexecution_report"],
                soak_entry=sources["soak_entry"],
                demotion_entry=sources["demotion_entry"],
                soak_demotion=sources["soak_demotion"],
                mode="auditor-review",
                reviewer_ref="auditor:model-risk",
                bundle_ref="shadow-review:aitrade:20260703",
                generated_at="2026-07-04T02:00:00Z",
            )
            result = verify_shadow_replay_review_bundle(bundle)
            markdown = render_shadow_replay_review_bundle_markdown(bundle)
            chain = EvidenceChain.load(tmp / "review-chain.json", tenant_id="shadow-review")
            entry = append_shadow_replay_review_bundle(chain, bundle)
            extracted = extract_shadow_replay_review_bundle_sources(bundle, tmp / "sources")

            self.assertEqual(SHADOW_REPLAY_REVIEW_BUNDLE_SCHEMA, bundle["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("auditor-review", bundle["mode"])
            self.assertTrue(bundle["source"]["passed"])
            self.assertEqual(10, bundle["summary"]["source_artifact_count"])
            self.assertTrue(bundle["summary"]["reexecution_report_embedded"])
            self.assertTrue(bundle["summary"]["soak_demotion_replay_embedded"])
            self.assertEqual(SHADOW_REPLAY_REVIEW_BUNDLE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
            self.assertEqual(10, len(extracted))
            self.assertIn("TrustAI Shadow Replay Review Bundle", markdown)

    def test_shadow_replay_review_bundle_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            bundle = build_shadow_replay_review_bundle(
                sources["contract"],
                sources["replay"],
                sources["temporal_holdout"],
                sources["traffic_export"],
                sources["traffic_completeness"],
                sources["provider_export"],
                artifact_paths=sources["paths"],
                reviewer_ref="auditor:model-risk",
                generated_at="2026-07-04T02:00:00Z",
            )
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["provider_export"]["stream_records"][0]["offset"] = 999

            result = verify_shadow_replay_review_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("bundle_id" in error for error in result.errors))
            self.assertTrue(any("does not match embedded source: provider_export" in error for error in result.errors))

    def test_shadow_replay_review_bundle_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            bundle_path = tmp / "shadow-review.json"
            markdown_path = tmp / "shadow-review.md"
            entry_path = tmp / "shadow-review-entry.json"
            extract_dir = tmp / "extracted"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT / "src")

            build_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "shadow-replay-review-bundle",
                str(CONTRACT),
                str(SHADOW),
                str(sources["paths"]["temporal_holdout"]),
                str(sources["paths"]["traffic_export"]),
                str(sources["paths"]["traffic_completeness"]),
                str(PROVIDER_EXPORT),
                "--reexecution-report",
                str(sources["paths"]["reexecution_report"]),
                "--soak-entry",
                str(sources["paths"]["soak_entry"]),
                "--demotion-entry",
                str(sources["paths"]["demotion_entry"]),
                "--soak-demotion",
                str(sources["paths"]["soak_demotion"]),
                "--reviewer-ref",
                "auditor:model-risk",
                "--bundle-ref",
                "shadow-review:aitrade:cli",
                "--generated-at",
                "2026-07-04T02:00:00Z",
                "--out",
                str(bundle_path),
                "--markdown",
                str(markdown_path),
            ]
            subprocess.run(build_cmd, cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            subprocess.run(
                [sys.executable, "-m", "trustai", "shadow-replay-review-bundle-verify", str(bundle_path)],
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
                    "shadow-replay-review-bundle-extract",
                    str(bundle_path),
                    "--out-dir",
                    str(extract_dir),
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
                    "shadow-replay-review-bundle-append",
                    str(bundle_path),
                    "--state",
                    str(tmp / "chain.json"),
                    "--tenant",
                    "shadow-review-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
            self.assertTrue(markdown_path.exists())
            self.assertTrue((extract_dir / "replay.json").exists())


if __name__ == "__main__":
    unittest.main()
