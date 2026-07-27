import base64
import copy
import json
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
import unittest
from pathlib import Path

from trustai.canonical import content_hash, file_sha256_ref, without_keys
from trustai.chain import EvidenceChain
from trustai.external_evidence import (
    EXTERNAL_EVIDENCE_ENTRY_TYPE,
    EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE,
    EXTERNAL_EVIDENCE_SCHEMA,
    EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA,
    EXTERNAL_EVIDENCE_INTAKE_SCHEMA,
    EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA,
    EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA,
    EXTERNAL_EVIDENCE_COLLECTION_RUN_SCHEMA,
    EXTERNAL_EVIDENCE_GAP_REPORT_SCHEMA,
    EXTERNAL_EVIDENCE_WORK_PACKAGE_SCHEMA,
    EXTERNAL_EVIDENCE_OWNER_PACKET_SCHEMA,
    EXTERNAL_EVIDENCE_OWNER_PACKET_STATUS_SCHEMA,
    EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_TEMPLATE_SCHEMA,
    EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_REVIEW_SCHEMA,
    EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_CLOSURE_SCHEMA,
    EXTERNAL_EVIDENCE_READINESS_SCHEMA,
    EXTERNAL_EVIDENCE_GIT_REMOTE_REF_EXPORT_SCHEMA,
    ROADMAP_EVIDENCE_REPORT_SCHEMA,
    ROADMAP_EVIDENCE_BUNDLE_SCHEMA,
    _allowed_authority_kinds_for_requirement,
    _authority_unit_id,
    append_external_evidence_collection_run,
    append_external_evidence_manifest,
    build_external_evidence_manifest,
    build_external_evidence_manifest_from_intakes,
    build_external_evidence_collection_plan,
    build_external_evidence_gap_report,
    build_external_evidence_work_package,
    build_external_evidence_owner_packets,
    build_external_evidence_owner_packet_status,
    build_external_evidence_owner_fulfillment_template,
    build_external_evidence_owner_fulfillment_review,
    build_external_evidence_owner_fulfillment_closure,
    build_external_evidence_readiness_report,
    build_external_evidence_intake,
    build_external_evidence_source_snapshot,
    build_external_evidence_source_map_template,
    fulfill_external_evidence_source_map,
    build_roadmap_evidence_bundle,
    extract_roadmap_evidence_bundle_sources,
    build_roadmap_evidence_report,
    load_roadmap_evidence_report,
    load_external_evidence_manifest,
    load_external_evidence_collection_plan,
    load_external_evidence_collection_run,
    load_external_evidence_gap_report,
    load_external_evidence_work_package,
    load_external_evidence_owner_packets,
    load_external_evidence_owner_packet_status,
    load_external_evidence_owner_fulfillment_template,
    load_external_evidence_owner_fulfillment_review,
    load_external_evidence_owner_fulfillment_closure,
    load_external_evidence_readiness_report,
    load_external_evidence_intake,
    load_external_evidence_intakes,
    load_external_evidence_source_snapshot,
    load_roadmap_evidence_bundle,
    parse_evidence_arg,
    parse_bundle_source_artifact_arg,
    parse_source_map_fulfillment_arg,
    render_external_evidence_markdown,
    render_external_evidence_collection_plan_markdown,
    render_external_evidence_work_package_markdown,
    render_external_evidence_owner_packets_markdown,
    render_external_evidence_owner_packet_status_markdown,
    render_external_evidence_owner_fulfillment_template_markdown,
    render_external_evidence_owner_fulfillment_review_markdown,
    render_external_evidence_owner_fulfillment_closure_markdown,
    render_external_evidence_readiness_markdown,
    render_roadmap_evidence_markdown,
    render_roadmap_evidence_bundle_markdown,
    verify_external_evidence_manifest,
    verify_external_evidence_gap_report,
    verify_external_evidence_work_package,
    verify_external_evidence_owner_packets,
    verify_external_evidence_owner_packet_status,
    verify_external_evidence_owner_fulfillment_template,
    verify_external_evidence_owner_fulfillment_review,
    verify_external_evidence_owner_fulfillment_closure,
    verify_external_evidence_readiness_report,
    verify_external_evidence_collection_plan,
    verify_external_evidence_source_map_template,
    verify_external_evidence_collection_run,
    verify_external_evidence_intake,
    verify_external_evidence_source_snapshot,
    verify_roadmap_evidence_chain,
    verify_roadmap_evidence_bundle,
    verify_roadmap_evidence_report,
    write_external_evidence_collection_plan,
    write_external_evidence_gap_report,
    write_external_evidence_manifest,
    write_external_evidence_source_snapshot,
)
from trustai.roadmap_audit import STATUS_REFERENCE_ATTESTED, append_roadmap_audit, build_roadmap_audit, verify_roadmap_audit, write_roadmap_audit


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "examples/aitrade/external-evidence/go-verifier-workflow-run.json"


class ExternalEvidenceManifestTests(unittest.TestCase):
    def test_partial_external_evidence_manifest_verifies_with_warnings(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )
        result = verify_external_evidence_manifest(manifest, audit, root=ROOT)
        strict_result = verify_external_evidence_manifest(manifest, audit, root=ROOT, require_complete=True)
        markdown = render_external_evidence_markdown(manifest)

        self.assertEqual(EXTERNAL_EVIDENCE_SCHEMA, manifest["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertFalse(strict_result.ok)
        self.assertTrue(any("incomplete" in error for error in strict_result.errors))
        self.assertEqual("partial", manifest["summary"]["status"])
        self.assertIn("TrustAI External Evidence Manifest", markdown)
        self.assertIn("Required External Evidence", markdown)
        self.assertIn("Accepted Authorities", markdown)
        self.assertIn("Covered Authorities", markdown)
        self.assertIn("Missing Authorities", markdown)
        self.assertIn("Authority Evidence Needed", markdown)
        self.assertIn("Authority Coverage Units", markdown)
        self.assertIn("Unit ID", markdown)
        self.assertIn("Unit Ref", markdown)
        self.assertIn("oss-verifier-and-public-spec", markdown)
        self.assertIn("self-serve-onboarding", markdown)
        self.assertIn("`ci-run`", markdown)
        required = next(
            item
            for item in manifest["required_external_requirements"]
            if item["id"] == "oss-verifier-and-public-spec"
        )
        self.assertIn("ci-run", required["allowed_authority_kinds"])
        self.assertEqual(
            required["allowed_authority_kinds"],
            manifest["evidence"][0]["accepted_authority_kinds"],
        )
        self.assertEqual(["ci-run"], manifest["summary"]["covered_authority_kinds_by_requirement"]["oss-verifier-and-public-spec"])
        self.assertNotIn(
            "ci-run",
            manifest["summary"]["missing_authority_kinds_by_requirement"].get("oss-verifier-and-public-spec", []),
        )
        self.assertGreater(manifest["summary"]["missing_authority_kind_count"], 0)
        self.assertEqual(
            manifest["summary"]["required_authority_kind_count"],
            len(manifest["required_authority_evidence_units"]),
        )
        ci_unit = next(
            item
            for item in manifest["required_authority_evidence_units"]
            if item["requirement_id"] == "oss-verifier-and-public-spec" and item["authority_kind"] == "ci-run"
        )
        provider_unit = next(
            item
            for item in manifest["required_authority_evidence_units"]
            if item["requirement_id"] == "oss-verifier-and-public-spec" and item["authority_kind"] == "provider-api"
        )
        self.assertEqual(_authority_unit_id("oss-verifier-and-public-spec", "ci-run"), ci_unit["unit_id"])
        self.assertEqual("oss-verifier-and-public-spec:ci-run", ci_unit["unit_ref"])
        self.assertEqual("covered", ci_unit["coverage_status"])
        self.assertEqual("missing", provider_unit["coverage_status"])
        self.assertIn(ci_unit["unit_id"], markdown)
        self.assertIn(ci_unit["unit_ref"], markdown)

    def test_external_evidence_collection_plan_exports_missing_authority_tasks(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )

        plan = build_external_evidence_collection_plan(
            manifest,
            audit,
            root=ROOT,
            status_filter="missing",
            generated_at="2026-07-09T00:00:00Z",
        )
        result = verify_external_evidence_collection_plan(plan, manifest, audit, root=ROOT)
        markdown = render_external_evidence_collection_plan_markdown(plan)

        self.assertEqual(EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA, plan["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(manifest["summary"]["missing_authority_kind_count"], plan["summary"]["selected_task_count"])
        self.assertEqual(70, plan["summary"]["selected_missing_task_count"])
        self.assertEqual(0, plan["summary"]["selected_covered_task_count"])
        self.assertFalse(any(task["coverage_status"] == "covered" for task in plan["tasks"]))
        provider_task = next(
            task
            for task in plan["tasks"]
            if task["unit_ref"] == "oss-verifier-and-public-spec:provider-api"
        )
        self.assertEqual("integration/platform owner", provider_task["owner_hint"])
        self.assertEqual("external-evidence/oss-verifier-and-public-spec/provider-api.json", provider_task["suggested_artifact_path"])
        self.assertIn("issuer=<issuer>", provider_task["evidence_argument_template"])
        self.assertIn("External Evidence Collection Plan", markdown)
        self.assertIn("oss-verifier-and-public-spec:provider-api", markdown)

        all_plan = build_external_evidence_collection_plan(
            manifest,
            audit,
            root=ROOT,
            status_filter="all",
            generated_at="2026-07-09T00:00:00Z",
        )
        self.assertEqual(manifest["summary"]["required_authority_kind_count"], all_plan["summary"]["selected_task_count"])
        self.assertTrue(any(task["unit_ref"] == "oss-verifier-and-public-spec:ci-run" and task["coverage_status"] == "covered" for task in all_plan["tasks"]))

        tampered = copy.deepcopy(plan)
        tampered["tasks"][0]["owner_hint"] = "wrong owner"
        tampered["plan_id"] = content_hash(without_keys(tampered, "plan_id"))
        tampered_result = verify_external_evidence_collection_plan(tampered, manifest, audit, root=ROOT)
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("collection plan body" in error for error in tampered_result.errors), tampered_result.errors)

    def test_cli_external_evidence_source_map_template_exports_batch_entries(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            audit_path = tmp_path / "roadmap-audit.json"
            manifest_path = tmp_path / "external-evidence-manifest.json"
            plan_path = tmp_path / "external-evidence-plan-all.json"
            source_map_path = tmp_path / "external-evidence-source-map-template.json"

            audit = build_roadmap_audit(ROOT)
            manifest = build_external_evidence_manifest(
                audit,
                root=ROOT,
                evidence=[
                    {
                        "requirement_id": "oss-verifier-and-public-spec",
                        "authority_kind": "ci-run",
                        "path": FIXTURE,
                        "description": "Recorded verifier workflow run export.",
                    }
                ],
                generated_at="2026-07-09T00:00:00Z",
            )
            plan = build_external_evidence_collection_plan(
                manifest,
                audit,
                root=ROOT,
                status_filter="all",
                generated_at="2026-07-09T00:00:00Z",
            )
            write_roadmap_audit(audit_path, audit)
            write_external_evidence_manifest(manifest_path, manifest)
            write_external_evidence_collection_plan(plan_path, plan)

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-source-map-template",
                    str(plan_path),
                    "--status-filter",
                    "missing",
                    "--authority-kind",
                    "provider-api",
                    "--limit",
                    "1",
                    "--source-uri-template",
                    "https://provider.example/{requirement_id}/{authority_kind}/{unit_id}",
                    "--description-template",
                    "{authority_kind} provider export for {requirement_id}",
                    "--source-file",
                    FIXTURE,
                    "--issuer",
                    "Provider API",
                    "--subject",
                    "trustai provider evidence exports",
                    "--content-type",
                    "application/json",
                    "--issued-at",
                    "2026-07-08T00:00:00Z",
                    "--expires-at",
                    "2026-12-31T00:00:00Z",
                    "--snapshot-dir",
                    "artifacts/source-map-template-sources",
                    "--intake-dir",
                    "artifacts/source-map-template-intakes",
                    "--generated-at",
                    "2026-07-09T00:00:00Z",
                    "--out",
                    str(source_map_path),
                ],
                cwd=ROOT,
                check=True,
            )
            source_map = json.loads(source_map_path.read_text(encoding="utf-8"))
            entry = source_map["entries"][0]

            self.assertEqual(EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA, source_map["schema"])
            self.assertEqual(content_hash(without_keys(source_map, "source_map_id")), source_map["source_map_id"])
            self.assertEqual(1, source_map["summary"]["entry_count"])
            self.assertEqual(1, source_map["summary"]["placeholder_source_uri_count"])
            self.assertEqual(0, source_map["summary"]["live_source_uri_count"])
            self.assertEqual(["provider-api"], source_map["summary"]["authority_kinds"])
            self.assertEqual(FIXTURE, source_map["defaults"]["source_file"])
            self.assertEqual("Provider API", source_map["defaults"]["issuer"])
            self.assertEqual("oss-verifier-and-public-spec:provider-api", entry["task"])
            self.assertEqual("external-evidence:oss-verifier-and-public-spec:provider-api", entry["task_ref"])
            self.assertEqual("provider-api", entry["authority_kind"])
            self.assertEqual(
                "https://provider.example/oss-verifier-and-public-spec/provider-api/" + entry["unit_id"],
                entry["source_uri"],
            )
            self.assertEqual(
                "artifacts/source-map-template-sources/oss-verifier-and-public-spec/provider-api.json",
                entry["snapshot_out"],
            )
            self.assertEqual(
                "artifacts/source-map-template-intakes/oss-verifier-and-public-spec/provider-api.json",
                entry["intake_out"],
            )

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-source-map-verify",
                    str(source_map_path),
                    str(plan_path),
                ],
                cwd=ROOT,
                check=True,
            )
            verify_result = verify_external_evidence_source_map_template(source_map, plan)
            self.assertTrue(verify_result.ok, verify_result.errors)
            self.assertEqual(1, verify_result.entry_count)
            gap_report = build_external_evidence_gap_report(
                manifest,
                plan,
                source_map,
                audit,
                root=ROOT,
                generated_at="2026-07-09T00:01:00Z",
            )
            gap = gap_report["gaps"][0]
            self.assertEqual(FIXTURE, gap["source_file"])
            self.assertEqual("Provider API", gap["issuer"])
            self.assertEqual("trustai provider evidence exports", gap["subject"])
            self.assertEqual("application/json", gap["content_type"])
            self.assertEqual("provider-api provider export for oss-verifier-and-public-spec", gap["description"])
            strict_result = verify_external_evidence_source_map_template(
                source_map,
                plan,
                require_live_source_uris=True,
            )
            self.assertFalse(strict_result.ok)
            self.assertTrue(any("live source URIs" in error for error in strict_result.errors), strict_result.errors)
            strict_cli = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-source-map-verify",
                    str(source_map_path),
                    str(plan_path),
                    "--require-live-source-uris",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, strict_cli.returncode)
            self.assertIn("live source URIs", strict_cli.stderr)

            fulfillment = parse_source_map_fulfillment_arg(
                "oss-verifier-and-public-spec:provider-api;"
                "source_uri=https://github.com/MSBeni/trust_ai/actions/runs/1234567890;"
                "description=GitHub Actions provider export for TrustAI source-map fulfillment;"
                "issuer=GitHub Actions;"
                "subject=trustai provider evidence export;"
                "issued_at=2026-07-08T00:00:00Z;"
                "expires_at=2026-12-31T00:00:00Z"
            )
            fulfilled = fulfill_external_evidence_source_map(
                source_map,
                [fulfillment],
                generated_at="2026-07-10T00:00:00Z",
            )
            fulfilled_entry = fulfilled["entries"][0]
            self.assertEqual(content_hash(without_keys(fulfilled, "source_map_id")), fulfilled["source_map_id"])
            self.assertEqual(0, fulfilled["summary"]["placeholder_source_uri_count"])
            self.assertEqual(1, fulfilled["summary"]["live_source_uri_count"])
            self.assertEqual("GitHub Actions", fulfilled_entry["issuer"])
            self.assertEqual("trustai provider evidence export", fulfilled_entry["subject"])
            self.assertEqual("2026-07-08T00:00:00Z", fulfilled_entry["issued_at"])
            self.assertEqual("2026-12-31T00:00:00Z", fulfilled_entry["expires_at"])
            strict_fulfilled = verify_external_evidence_source_map_template(
                fulfilled,
                plan,
                require_live_source_uris=True,
            )
            self.assertTrue(strict_fulfilled.ok, strict_fulfilled.errors)
            missing_snapshot_result = verify_external_evidence_source_map_template(
                fulfilled,
                plan,
                root=tmp_path,
                require_live_source_uris=True,
                require_source_snapshots=True,
            )
            self.assertFalse(missing_snapshot_result.ok)
            self.assertTrue(any("snapshot_out does not exist" in error for error in missing_snapshot_result.errors), missing_snapshot_result.errors)

            snapshot_path = tmp_path / fulfilled_entry["snapshot_out"]
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            snapshot = build_external_evidence_source_snapshot(
                source_uri=fulfilled_entry["source_uri"],
                body=b'{"ok": true}\n',
                retrieval_method="http-get",
                content_type="application/json",
                status_code=200,
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-12-31T00:00:00Z",
            )
            snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
            strict_snapshot_result = verify_external_evidence_source_map_template(
                fulfilled,
                plan,
                root=tmp_path,
                require_live_source_uris=True,
                require_source_snapshots=True,
            )
            self.assertTrue(strict_snapshot_result.ok, strict_snapshot_result.errors)
            fresh_without_snapshot_result = verify_external_evidence_source_map_template(
                fulfilled,
                plan,
                root=tmp_path,
                require_fresh_source_snapshots=True,
                now="2026-07-12T00:00:00Z",
            )
            self.assertFalse(fresh_without_snapshot_result.ok)
            self.assertTrue(any("requires --require-source-snapshots" in error for error in fresh_without_snapshot_result.errors), fresh_without_snapshot_result.errors)
            fresh_snapshot_result = verify_external_evidence_source_map_template(
                fulfilled,
                plan,
                root=tmp_path,
                require_live_source_uris=True,
                require_source_snapshots=True,
                require_fresh_source_snapshots=True,
                now="2026-07-12T00:00:00Z",
            )
            self.assertTrue(fresh_snapshot_result.ok, fresh_snapshot_result.errors)
            expired_snapshot = copy.deepcopy(snapshot)
            expired_snapshot["expires_at"] = "2026-07-11T00:00:00Z"
            expired_snapshot["snapshot_id"] = content_hash(without_keys(expired_snapshot, "snapshot_id"))
            snapshot_path.write_text(json.dumps(expired_snapshot, indent=2, sort_keys=True), encoding="utf-8")
            expired_snapshot_result = verify_external_evidence_source_map_template(
                fulfilled,
                plan,
                root=tmp_path,
                require_live_source_uris=True,
                require_source_snapshots=True,
                require_fresh_source_snapshots=True,
                now="2026-07-12T00:00:00Z",
            )
            self.assertFalse(expired_snapshot_result.ok)
            self.assertTrue(any("snapshot expired" in error for error in expired_snapshot_result.errors), expired_snapshot_result.errors)
            snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
            failed_status_snapshot = copy.deepcopy(snapshot)
            failed_status_snapshot["status_code"] = 500
            failed_status_snapshot["snapshot_id"] = content_hash(without_keys(failed_status_snapshot, "snapshot_id"))
            snapshot_path.write_text(json.dumps(failed_status_snapshot, indent=2, sort_keys=True), encoding="utf-8")
            failed_status_result = verify_external_evidence_source_map_template(
                fulfilled,
                plan,
                root=tmp_path,
                require_live_source_uris=True,
                require_source_snapshots=True,
            )
            self.assertFalse(failed_status_result.ok)
            self.assertTrue(any("status_code is not successful" in error for error in failed_status_result.errors), failed_status_result.errors)
            snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")

            fulfilled_path = tmp_path / "external-evidence-source-map-fulfilled.json"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-source-map-fulfill",
                    str(source_map_path),
                    str(plan_path),
                    "--root",
                    str(tmp_path),
                    "--fulfillment",
                    "oss-verifier-and-public-spec:provider-api;source_uri=https://github.com/MSBeni/trust_ai/actions/runs/1234567890;description=GitHub Actions provider export for TrustAI source-map fulfillment",
                    "--generated-at",
                    "2026-07-10T00:00:00Z",
                    "--require-live-source-uris",
                    "--require-source-snapshots",
                    "--require-fresh-source-snapshots",
                    "--now",
                    "2026-07-12T00:00:00Z",
                    "--out",
                    str(fulfilled_path),
                ],
                cwd=ROOT,
                check=True,
            )
            fulfilled_cli = json.loads(fulfilled_path.read_text(encoding="utf-8"))
            self.assertEqual(0, fulfilled_cli["summary"]["placeholder_source_uri_count"])
            self.assertEqual(1, fulfilled_cli["summary"]["live_source_uri_count"])

            tampered = copy.deepcopy(source_map)
            tampered["entries"][0]["snapshot_out"] = "artifacts/wrong.json"
            tampered["source_map_id"] = content_hash(without_keys(tampered, "source_map_id"))
            tampered_result = verify_external_evidence_source_map_template(tampered, plan)
            self.assertFalse(tampered_result.ok)
            self.assertTrue(any("snapshot_out" in error for error in tampered_result.errors), tampered_result.errors)

    def test_external_evidence_work_package_groups_gap_tasks_by_owner_and_cli_verifies(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
            generated_at="2026-07-09T00:00:00Z",
        )
        plan = build_external_evidence_collection_plan(
            manifest,
            audit,
            root=ROOT,
            status_filter="missing",
            generated_at="2026-07-09T00:00:00Z",
        )
        source_map = build_external_evidence_source_map_template(
            plan,
            status_filter="missing",
            authority_kinds=["provider-api"],
            source_uri_template="TODO://authority/{requirement_id}/{authority_kind}",
            description_template="{authority_kind} provider export for {requirement_id}",
            limit=2,
            generated_at="2026-07-09T00:01:00Z",
        )
        gap_report = build_external_evidence_gap_report(
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
            generated_at="2026-07-09T00:02:00Z",
        )
        command_context = {
            "python": sys.executable,
            "manifest_path": "manifest.json",
            "plan_path": "plan.json",
            "source_map_path": "source-map.json",
            "roadmap_audit_path": "roadmap-audit.json",
            "intake_dir": "artifacts/intakes",
        }

        work_package = build_external_evidence_work_package(
            gap_report,
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
            group_by="owner_hint",
            command_context=command_context,
            generated_at="2026-07-09T00:03:00Z",
        )
        result = verify_external_evidence_work_package(
            work_package,
            gap_report,
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
        )
        markdown = render_external_evidence_work_package_markdown(work_package)

        self.assertEqual(EXTERNAL_EVIDENCE_WORK_PACKAGE_SCHEMA, work_package["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(content_hash(without_keys(work_package, "work_package_id")), work_package["work_package_id"])
        self.assertEqual("owner_hint", work_package["group_by"])
        self.assertEqual(1, work_package["summary"]["package_count"])
        self.assertEqual(2, work_package["summary"]["task_count"])
        self.assertEqual(2, work_package["summary"]["placeholder_source_uri_count"])
        package = work_package["packages"][0]
        self.assertEqual("integration/platform owner", package["group_key"])
        self.assertEqual("integration/platform owner", package["owner_hint"])
        self.assertEqual(["provider-api"], package["authority_kinds"])
        self.assertIn("external-evidence-manifest-from-intakes", package["commands"]["rebuild_manifest_command"])
        task = package["tasks"][0]
        self.assertEqual("placeholder", task["source_uri_status"])
        self.assertIn("--snapshot-out", task["commands"]["collect_args"])
        self.assertIn("external-evidence-collect", task["commands"]["collect_command"])
        self.assertTrue(any("placeholder source_uri" in action for action in task["next_actions"]))
        self.assertIn("External Evidence Work Packages", markdown)
        self.assertIn("integration/platform owner", markdown)

        tampered = copy.deepcopy(work_package)
        tampered["packages"][0]["tasks"][0]["owner_hint"] = "wrong owner"
        tampered["work_package_id"] = content_hash(without_keys(tampered, "work_package_id"))
        tampered_result = verify_external_evidence_work_package(
            tampered,
            gap_report,
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
        )
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("work package body" in error for error in tampered_result.errors), tampered_result.errors)

        tampered = copy.deepcopy(work_package)
        tampered["packages"][0]["owner_hint"] = "wrong owner"
        tampered["work_package_id"] = content_hash(without_keys(tampered, "work_package_id"))
        tampered_result = verify_external_evidence_work_package(
            tampered,
            gap_report,
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
        )
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("work package body" in error for error in tampered_result.errors), tampered_result.errors)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            audit_path = tmp_path / "roadmap-audit.json"
            manifest_path = tmp_path / "manifest.json"
            plan_path = tmp_path / "plan.json"
            source_map_path = tmp_path / "source-map.json"
            gap_report_path = tmp_path / "gap-report.json"
            work_package_path = tmp_path / "work-package.json"
            markdown_path = tmp_path / "work-package.md"
            write_roadmap_audit(audit_path, audit)
            write_external_evidence_manifest(manifest_path, manifest)
            write_external_evidence_collection_plan(plan_path, plan)
            source_map_path.write_text(json.dumps(source_map, indent=2, sort_keys=True), encoding="utf-8")
            write_external_evidence_gap_report(gap_report_path, gap_report)

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-work-package",
                    str(gap_report_path),
                    str(manifest_path),
                    str(plan_path),
                    str(source_map_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--group-by",
                    "authority_kind",
                    "--python",
                    sys.executable,
                    "--generated-at",
                    "2026-07-09T00:04:00Z",
                    "--out",
                    str(work_package_path),
                    "--markdown",
                    str(markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            cli_package = load_external_evidence_work_package(work_package_path)
            self.assertEqual("authority_kind", cli_package["group_by"])
            self.assertEqual(1, cli_package["summary"]["package_count"])
            self.assertTrue(markdown_path.exists())
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-work-package-verify",
                    str(work_package_path),
                    str(gap_report_path),
                    str(manifest_path),
                    str(plan_path),
                    str(source_map_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                ],
                cwd=ROOT,
                check=True,
            )

    def test_external_evidence_owner_packets_bind_work_package_assignments(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[{
                "requirement_id": "oss-verifier-and-public-spec",
                "authority_kind": "ci-run",
                "path": FIXTURE,
                "description": "Recorded verifier workflow run export.",
                "issuer": "GitHub Actions",
                "subject": "trustai go verifier release workflow",
                "source_uri": "https://github.com/MSBeni/trust_ai/actions",
                "issued_at": "2026-07-08T00:00:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            }],
            generated_at="2026-07-09T00:00:00Z",
        )
        plan = build_external_evidence_collection_plan(manifest, audit, root=ROOT, status_filter="missing", generated_at="2026-07-09T00:00:00Z")
        source_map = build_external_evidence_source_map_template(
            plan,
            status_filter="missing",
            authority_kinds=["provider-api", "identity-provider"],
            source_uri_template="TODO://authority/{requirement_id}/{authority_kind}",
            description_template="{authority_kind} evidence for {requirement_id}",
            limit=3,
            generated_at="2026-07-09T00:01:00Z",
        )
        gap_report = build_external_evidence_gap_report(
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
            generated_at="2026-07-09T00:02:00Z",
        )
        work_package = build_external_evidence_work_package(
            gap_report,
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
            generated_at="2026-07-09T00:03:00Z",
        )
        packet_bundle = build_external_evidence_owner_packets(work_package, generated_at="2026-07-09T00:04:00Z")
        result = verify_external_evidence_owner_packets(packet_bundle, work_package)
        markdown = render_external_evidence_owner_packets_markdown(packet_bundle)

        self.assertEqual(EXTERNAL_EVIDENCE_OWNER_PACKET_SCHEMA, packet_bundle["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(work_package["summary"]["package_count"], packet_bundle["summary"]["packet_count"])
        self.assertEqual(work_package["summary"]["task_count"], packet_bundle["summary"]["task_count"])
        self.assertEqual(content_hash(work_package), packet_bundle["source_work_package"]["work_package_hash"])
        self.assertTrue(all(packet["packet_ref"].startswith("owner-packet:") for packet in packet_bundle["packets"]))
        self.assertTrue(any(packet["handoff"]["collect_batch_command"] for packet in packet_bundle["packets"]))
        self.assertIn("External Evidence Owner Packets", markdown)
        self.assertIn("Completion gate", markdown)
        self.assertIn("Task Commands", markdown)

        status_report = build_external_evidence_owner_packet_status(
            packet_bundle,
            work_package,
            source_map,
            [],
            root=ROOT,
            generated_at="2026-07-09T00:05:00Z",
        )
        status_result = verify_external_evidence_owner_packet_status(
            status_report,
            packet_bundle,
            work_package,
            source_map,
            [],
            root=ROOT,
        )
        status_markdown = render_external_evidence_owner_packet_status_markdown(status_report)
        self.assertEqual(EXTERNAL_EVIDENCE_OWNER_PACKET_STATUS_SCHEMA, status_report["schema"])
        self.assertTrue(status_result.ok, status_result.errors)
        self.assertEqual(packet_bundle["summary"]["packet_count"], status_report["summary"]["packet_count"])
        self.assertEqual(packet_bundle["summary"]["task_count"], status_report["summary"]["task_count"])
        self.assertEqual(0, status_report["summary"]["closed_task_count"])
        self.assertEqual(packet_bundle["summary"]["task_count"], status_report["summary"]["blocked_task_count"])
        self.assertEqual(packet_bundle["summary"]["placeholder_source_uri_count"], status_report["summary"]["placeholder_source_uri_count"])
        self.assertIn("External Evidence Owner Packet Status", status_markdown)
        self.assertIn("Open And Blocked Tasks", status_markdown)

        tampered_status = copy.deepcopy(status_report)
        tampered_status["tasks"][0]["task_status"] = "closed"
        tampered_status["owner_packet_status_id"] = content_hash(without_keys(tampered_status, "owner_packet_status_id"))
        tampered_status_result = verify_external_evidence_owner_packet_status(
            tampered_status,
            packet_bundle,
            work_package,
            source_map,
            [],
            root=ROOT,
        )
        self.assertFalse(tampered_status_result.ok)
        self.assertTrue(any("owner packet status body" in error for error in tampered_status_result.errors), tampered_status_result.errors)

        fulfillment_template = build_external_evidence_owner_fulfillment_template(
            status_report,
            generated_at="2026-07-09T00:06:00Z",
        )
        fulfillment_result = verify_external_evidence_owner_fulfillment_template(fulfillment_template, status_report)
        fulfillment_markdown = render_external_evidence_owner_fulfillment_template_markdown(fulfillment_template)
        self.assertEqual(EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_TEMPLATE_SCHEMA, fulfillment_template["schema"])
        self.assertTrue(fulfillment_result.ok, fulfillment_result.errors)
        self.assertEqual(status_report["summary"]["blocked_task_count"], fulfillment_template["summary"]["fulfillment_count"])
        self.assertEqual(status_report["summary"]["blocked_task_count"], fulfillment_template["summary"]["blocked_task_count"])
        self.assertTrue(all(set(item) <= {"task", "source_uri", "description"} for item in fulfillment_template["fulfillments"]))
        self.assertEqual(fulfillment_template["assignments"][0]["task"], fulfillment_template["fulfillments"][0]["task"])
        self.assertIn("External Evidence Owner Fulfillment Template", fulfillment_markdown)
        self.assertIn("Fulfillments", fulfillment_markdown)
        fulfilled_from_template = fulfill_external_evidence_source_map(
            source_map,
            fulfillment_template["fulfillments"],
            generated_at="2026-07-09T00:07:00Z",
        )
        self.assertTrue(verify_external_evidence_source_map_template(fulfilled_from_template, plan).ok)

        fulfillment_review = build_external_evidence_owner_fulfillment_review(
            fulfillment_template,
            status_report,
            source_map,
            plan,
            root=ROOT,
            require_live_source_uris=True,
            generated_at="2026-07-09T00:08:00Z",
        )
        fulfillment_review_result = verify_external_evidence_owner_fulfillment_review(
            fulfillment_review,
            fulfillment_template,
            status_report,
            source_map,
            plan,
            root=ROOT,
            require_live_source_uris=True,
        )
        fulfillment_review_markdown = render_external_evidence_owner_fulfillment_review_markdown(fulfillment_review)
        self.assertEqual(EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_REVIEW_SCHEMA, fulfillment_review["schema"])
        self.assertTrue(fulfillment_review_result.ok, fulfillment_review_result.errors)
        self.assertEqual("blocked", fulfillment_review["summary"]["review_status"])
        self.assertFalse(fulfillment_review["summary"]["fulfilled_source_map_verification_ok"])
        self.assertEqual(fulfillment_template["summary"]["fulfillment_count"], fulfillment_review["summary"]["blocked_task_count"])
        self.assertEqual(fulfillment_template["summary"]["fulfillment_count"], fulfillment_review["summary"]["placeholder_source_uri_count"])
        self.assertIn("External Evidence Owner Fulfillment Review", fulfillment_review_markdown)
        self.assertTrue(any("placeholder" in blocker for blocker in fulfillment_review["blockers"]), fulfillment_review["blockers"])
        strict_fulfillment_review_result = verify_external_evidence_owner_fulfillment_review(
            fulfillment_review,
            fulfillment_template,
            status_report,
            source_map,
            plan,
            root=ROOT,
            require_live_source_uris=True,
            require_ready=True,
        )
        self.assertFalse(strict_fulfillment_review_result.ok)

        fulfillment_closure = build_external_evidence_owner_fulfillment_closure(
            fulfillment_review,
            status_report,
            manifest,
            manifest,
            plan,
            audit,
            root=ROOT,
            intakes=[],
            require_live_source_uris=True,
            generated_at="2026-07-09T00:08:30Z",
        )
        fulfillment_closure_result = verify_external_evidence_owner_fulfillment_closure(
            fulfillment_closure,
            fulfillment_review,
            status_report,
            manifest,
            manifest,
            plan,
            audit,
            root=ROOT,
            intakes=[],
            require_live_source_uris=True,
        )
        fulfillment_closure_markdown = render_external_evidence_owner_fulfillment_closure_markdown(fulfillment_closure)
        self.assertEqual(EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_CLOSURE_SCHEMA, fulfillment_closure["schema"])
        self.assertTrue(fulfillment_closure_result.ok, fulfillment_closure_result.errors)
        self.assertEqual("blocked", fulfillment_closure["summary"]["closure_status"])
        self.assertEqual(0, fulfillment_closure["summary"]["closed_task_count"])
        self.assertEqual(fulfillment_review["summary"]["blocked_task_count"], fulfillment_closure["summary"]["missing_intake_count"])
        self.assertEqual(fulfillment_review["summary"]["blocked_task_count"], fulfillment_closure["summary"]["missing_manifest_coverage_count"])
        self.assertEqual(fulfillment_review["summary"]["placeholder_source_uri_count"], fulfillment_closure["summary"]["placeholder_source_uri_count"])
        self.assertIn("External Evidence Owner Fulfillment Closure", fulfillment_closure_markdown)
        strict_fulfillment_closure_result = verify_external_evidence_owner_fulfillment_closure(
            fulfillment_closure,
            fulfillment_review,
            status_report,
            manifest,
            manifest,
            plan,
            audit,
            root=ROOT,
            intakes=[],
            require_live_source_uris=True,
            require_closed=True,
        )
        self.assertFalse(strict_fulfillment_closure_result.ok)

        filled_template = copy.deepcopy(fulfillment_template)
        for item in filled_template["fulfillments"]:
            task_slug = str(item["task"]).replace(":", "/")
            item["source_uri"] = f"https://authority.trustai.local/live/{task_slug}.json"
        filled_review = build_external_evidence_owner_fulfillment_review(
            filled_template,
            status_report,
            source_map,
            plan,
            root=ROOT,
            require_live_source_uris=True,
            generated_at="2026-07-09T00:09:00Z",
        )
        filled_review_result = verify_external_evidence_owner_fulfillment_review(
            filled_review,
            filled_template,
            status_report,
            source_map,
            plan,
            root=ROOT,
            require_live_source_uris=True,
            require_ready=True,
        )
        self.assertTrue(filled_review_result.ok, filled_review_result.errors)
        self.assertEqual("ready-to-collect", filled_review["summary"]["review_status"])
        self.assertTrue(filled_review["summary"]["fulfilled_source_map_verification_ok"])
        self.assertEqual(0, filled_review["summary"]["placeholder_source_uri_count"])
        self.assertEqual(fulfillment_template["summary"]["fulfillment_count"], filled_review["summary"]["ready_task_count"])
        self.assertTrue(any("stale" in warning for warning in filled_review["verification"]["template_warnings"]), filled_review["verification"])

        filled_intakes = []
        for index, task in enumerate(filled_review["task_reviews"]):
            filled_intakes.append(
                build_external_evidence_intake(
                    plan,
                    manifest,
                    audit,
                    root=ROOT,
                    task_ref=task["task"],
                    artifact_path=FIXTURE,
                    description=f"Authority export for {task['task']}",
                    issuer="TrustAI test authority",
                    subject=task["task"],
                    source_uri=task["source_uri"],
                    issued_at="2026-07-09T00:10:00Z",
                    expires_at="2026-12-31T00:00:00Z",
                    generated_at=f"2026-07-09T00:10:{index:02d}Z",
                )
            )
        rebuilt_manifest = build_external_evidence_manifest_from_intakes(
            plan,
            manifest,
            audit,
            root=ROOT,
            intakes=filled_intakes,
            require_live_source_uris=True,
            generated_at="2026-07-09T00:11:00Z",
        )
        closed_fulfillment_closure = build_external_evidence_owner_fulfillment_closure(
            filled_review,
            status_report,
            rebuilt_manifest,
            manifest,
            plan,
            audit,
            root=ROOT,
            intakes=filled_intakes,
            require_live_source_uris=True,
            generated_at="2026-07-09T00:12:00Z",
        )
        closed_fulfillment_closure_result = verify_external_evidence_owner_fulfillment_closure(
            closed_fulfillment_closure,
            filled_review,
            status_report,
            rebuilt_manifest,
            manifest,
            plan,
            audit,
            root=ROOT,
            intakes=filled_intakes,
            require_live_source_uris=True,
            require_closed=True,
        )
        self.assertTrue(closed_fulfillment_closure_result.ok, closed_fulfillment_closure_result.errors)
        self.assertEqual("closed", closed_fulfillment_closure["summary"]["closure_status"])
        self.assertEqual(filled_review["summary"]["ready_task_count"], closed_fulfillment_closure["summary"]["closed_task_count"])
        self.assertEqual(0, closed_fulfillment_closure["summary"]["missing_intake_count"])
        self.assertEqual(0, closed_fulfillment_closure["summary"]["missing_manifest_coverage_count"])

        filtered_template = build_external_evidence_owner_fulfillment_template(
            status_report,
            owner_hint=fulfillment_template["summary"]["owners"][0],
            generated_at="2026-07-09T00:06:00Z",
        )
        self.assertEqual(1, filtered_template["summary"]["owner_count"])
        self.assertLess(filtered_template["summary"]["fulfillment_count"], fulfillment_template["summary"]["fulfillment_count"])

        tampered_template = copy.deepcopy(fulfillment_template)
        tampered_template["fulfillments"][0]["source_uri"] = "https://authority.example/live/source.json"
        tampered_template["owner_fulfillment_template_id"] = content_hash(without_keys(tampered_template, "owner_fulfillment_template_id"))
        tampered_template_result = verify_external_evidence_owner_fulfillment_template(tampered_template, status_report)
        self.assertFalse(tampered_template_result.ok)
        self.assertTrue(any("owner fulfillment template body" in error for error in tampered_template_result.errors), tampered_template_result.errors)

        tampered = copy.deepcopy(packet_bundle)
        tampered["packets"][0]["tasks"][0]["source_uri_status"] = "live"
        tampered["owner_packet_bundle_id"] = content_hash(without_keys(tampered, "owner_packet_bundle_id"))
        tampered_result = verify_external_evidence_owner_packets(tampered, work_package)
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("owner packet bundle body" in error for error in tampered_result.errors), tampered_result.errors)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            work_package_path = tmp_path / "work-package.json"
            manifest_path = tmp_path / "manifest.json"
            audit_path = tmp_path / "roadmap-audit.json"
            plan_path = tmp_path / "plan.json"
            source_map_path = tmp_path / "source-map.json"
            packet_path = tmp_path / "owner-packets.json"
            markdown_path = tmp_path / "owner-packets.md"
            status_path = tmp_path / "owner-packet-status.json"
            status_markdown_path = tmp_path / "owner-packet-status.md"
            fulfillment_template_path = tmp_path / "owner-fulfillment-template.json"
            fulfillment_markdown_path = tmp_path / "owner-fulfillment-template.md"
            fulfillment_review_path = tmp_path / "owner-fulfillment-review.json"
            fulfillment_review_markdown_path = tmp_path / "owner-fulfillment-review.md"
            fulfillment_closure_path = tmp_path / "owner-fulfillment-closure.json"
            fulfillment_closure_markdown_path = tmp_path / "owner-fulfillment-closure.md"
            reviewed_source_map_path = tmp_path / "source-map-reviewed.json"
            fulfilled_source_map_path = tmp_path / "source-map-fulfilled.json"
            work_package_path.write_text(json.dumps(work_package, indent=2, sort_keys=True), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
            audit_path.write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")
            plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
            source_map_path.write_text(json.dumps(source_map, indent=2, sort_keys=True), encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-packets",
                    str(work_package_path),
                    "--generated-at",
                    "2026-07-09T00:04:00Z",
                    "--out",
                    str(packet_path),
                    "--markdown",
                    str(markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            cli_packet_bundle = load_external_evidence_owner_packets(packet_path)
            self.assertEqual(packet_bundle, cli_packet_bundle)
            self.assertTrue(markdown_path.exists())
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-packets-verify",
                    str(packet_path),
                    str(work_package_path),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-packet-status",
                    str(packet_path),
                    str(work_package_path),
                    str(source_map_path),
                    "--root",
                    str(ROOT),
                    "--generated-at",
                    "2026-07-09T00:05:00Z",
                    "--out",
                    str(status_path),
                    "--markdown",
                    str(status_markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            cli_status_report = load_external_evidence_owner_packet_status(status_path)
            self.assertEqual(status_report, cli_status_report)
            self.assertTrue(status_markdown_path.exists())
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-packet-status-verify",
                    str(status_path),
                    str(packet_path),
                    str(work_package_path),
                    str(source_map_path),
                    "--root",
                    str(ROOT),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-fulfillment-template",
                    str(status_path),
                    "--generated-at",
                    "2026-07-09T00:06:00Z",
                    "--out",
                    str(fulfillment_template_path),
                    "--markdown",
                    str(fulfillment_markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            cli_fulfillment_template = load_external_evidence_owner_fulfillment_template(fulfillment_template_path)
            self.assertEqual(fulfillment_template, cli_fulfillment_template)
            self.assertTrue(fulfillment_markdown_path.exists())
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-fulfillment-template-verify",
                    str(fulfillment_template_path),
                    str(status_path),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-source-map-fulfill",
                    str(source_map_path),
                    str(plan_path),
                    "--fulfillment-file",
                    str(fulfillment_template_path),
                    "--generated-at",
                    "2026-07-09T00:07:00Z",
                    "--out",
                    str(fulfilled_source_map_path),
                ],
                cwd=ROOT,
                check=True,
            )
            cli_fulfilled_source_map = json.loads(fulfilled_source_map_path.read_text(encoding="utf-8"))
            self.assertTrue(verify_external_evidence_source_map_template(cli_fulfilled_source_map, plan).ok)
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-fulfillment-review",
                    str(fulfillment_template_path),
                    str(status_path),
                    str(source_map_path),
                    str(plan_path),
                    "--root",
                    str(ROOT),
                    "--require-live-source-uris",
                    "--generated-at",
                    "2026-07-09T00:08:00Z",
                    "--out",
                    str(fulfillment_review_path),
                    "--markdown",
                    str(fulfillment_review_markdown_path),
                    "--fulfilled-source-map-out",
                    str(reviewed_source_map_path),
                ],
                cwd=ROOT,
                check=True,
            )
            cli_fulfillment_review = load_external_evidence_owner_fulfillment_review(fulfillment_review_path)
            self.assertEqual(fulfillment_review, cli_fulfillment_review)
            self.assertTrue(fulfillment_review_markdown_path.exists())
            self.assertEqual(fulfillment_review["fulfilled_source_map"], json.loads(reviewed_source_map_path.read_text(encoding="utf-8")))
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-fulfillment-review-verify",
                    str(fulfillment_review_path),
                    str(fulfillment_template_path),
                    str(status_path),
                    str(source_map_path),
                    str(plan_path),
                    "--root",
                    str(ROOT),
                    "--require-live-source-uris",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-fulfillment-closure",
                    str(fulfillment_review_path),
                    str(status_path),
                    str(manifest_path),
                    str(manifest_path),
                    str(plan_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-live-source-uris",
                    "--generated-at",
                    "2026-07-09T00:08:30Z",
                    "--out",
                    str(fulfillment_closure_path),
                    "--markdown",
                    str(fulfillment_closure_markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            cli_fulfillment_closure = load_external_evidence_owner_fulfillment_closure(fulfillment_closure_path)
            self.assertEqual(fulfillment_closure, cli_fulfillment_closure)
            self.assertTrue(fulfillment_closure_markdown_path.exists())
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-fulfillment-closure-verify",
                    str(fulfillment_closure_path),
                    str(fulfillment_review_path),
                    str(status_path),
                    str(manifest_path),
                    str(manifest_path),
                    str(plan_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-live-source-uris",
                ],
                cwd=ROOT,
                check=True,
            )
            strict_closure = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-fulfillment-closure-verify",
                    str(fulfillment_closure_path),
                    str(fulfillment_review_path),
                    str(status_path),
                    str(manifest_path),
                    str(manifest_path),
                    str(plan_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-live-source-uris",
                    "--require-closed",
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertNotEqual(0, strict_closure.returncode)
            strict_review = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-owner-fulfillment-review-verify",
                    str(fulfillment_review_path),
                    str(fulfillment_template_path),
                    str(status_path),
                    str(source_map_path),
                    str(plan_path),
                    "--root",
                    str(ROOT),
                    "--require-live-source-uris",
                    "--require-ready",
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertNotEqual(0, strict_review.returncode)

    def test_external_evidence_readiness_reports_not_ready_and_strict_cli_fails(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[{
                "requirement_id": "oss-verifier-and-public-spec",
                "authority_kind": "ci-run",
                "path": FIXTURE,
                "description": "Recorded verifier workflow run export.",
                "issuer": "GitHub Actions",
                "subject": "trustai go verifier release workflow",
                "source_uri": "https://github.com/MSBeni/trust_ai/actions",
                "issued_at": "2026-07-08T00:00:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            }],
            generated_at="2026-07-09T00:00:00Z",
        )
        plan = build_external_evidence_collection_plan(manifest, audit, root=ROOT, status_filter="missing", generated_at="2026-07-09T00:00:00Z")
        source_map = build_external_evidence_source_map_template(
            plan,
            status_filter="missing",
            authority_kinds=["provider-api"],
            source_uri_template="TODO://authority/{requirement_id}/{authority_kind}",
            description_template="{authority_kind} provider export for {requirement_id}",
            limit=2,
            generated_at="2026-07-09T00:01:00Z",
        )
        gap_report = build_external_evidence_gap_report(
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
            require_fresh=True,
            now="2026-07-12T00:00:00Z",
            generated_at="2026-07-09T00:02:00Z",
        )
        work_package = build_external_evidence_work_package(gap_report, manifest, plan, source_map, audit, root=ROOT, generated_at="2026-07-09T00:03:00Z")
        readiness = build_external_evidence_readiness_report(
            gap_report,
            manifest,
            plan,
            source_map,
            audit,
            root=ROOT,
            work_package=work_package,
            require_fresh=True,
            now="2026-07-12T00:00:00Z",
            generated_at="2026-07-09T00:04:00Z",
        )
        result = verify_external_evidence_readiness_report(readiness, gap_report, manifest, plan, source_map, audit, root=ROOT, work_package=work_package)
        strict_result = verify_external_evidence_readiness_report(readiness, gap_report, manifest, plan, source_map, audit, root=ROOT, work_package=work_package, require_ready=True)
        markdown = render_external_evidence_readiness_markdown(readiness)

        self.assertEqual(EXTERNAL_EVIDENCE_READINESS_SCHEMA, readiness["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertFalse(strict_result.ok)
        self.assertEqual("not-ready", readiness["summary"]["readiness_status"])
        self.assertGreater(readiness["summary"]["remaining_task_count"], 2)
        self.assertEqual(2, readiness["summary"]["source_map_entry_count"])
        self.assertEqual(2, readiness["summary"]["placeholder_source_uri_count"])
        self.assertEqual(0, readiness["summary"]["production_usable_covered_authority_kind_count"])
        self.assertEqual(1, readiness["summary"]["non_production_covered_authority_kind_count"])
        self.assertEqual("oss-verifier-and-public-spec:ci-run", readiness["non_production_covered_authority_units"][0]["unit_ref"])
        self.assertGreater(readiness["summary"]["work_package_count"], 0)
        self.assertLess(readiness["summary"]["work_package_task_count"], readiness["summary"]["remaining_task_count"])
        self.assertTrue(any("work package task count" in blocker for blocker in readiness["blockers"]))
        self.assertTrue(any("non-production evidence" in blocker for blocker in readiness["blockers"]))
        self.assertTrue(any(check["id"] == "source-map-live" and check["status"] == "failed" for check in readiness["checks"]))
        self.assertTrue(any(check["id"] == "covered-evidence-production-usable" and check["status"] == "failed" for check in readiness["checks"]))
        self.assertIn("External Evidence Production Readiness", markdown)
        self.assertIn("Non-production covered authority units: 1", markdown)
        self.assertIn("not-ready", markdown)

        tampered = copy.deepcopy(readiness)
        tampered["summary"]["remaining_task_count"] = 0
        tampered["readiness_id"] = content_hash(without_keys(tampered, "readiness_id"))
        tampered_result = verify_external_evidence_readiness_report(tampered, gap_report, manifest, plan, source_map, audit, root=ROOT, work_package=work_package)
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("readiness report body" in error for error in tampered_result.errors), tampered_result.errors)



    def test_external_evidence_intake_binds_artifact_to_collection_task(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                    "issuer": "GitHub Actions",
                    "subject": "trustai go verifier release workflow",
                    "source_uri": "https://github.com/MSBeni/trust_ai/actions",
                    "issued_at": "2026-07-08T00:00:00Z",
                    "expires_at": "2026-12-31T00:00:00Z",
                }
            ],
        )
        plan = build_external_evidence_collection_plan(
            manifest,
            audit,
            root=ROOT,
            status_filter="all",
            generated_at="2026-07-09T00:00:00Z",
        )

        intake = build_external_evidence_intake(
            plan,
            manifest,
            audit,
            root=ROOT,
            task_ref="oss-verifier-and-public-spec:ci-run",
            artifact_path=FIXTURE,
            description="Recorded verifier workflow run export",
            issuer="GitHub Actions",
            subject="trustai go verifier release workflow",
            source_uri="https://github.com/MSBeni/trust_ai/actions",
            issued_at="2026-07-08T00:00:00Z",
            expires_at="2026-12-31T00:00:00Z",
            generated_at="2026-07-09T00:00:00Z",
        )
        result = verify_external_evidence_intake(
            intake,
            plan,
            manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            now="2026-07-09T00:00:00Z",
        )

        self.assertEqual(EXTERNAL_EVIDENCE_INTAKE_SCHEMA, intake["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("oss-verifier-and-public-spec:ci-run", intake["task"]["unit_ref"])
        self.assertEqual(FIXTURE, intake["evidence_item"]["path"])
        self.assertIn("oss-verifier-and-public-spec,ci-run", intake["evidence_argument"])
        self.assertIn("issued_at=2026-07-08T00:00:00Z", intake["evidence_argument"])
        rebuilt = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[parse_evidence_arg(intake["evidence_argument"])],
        )
        self.assertEqual(["ci-run"], rebuilt["summary"]["covered_authority_kinds_by_requirement"]["oss-verifier-and-public-spec"])
        strict_manifest_without_snapshot_artifact = verify_external_evidence_manifest(
            manifest,
            audit,
            root=ROOT,
            require_source_snapshot_artifacts=True,
        )
        self.assertFalse(strict_manifest_without_snapshot_artifact.ok)
        self.assertTrue(
            any("external evidence source snapshot artifact" in error for error in strict_manifest_without_snapshot_artifact.errors),
            strict_manifest_without_snapshot_artifact.errors,
        )

        placeholder_intake = build_external_evidence_intake(
            plan,
            manifest,
            audit,
            root=ROOT,
            task_ref="oss-verifier-and-public-spec:ci-run",
            artifact_path=FIXTURE,
            description="Recorded verifier workflow run export",
            issuer="Example Provider",
            subject="placeholder source uri check",
            source_uri="https://provider.example/export",
            issued_at="2026-07-08T00:00:00Z",
            expires_at="2026-12-31T00:00:00Z",
            generated_at="2026-07-09T00:00:00Z",
        )
        placeholder_nonstrict = verify_external_evidence_intake(
            placeholder_intake,
            plan,
            manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            now="2026-07-09T00:00:00Z",
        )
        placeholder_strict = verify_external_evidence_intake(
            placeholder_intake,
            plan,
            manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            require_live_source_uris=True,
            now="2026-07-09T00:00:00Z",
        )
        self.assertTrue(placeholder_nonstrict.ok, placeholder_nonstrict.errors)
        self.assertTrue(any("source_uri is placeholder" in warning for warning in placeholder_nonstrict.warnings))
        self.assertFalse(placeholder_strict.ok)
        self.assertTrue(any("source_uri is placeholder" in error for error in placeholder_strict.errors), placeholder_strict.errors)

        strict_without_snapshot_artifact = verify_external_evidence_intake(
            intake,
            plan,
            manifest,
            audit,
            root=ROOT,
            require_source_snapshot_artifacts=True,
        )
        fresh_snapshot_without_snapshot_artifact = verify_external_evidence_intake(
            intake,
            plan,
            manifest,
            audit,
            root=ROOT,
            require_fresh_source_snapshot_artifacts=True,
        )
        self.assertFalse(strict_without_snapshot_artifact.ok)
        self.assertTrue(
            any("unsupported external evidence source snapshot schema" in error for error in strict_without_snapshot_artifact.errors),
            strict_without_snapshot_artifact.errors,
        )
        self.assertFalse(fresh_snapshot_without_snapshot_artifact.ok)
        self.assertTrue(
            any("requires source snapshot artifact verification" in error for error in fresh_snapshot_without_snapshot_artifact.errors),
            fresh_snapshot_without_snapshot_artifact.errors,
        )

        snapshot_rel = Path("artifacts/test-intake-source-snapshot/source-snapshot.json")
        snapshot_path = ROOT / snapshot_rel
        mismatch_rel = Path("artifacts/test-intake-source-snapshot/source-snapshot-mismatch.json")
        mismatch_path = ROOT / mismatch_rel
        shutil.rmtree(snapshot_path.parent, ignore_errors=True)
        try:
            snapshot = build_external_evidence_source_snapshot(
                source_uri="https://github.com/MSBeni/trust_ai/actions",
                body=(ROOT / FIXTURE).read_bytes(),
                retrieval_method="file-copy",
                issuer="GitHub Actions",
                subject="trustai go verifier release workflow",
                content_type="application/json",
                status_code=200,
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-12-31T00:00:00Z",
                generated_at="2026-07-09T00:00:00Z",
            )
            write_external_evidence_source_snapshot(snapshot_path, snapshot)
            snapshot_intake = build_external_evidence_intake(
                plan,
                manifest,
                audit,
                root=ROOT,
                task_ref="oss-verifier-and-public-spec:ci-run",
                artifact_path=snapshot_rel.as_posix(),
                description="Recorded verifier workflow run source snapshot",
                issuer="GitHub Actions",
                subject="trustai go verifier release workflow",
                source_uri="https://github.com/MSBeni/trust_ai/actions",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-12-31T00:00:00Z",
                generated_at="2026-07-09T00:00:00Z",
            )
            snapshot_result = verify_external_evidence_intake(
                snapshot_intake,
                plan,
                manifest,
                audit,
                root=ROOT,
                require_fresh=True,
                require_source_snapshot_artifacts=True,
                require_fresh_source_snapshot_artifacts=True,
                now="2026-07-09T00:00:00Z",
            )
            self.assertTrue(snapshot_result.ok, snapshot_result.errors)

            mismatch_snapshot = build_external_evidence_source_snapshot(
                source_uri="https://github.com/MSBeni/trust_ai/actions/runs/different",
                body=(ROOT / FIXTURE).read_bytes(),
                retrieval_method="file-copy",
                issuer="GitHub Actions",
                subject="trustai go verifier release workflow",
                content_type="application/json",
                status_code=200,
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-12-31T00:00:00Z",
                generated_at="2026-07-09T00:00:00Z",
            )
            write_external_evidence_source_snapshot(mismatch_path, mismatch_snapshot)
            mismatch_intake = build_external_evidence_intake(
                plan,
                manifest,
                audit,
                root=ROOT,
                task_ref="oss-verifier-and-public-spec:ci-run",
                artifact_path=mismatch_rel.as_posix(),
                description="Recorded verifier workflow run source snapshot",
                issuer="GitHub Actions",
                subject="trustai go verifier release workflow",
                source_uri="https://github.com/MSBeni/trust_ai/actions",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-12-31T00:00:00Z",
                generated_at="2026-07-09T00:00:00Z",
            )
            mismatch_result = verify_external_evidence_intake(
                mismatch_intake,
                plan,
                manifest,
                audit,
                root=ROOT,
                require_source_snapshot_artifacts=True,
            )
            self.assertFalse(mismatch_result.ok)
            self.assertTrue(
                any("source_uri does not match evidence source_uri" in error for error in mismatch_result.errors),
                mismatch_result.errors,
            )
        finally:
            shutil.rmtree(snapshot_path.parent, ignore_errors=True)

        tampered = copy.deepcopy(intake)
        tampered["evidence_item"]["sha256"] = "sha256:" + "0" * 64
        tampered["intake_id"] = content_hash(without_keys(tampered, "intake_id"))
        tampered_result = verify_external_evidence_intake(tampered, plan, manifest, audit, root=ROOT)
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("hash mismatch" in error for error in tampered_result.errors), tampered_result.errors)

    def test_external_evidence_source_snapshot_hashes_body_and_freshness(self):
        body = (ROOT / FIXTURE).read_bytes()
        snapshot = build_external_evidence_source_snapshot(
            source_uri="https://github.com/MSBeni/trust_ai/actions/runs/1234567890",
            body=body,
            retrieval_method="file-copy",
            issuer="GitHub Actions",
            subject="trustai verifier release workflow",
            content_type="application/json",
            response_headers={"ETag": "run-123"},
            issued_at="2026-07-08T00:00:00Z",
            expires_at="2026-12-31T00:00:00Z",
            generated_at="2026-07-09T00:00:00Z",
        )
        result = verify_external_evidence_source_snapshot(
            snapshot,
            require_fresh=True,
            now="2026-07-09T00:00:00Z",
        )

        self.assertEqual(EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA, snapshot["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("sha256:" + sha256(body).hexdigest(), snapshot["body_sha256"])
        self.assertEqual(len(body), snapshot["body_size_bytes"])
        self.assertEqual("run-123", snapshot["response_headers"]["etag"])

        tampered = copy.deepcopy(snapshot)
        tampered["body_base64"] = "eyJ0YW1wZXJlZCI6dHJ1ZX0K"
        tampered["snapshot_id"] = content_hash(without_keys(tampered, "snapshot_id"))
        tampered_result = verify_external_evidence_source_snapshot(tampered)
        self.assertFalse(tampered_result.ok)
        self.assertTrue(any("body_sha256 mismatch" in error for error in tampered_result.errors), tampered_result.errors)

        missing_freshness = build_external_evidence_source_snapshot(
            source_uri="https://provider.example/export",
            body="{}",
            retrieval_method="manual-export",
            generated_at="2026-07-09T00:00:00Z",
        )
        nonstrict = verify_external_evidence_source_snapshot(missing_freshness, now="2026-07-09T00:00:00Z")
        strict = verify_external_evidence_source_snapshot(
            missing_freshness,
            require_fresh=True,
            now="2026-07-09T00:00:00Z",
        )
        self.assertTrue(nonstrict.ok, nonstrict.errors)
        self.assertTrue(any("freshness metadata missing" in warning for warning in nonstrict.warnings))
        self.assertFalse(strict.ok)
        self.assertTrue(any("freshness metadata missing" in error for error in strict.errors), strict.errors)

    def test_cli_external_evidence_snapshot_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            source_path = tmp_path / "provider-export.json"
            snapshot_path = tmp_path / "external-evidence-source-snapshot.json"
            source_path.write_text('{"run":"ok","status":"completed"}\n', encoding="utf-8")

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-snapshot",
                    "https://provider.example/runs/1234567890",
                    "--source-file",
                    str(source_path),
                    "--issuer",
                    "Provider API",
                    "--subject",
                    "trustai external evidence source export",
                    "--content-type",
                    "application/json",
                    "--issued-at",
                    "2026-07-08T00:00:00Z",
                    "--expires-at",
                    "2026-12-31T00:00:00Z",
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                    "--out",
                    str(snapshot_path),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-snapshot-verify",
                    str(snapshot_path),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                ],
                cwd=ROOT,
                check=True,
            )
            snapshot = load_external_evidence_source_snapshot(snapshot_path)

            self.assertEqual(EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA, snapshot["schema"])
            self.assertEqual("file-copy", snapshot["retrieval_method"])
            self.assertEqual("https://provider.example/runs/1234567890", snapshot["source_uri"])
            self.assertEqual("sha256:" + sha256(source_path.read_bytes()).hexdigest(), snapshot["body_sha256"])

    def test_cli_external_evidence_collect_creates_snapshot_and_intake(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            audit_path = tmp_path / "roadmap-audit.json"
            manifest_path = tmp_path / "external-evidence-manifest.json"
            plan_path = tmp_path / "external-evidence-plan-all.json"
            intake_path = tmp_path / "external-evidence-intake.json"
            source_path = tmp_path / "provider-export.json"
            snapshot_rel = Path("artifacts/test-external-evidence-collect/source-snapshot.json")
            snapshot_path = ROOT / snapshot_rel
            shutil.rmtree(snapshot_path.parent, ignore_errors=True)
            source_path.write_text('{"run":"ok","status":"completed"}\n', encoding="utf-8")

            try:
                audit = build_roadmap_audit(ROOT)
                manifest = build_external_evidence_manifest(
                    audit,
                    root=ROOT,
                    evidence=[],
                    generated_at="2026-07-09T00:00:00Z",
                )
                plan = build_external_evidence_collection_plan(
                    manifest,
                    audit,
                    root=ROOT,
                    status_filter="all",
                    generated_at="2026-07-09T00:00:00Z",
                )
                write_roadmap_audit(audit_path, audit)
                write_external_evidence_manifest(manifest_path, manifest)
                write_external_evidence_collection_plan(plan_path, plan)

                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "trustai",
                        "external-evidence-collect",
                        str(plan_path),
                        str(manifest_path),
                        str(audit_path),
                        "https://provider.example/runs/1234567890",
                        "--root",
                        str(ROOT),
                        "--task",
                        "oss-verifier-and-public-spec:ci-run",
                        "--source-file",
                        str(source_path),
                        "--description",
                        "Snapshot of provider workflow export",
                        "--issuer",
                        "Provider API",
                        "--subject",
                        "trustai external evidence source export",
                        "--content-type",
                        "application/json",
                        "--issued-at",
                        "2026-07-08T00:00:00Z",
                        "--expires-at",
                        "2026-12-31T00:00:00Z",
                        "--snapshot-out",
                        snapshot_rel.as_posix(),
                        "--intake-out",
                        str(intake_path),
                        "--require-fresh",
                        "--now",
                        "2026-07-09T00:00:00Z",
                    ],
                    cwd=ROOT,
                    check=True,
                )
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "trustai",
                        "external-evidence-intake-verify",
                        str(intake_path),
                        str(plan_path),
                        str(manifest_path),
                        str(audit_path),
                        "--root",
                        str(ROOT),
                        "--require-fresh",
                        "--now",
                        "2026-07-09T00:00:00Z",
                    ],
                    cwd=ROOT,
                    check=True,
                )
                snapshot = load_external_evidence_source_snapshot(snapshot_path)
                intake = load_external_evidence_intake(intake_path)

                self.assertEqual(EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA, snapshot["schema"])
                self.assertEqual("file-copy", snapshot["retrieval_method"])
                self.assertEqual(snapshot_rel.as_posix(), intake["evidence_item"]["path"])
                self.assertEqual(file_sha256_ref(snapshot_path), intake["evidence_item"]["sha256"])
                self.assertIn("oss-verifier-and-public-spec,ci-run", intake["evidence_argument"])
            finally:
                shutil.rmtree(snapshot_path.parent, ignore_errors=True)

    def test_retained_external_evidence_examples_verify(self):
        audit = json.loads((ROOT / "examples/aitrade/external-evidence/source-roadmap-audit.json").read_text(encoding="utf-8"))
        manifest = load_external_evidence_manifest(ROOT / "examples/aitrade/external-evidence/source-external-evidence-manifest.json")
        retained_manifest = load_external_evidence_manifest(ROOT / "examples/aitrade/external-evidence/retained-external-evidence-manifest.json")
        plan = load_external_evidence_collection_plan(ROOT / "examples/aitrade/external-evidence/source-external-evidence-plan-all.json")
        remaining_plan = load_external_evidence_collection_plan(ROOT / "examples/aitrade/external-evidence/remaining-external-evidence-plan.json")
        source_map = json.loads((ROOT / "examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json").read_text(encoding="utf-8"))
        collected_source_map = json.loads((ROOT / "examples/aitrade/external-evidence/retained-external-evidence-collected-source-map.json").read_text(encoding="utf-8"))
        collection_run = load_external_evidence_collection_run(ROOT / "examples/aitrade/external-evidence/retained-external-evidence-collection-run.json")
        ci_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/github-actions-workflow-run-source-snapshot.json")
        provider_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/github-main-ref-source-snapshot.json")
        hosted_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/github-hosted-service-source-snapshot.json")
        self_serve_provider_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/self-serve-provider-api-source-snapshot.json")
        self_serve_hosted_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/self-serve-hosted-service-source-snapshot.json")
        self_serve_identity_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/self-serve-identity-provider-source-snapshot.json")
        cicd_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/github-check-suite-source-snapshot.json")
        cicd_provider_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/github-audit-log-source-snapshot.json")
        cicd_hosted_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/cicd-provider-approvals-hosted-service-source-snapshot.json")
        cicd_identity_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/cicd-provider-approvals-identity-provider-source-snapshot.json")
        framework_provider_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/framework-hook-release-provider-api-source-snapshot.json")
        framework_hosted_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/framework-hook-release-hosted-service-source-snapshot.json")
        agent_inventory_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/agent-inventory-provider-api-source-snapshot.json")
        identity_inventory_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/identity-inventory-provider-source-snapshot.json")
        mcp_ci_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/mcp-gateway-ci-run-source-snapshot.json")
        mcp_kms_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/mcp-gateway-kms-hsm-source-snapshot.json")
        mcp_provider_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/mcp-proxy-events-provider-api-source-snapshot.json")
        mcp_hosted_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/mcp-proxy-events-hosted-service-source-snapshot.json")
        runtime_policy_kms_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/runtime-policy-kms-hsm-source-snapshot.json")
        runtime_policy_provider_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/runtime-policy-provider-api-source-snapshot.json")
        runtime_action_hosted_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/runtime-action-hosted-service-source-snapshot.json")
        runtime_policy_identity_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/runtime-policy-identity-provider-source-snapshot.json")
        shadow_holdout_kms_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/shadow-holdout-kms-hsm-source-snapshot.json")
        shadow_holdout_provider_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/traffic-completeness-provider-api-source-snapshot.json")
        shadow_holdout_identity_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/shadow-holdout-identity-provider-source-snapshot.json")
        shadow_holdout_standards_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/shadow-holdout-standards-body-source-snapshot.json")
        byoc_provider_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/byoc-provider-api-source-snapshot.json")
        byoc_kms_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/byoc-kms-hsm-source-snapshot.json")
        byoc_object_lock_snapshot = load_external_evidence_source_snapshot(ROOT / "examples/aitrade/external-evidence/byoc-object-lock-source-snapshot.json")
        ci_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/oss-verifier-ci-run.json")
        provider_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/oss-verifier-provider-api.json")
        hosted_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/oss-verifier-hosted-service.json")
        self_serve_provider_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/self-serve-onboarding-provider-api.json")
        self_serve_hosted_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/self-serve-onboarding-hosted-service.json")
        self_serve_identity_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/self-serve-onboarding-identity-provider.json")
        cicd_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-ci-run.json")
        cicd_provider_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-provider-api.json")
        cicd_hosted_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-hosted-service.json")
        cicd_identity_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-identity-provider.json")
        framework_provider_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/framework-adapters-provider-api.json")
        framework_hosted_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/framework-adapters-hosted-service.json")
        agent_inventory_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/agent-inventory-and-identity-provider-api.json")
        identity_inventory_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/agent-inventory-and-identity-identity-provider.json")
        mcp_ci_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/mcp-gateway-ci-run.json")
        mcp_kms_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/mcp-gateway-kms-hsm.json")
        mcp_provider_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/mcp-gateway-provider-api.json")
        mcp_hosted_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/mcp-gateway-hosted-service.json")
        runtime_policy_kms_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-kms-hsm.json")
        runtime_policy_provider_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-provider-api.json")
        runtime_action_hosted_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-hosted-service.json")
        runtime_policy_identity_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-identity-provider.json")
        shadow_holdout_kms_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-kms-hsm.json")
        shadow_holdout_provider_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-provider-api.json")
        shadow_holdout_identity_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-identity-provider.json")
        shadow_holdout_standards_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-standards-body.json")
        byoc_provider_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/byoc-self-hosted-provider-api.json")
        byoc_kms_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/byoc-self-hosted-kms-hsm.json")
        byoc_object_lock_intake = load_external_evidence_intake(ROOT / "examples/aitrade/external-evidence/intakes/byoc-self-hosted-cloud-object-lock.json")

        audit_result = verify_roadmap_audit(audit, root=ROOT)
        manifest_result = verify_external_evidence_manifest(
            manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            now="2026-07-12T00:00:00Z",
        )
        plan_result = verify_external_evidence_collection_plan(plan, manifest, audit, root=ROOT)
        retained_manifest_result = verify_external_evidence_manifest(
            retained_manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            require_source_snapshot_artifacts=True,
            require_fresh_source_snapshot_artifacts=True,
            now="2026-07-12T00:00:00Z",
        )
        remaining_plan_result = verify_external_evidence_collection_plan(remaining_plan, retained_manifest, audit, root=ROOT)
        collection_run_result = verify_external_evidence_collection_run(
            collection_run,
            plan,
            manifest,
            audit,
            root=ROOT,
            source_map=collected_source_map,
            require_fresh=True,
            require_live_source_uris=True,
            require_fresh_source_snapshot_artifacts=True,
            now="2026-07-12T00:00:00Z",
        )
        snapshot_results = [
            verify_external_evidence_source_snapshot(
                snapshot,
                require_fresh=True,
                now="2026-07-12T00:00:00Z",
            )
            for snapshot in (
                ci_snapshot,
                provider_snapshot,
                hosted_snapshot,
                self_serve_provider_snapshot,
                self_serve_hosted_snapshot,
                self_serve_identity_snapshot,
                cicd_snapshot,
                cicd_provider_snapshot,
                cicd_hosted_snapshot,
                cicd_identity_snapshot,
                framework_provider_snapshot,
                framework_hosted_snapshot,
                agent_inventory_snapshot,
                identity_inventory_snapshot,
                mcp_ci_snapshot,
                mcp_kms_snapshot,
                mcp_provider_snapshot,
                mcp_hosted_snapshot,
                runtime_policy_kms_snapshot,
                runtime_policy_provider_snapshot,
                runtime_action_hosted_snapshot,
                runtime_policy_identity_snapshot,
                shadow_holdout_kms_snapshot,
                shadow_holdout_provider_snapshot,
                shadow_holdout_identity_snapshot,
                shadow_holdout_standards_snapshot,
                byoc_provider_snapshot,
                byoc_kms_snapshot,
                byoc_object_lock_snapshot,
            )
        ]
        intake_results = [
            verify_external_evidence_intake(
                intake,
                plan,
                manifest,
                audit,
                root=ROOT,
                require_fresh=True,
                require_source_snapshot_artifacts=True,
                require_fresh_source_snapshot_artifacts=True,
                now="2026-07-12T00:00:00Z",
            )
            for intake in (
                ci_intake,
                provider_intake,
                hosted_intake,
                self_serve_provider_intake,
                self_serve_hosted_intake,
                self_serve_identity_intake,
                cicd_intake,
                cicd_provider_intake,
                cicd_hosted_intake,
                cicd_identity_intake,
                framework_provider_intake,
                framework_hosted_intake,
                agent_inventory_intake,
                identity_inventory_intake,
                mcp_ci_intake,
                mcp_kms_intake,
                mcp_provider_intake,
                mcp_hosted_intake,
                runtime_policy_kms_intake,
                runtime_policy_provider_intake,
                runtime_action_hosted_intake,
                runtime_policy_identity_intake,
                shadow_holdout_kms_intake,
                shadow_holdout_provider_intake,
                shadow_holdout_identity_intake,
                shadow_holdout_standards_intake,
                byoc_provider_intake,
                byoc_kms_intake,
                byoc_object_lock_intake,
            )
        ]
        rebuilt = build_external_evidence_manifest_from_intakes(
            plan,
            manifest,
            audit,
            root=ROOT,
            intakes=[
                ci_intake,
                provider_intake,
                hosted_intake,
                self_serve_provider_intake,
                self_serve_hosted_intake,
                self_serve_identity_intake,
                cicd_intake,
                cicd_provider_intake,
                cicd_hosted_intake,
                cicd_identity_intake,
                framework_provider_intake,
                framework_hosted_intake,
                agent_inventory_intake,
                identity_inventory_intake,
                mcp_ci_intake,
                mcp_kms_intake,
                mcp_provider_intake,
                mcp_hosted_intake,
                runtime_policy_kms_intake,
                runtime_policy_provider_intake,
                runtime_action_hosted_intake,
                runtime_policy_identity_intake,
                shadow_holdout_kms_intake,
                shadow_holdout_provider_intake,
                shadow_holdout_identity_intake,
                shadow_holdout_standards_intake,
                byoc_provider_intake,
                byoc_kms_intake,
                byoc_object_lock_intake,
            ],
            require_fresh=True,
            require_source_snapshot_artifacts=True,
            require_fresh_source_snapshot_artifacts=True,
            now="2026-07-12T00:00:00Z",
            generated_at="2026-07-12T00:01:00Z",
        )

        self.assertTrue(audit_result.ok, audit_result.errors)
        self.assertTrue(manifest_result.ok, manifest_result.errors)
        self.assertTrue(plan_result.ok, plan_result.errors)
        self.assertTrue(retained_manifest_result.ok, retained_manifest_result.errors)
        self.assertTrue(remaining_plan_result.ok, remaining_plan_result.errors)
        self.assertTrue(collection_run_result.ok, collection_run_result.errors)
        for result in snapshot_results:
            self.assertTrue(result.ok, result.errors)
        for result in intake_results:
            self.assertTrue(result.ok, result.errors)
        self.assertEqual("file-copy", ci_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/external-evidence/go-verifier-workflow-run.json").read_bytes()).hexdigest(), ci_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/github-actions-workflow-run-source-snapshot.json", ci_intake["evidence_item"]["path"])
        self.assertEqual("examples/aitrade/external-evidence/self-serve-provider-api-source-snapshot.json", self_serve_provider_intake["evidence_item"]["path"])
        self.assertEqual("self-serve-onboarding", self_serve_provider_intake["task"]["requirement_id"])
        self.assertEqual("provider-api", self_serve_provider_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", self_serve_provider_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/self-serve-provider-api-authority-export.json").read_bytes()).hexdigest(), self_serve_provider_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/self-serve-hosted-service-source-snapshot.json", self_serve_hosted_intake["evidence_item"]["path"])
        self.assertEqual("self-serve-onboarding", self_serve_hosted_intake["task"]["requirement_id"])
        self.assertEqual("hosted-service", self_serve_hosted_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", self_serve_hosted_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/self-serve-hosted-service-authority-export.json").read_bytes()).hexdigest(), self_serve_hosted_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/self-serve-identity-provider-source-snapshot.json", self_serve_identity_intake["evidence_item"]["path"])
        self.assertEqual("self-serve-onboarding", self_serve_identity_intake["task"]["requirement_id"])
        self.assertEqual("identity-provider", self_serve_identity_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", self_serve_identity_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/self-serve-identity-provider-authority-export.json").read_bytes()).hexdigest(), self_serve_identity_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/github-check-suite-source-snapshot.json", cicd_intake["evidence_item"]["path"])
        self.assertEqual("cicd-provider-approvals", cicd_intake["task"]["requirement_id"])
        self.assertEqual("ci-run", cicd_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", cicd_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/webhooks/github-check-suite.json").read_bytes()).hexdigest(), cicd_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/github-audit-log-source-snapshot.json", cicd_provider_intake["evidence_item"]["path"])
        self.assertEqual("cicd-provider-approvals", cicd_provider_intake["task"]["requirement_id"])
        self.assertEqual("provider-api", cicd_provider_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", cicd_provider_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/webhooks/github-audit-log.json").read_bytes()).hexdigest(), cicd_provider_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/cicd-provider-approvals-hosted-service-source-snapshot.json", cicd_hosted_intake["evidence_item"]["path"])
        self.assertEqual("cicd-provider-approvals", cicd_hosted_intake["task"]["requirement_id"])
        self.assertEqual("hosted-service", cicd_hosted_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", cicd_hosted_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/cicd-provider-approvals-hosted-service-authority-export.json").read_bytes()).hexdigest(), cicd_hosted_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/cicd-provider-approvals-identity-provider-source-snapshot.json", cicd_identity_intake["evidence_item"]["path"])
        self.assertEqual("cicd-provider-approvals", cicd_identity_intake["task"]["requirement_id"])
        self.assertEqual("identity-provider", cicd_identity_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", cicd_identity_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/cicd-provider-approvals-identity-provider-authority-export.json").read_bytes()).hexdigest(), cicd_identity_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/framework-hook-release-provider-api-source-snapshot.json", framework_provider_intake["evidence_item"]["path"])
        self.assertEqual("framework-adapters", framework_provider_intake["task"]["requirement_id"])
        self.assertEqual("provider-api", framework_provider_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", framework_provider_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/framework-hook-release.json").read_bytes()).hexdigest(), framework_provider_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/framework-hook-release-hosted-service-source-snapshot.json", framework_hosted_intake["evidence_item"]["path"])
        self.assertEqual("framework-adapters", framework_hosted_intake["task"]["requirement_id"])
        self.assertEqual("hosted-service", framework_hosted_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", framework_hosted_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/framework-hook-release.json").read_bytes()).hexdigest(), framework_hosted_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/agent-inventory-provider-api-source-snapshot.json", agent_inventory_intake["evidence_item"]["path"])
        self.assertEqual("agent-inventory-and-identity", agent_inventory_intake["task"]["requirement_id"])
        self.assertEqual("provider-api", agent_inventory_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", agent_inventory_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/agent-inventory.json").read_bytes()).hexdigest(), agent_inventory_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/identity-inventory-provider-source-snapshot.json", identity_inventory_intake["evidence_item"]["path"])
        self.assertEqual("agent-inventory-and-identity", identity_inventory_intake["task"]["requirement_id"])
        self.assertEqual("identity-provider", identity_inventory_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", identity_inventory_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/identity-inventory.json").read_bytes()).hexdigest(), identity_inventory_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/mcp-gateway-ci-run-source-snapshot.json", mcp_ci_intake["evidence_item"]["path"])
        self.assertEqual("mcp-gateway", mcp_ci_intake["task"]["requirement_id"])
        self.assertEqual("ci-run", mcp_ci_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", mcp_ci_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/mcp-gateway-ci-run-authority-export.json").read_bytes()).hexdigest(), mcp_ci_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/mcp-gateway-kms-hsm-source-snapshot.json", mcp_kms_intake["evidence_item"]["path"])
        self.assertEqual("mcp-gateway", mcp_kms_intake["task"]["requirement_id"])
        self.assertEqual("kms-hsm", mcp_kms_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", mcp_kms_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/mcp-gateway-kms-hsm-authority-export.json").read_bytes()).hexdigest(), mcp_kms_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/mcp-proxy-events-provider-api-source-snapshot.json", mcp_provider_intake["evidence_item"]["path"])
        self.assertEqual("mcp-gateway", mcp_provider_intake["task"]["requirement_id"])
        self.assertEqual("provider-api", mcp_provider_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", mcp_provider_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/mcp-proxy-events.json").read_bytes()).hexdigest(), mcp_provider_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/mcp-proxy-events-hosted-service-source-snapshot.json", mcp_hosted_intake["evidence_item"]["path"])
        self.assertEqual("mcp-gateway", mcp_hosted_intake["task"]["requirement_id"])
        self.assertEqual("hosted-service", mcp_hosted_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", mcp_hosted_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/mcp-proxy-events.json").read_bytes()).hexdigest(), mcp_hosted_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/runtime-policy-kms-hsm-source-snapshot.json", runtime_policy_kms_intake["evidence_item"]["path"])
        self.assertEqual("runtime-policy-and-attestation", runtime_policy_kms_intake["task"]["requirement_id"])
        self.assertEqual("kms-hsm", runtime_policy_kms_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", runtime_policy_kms_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/trust-authority-kms-response.json").read_bytes()).hexdigest(), runtime_policy_kms_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/runtime-policy-provider-api-source-snapshot.json", runtime_policy_provider_intake["evidence_item"]["path"])
        self.assertEqual("runtime-policy-and-attestation", runtime_policy_provider_intake["task"]["requirement_id"])
        self.assertEqual("provider-api", runtime_policy_provider_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", runtime_policy_provider_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/policy-pack.json").read_bytes()).hexdigest(), runtime_policy_provider_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/runtime-action-hosted-service-source-snapshot.json", runtime_action_hosted_intake["evidence_item"]["path"])
        self.assertEqual("runtime-policy-and-attestation", runtime_action_hosted_intake["task"]["requirement_id"])
        self.assertEqual("hosted-service", runtime_action_hosted_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", runtime_action_hosted_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/runtime-action.json").read_bytes()).hexdigest(), runtime_action_hosted_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/runtime-policy-identity-provider-source-snapshot.json", runtime_policy_identity_intake["evidence_item"]["path"])
        self.assertEqual("runtime-policy-and-attestation", runtime_policy_identity_intake["task"]["requirement_id"])
        self.assertEqual("identity-provider", runtime_policy_identity_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", runtime_policy_identity_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/identity-inventory.json").read_bytes()).hexdigest(), runtime_policy_identity_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/shadow-holdout-kms-hsm-source-snapshot.json", shadow_holdout_kms_intake["evidence_item"]["path"])
        self.assertEqual("shadow-replay-temporal-holdout", shadow_holdout_kms_intake["task"]["requirement_id"])
        self.assertEqual("kms-hsm", shadow_holdout_kms_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", shadow_holdout_kms_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/trust-authority-kms-response.json").read_bytes()).hexdigest(), shadow_holdout_kms_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/traffic-completeness-provider-api-source-snapshot.json", shadow_holdout_provider_intake["evidence_item"]["path"])
        self.assertEqual("shadow-replay-temporal-holdout", shadow_holdout_provider_intake["task"]["requirement_id"])
        self.assertEqual("provider-api", shadow_holdout_provider_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", shadow_holdout_provider_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/traffic-completeness-provider-export.json").read_bytes()).hexdigest(), shadow_holdout_provider_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/shadow-holdout-identity-provider-source-snapshot.json", shadow_holdout_identity_intake["evidence_item"]["path"])
        self.assertEqual("shadow-replay-temporal-holdout", shadow_holdout_identity_intake["task"]["requirement_id"])
        self.assertEqual("identity-provider", shadow_holdout_identity_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", shadow_holdout_identity_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/identity-inventory.json").read_bytes()).hexdigest(), shadow_holdout_identity_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/shadow-holdout-standards-body-source-snapshot.json", shadow_holdout_standards_intake["evidence_item"]["path"])
        self.assertEqual("shadow-replay-temporal-holdout", shadow_holdout_standards_intake["task"]["requirement_id"])
        self.assertEqual("standards-body", shadow_holdout_standards_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", shadow_holdout_standards_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/standards-ballot-system-response.json").read_bytes()).hexdigest(), shadow_holdout_standards_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/byoc-provider-api-source-snapshot.json", byoc_provider_intake["evidence_item"]["path"])
        self.assertEqual("byoc-self-hosted", byoc_provider_intake["task"]["requirement_id"])
        self.assertEqual("provider-api", byoc_provider_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", byoc_provider_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/byoc-network-policy-authority-export.json").read_bytes()).hexdigest(), byoc_provider_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/byoc-kms-hsm-source-snapshot.json", byoc_kms_intake["evidence_item"]["path"])
        self.assertEqual("byoc-self-hosted", byoc_kms_intake["task"]["requirement_id"])
        self.assertEqual("kms-hsm", byoc_kms_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", byoc_kms_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/trust-authority-kms-response.json").read_bytes()).hexdigest(), byoc_kms_snapshot["body_sha256"])
        self.assertEqual("examples/aitrade/external-evidence/byoc-object-lock-source-snapshot.json", byoc_object_lock_intake["evidence_item"]["path"])
        self.assertEqual("byoc-self-hosted", byoc_object_lock_intake["task"]["requirement_id"])
        self.assertEqual("cloud-object-lock", byoc_object_lock_intake["task"]["authority_kind"])
        self.assertEqual("file-copy", byoc_object_lock_snapshot["retrieval_method"])
        self.assertEqual("sha256:" + sha256((ROOT / "examples/aitrade/byoc-object-lock-provider-export.json").read_bytes()).hexdigest(), byoc_object_lock_snapshot["body_sha256"])
        for snapshot in (provider_snapshot, hosted_snapshot):
            self.assertEqual("git-ls-remote", snapshot["retrieval_method"])
            export = json.loads(base64.b64decode(snapshot["body_base64"]).decode("utf-8"))
            self.assertEqual("trustai.external-evidence-git-remote-ref-export/0.1", export["schema"])
        self.assertEqual(71, rebuilt["summary"]["required_authority_kind_count"])
        self.assertEqual(29, rebuilt["summary"]["covered_authority_kind_count"])
        self.assertEqual(42, rebuilt["summary"]["missing_authority_kind_count"])
        self.assertEqual(retained_manifest["summary"], rebuilt["summary"])
        self.assertEqual(42, remaining_plan["summary"]["selected_task_count"])
        self.assertEqual(42, remaining_plan["summary"]["selected_missing_task_count"])
        self.assertEqual(EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA, source_map["schema"])
        self.assertEqual(content_hash(without_keys(source_map, "source_map_id")), source_map["source_map_id"])
        self.assertEqual(42, source_map["summary"]["entry_count"])
        self.assertEqual(42, source_map["summary"]["placeholder_source_uri_count"])
        self.assertEqual(0, source_map["summary"]["live_source_uri_count"])
        self.assertEqual(EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA, collected_source_map["schema"])
        self.assertEqual(content_hash(without_keys(collected_source_map, "source_map_id")), collected_source_map["source_map_id"])
        self.assertEqual(29, collected_source_map["summary"]["entry_count"])
        self.assertEqual(0, collected_source_map["summary"]["placeholder_source_uri_count"])
        self.assertEqual(29, collected_source_map["summary"]["live_source_uri_count"])
        self.assertEqual(EXTERNAL_EVIDENCE_COLLECTION_RUN_SCHEMA, collection_run["schema"])
        self.assertEqual(content_hash(without_keys(collection_run, "run_id")), collection_run["run_id"])
        self.assertEqual(content_hash(collected_source_map), collection_run["source_map"]["source_map_hash"])
        self.assertEqual(29, collection_run["summary"]["collected_count"])
        self.assertEqual(29, collection_run_result.collected_count)
        self.assertEqual(
            ["ci-run", "provider-api", "hosted-service"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["oss-verifier-and-public-spec"],
        )
        self.assertEqual(
            ["provider-api", "hosted-service", "identity-provider"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["self-serve-onboarding"],
        )
        self.assertEqual(
            ["ci-run", "provider-api", "hosted-service", "identity-provider"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["cicd-provider-approvals"],
        )
        self.assertEqual(
            ["provider-api", "hosted-service"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["framework-adapters"],
        )
        self.assertEqual(
            ["provider-api", "identity-provider"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["agent-inventory-and-identity"],
        )
        self.assertEqual(
            ["ci-run", "kms-hsm", "provider-api", "hosted-service"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["mcp-gateway"],
        )
        self.assertEqual(
            ["kms-hsm", "provider-api", "hosted-service", "identity-provider"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["runtime-policy-and-attestation"],
        )
        self.assertEqual(
            ["kms-hsm", "provider-api", "identity-provider", "standards-body"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["shadow-replay-temporal-holdout"],
        )
        self.assertEqual(
            ["kms-hsm", "cloud-object-lock", "provider-api"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["byoc-self-hosted"],
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            chain = EvidenceChain.load(tmp_path / "chain.json", tenant_id="retained-external-evidence-strict")
            append_roadmap_audit(chain, audit, root=ROOT)
            collection_entry = append_external_evidence_collection_run(
                chain,
                collection_run,
                plan,
                manifest,
                audit,
                root=ROOT,
                source_map=collected_source_map,
                require_fresh=True,
                require_live_source_uris=True,
                require_fresh_source_snapshot_artifacts=True,
                now="2026-07-12T00:00:00Z",
            )
            entry = append_external_evidence_manifest(
                chain,
                retained_manifest,
                audit,
                root=ROOT,
                require_fresh=True,
                require_live_source_uris=True,
                require_source_snapshot_artifacts=True,
                require_fresh_source_snapshot_artifacts=True,
                now="2026-07-12T00:00:00Z",
            )
            report = build_roadmap_evidence_report(chain, require_external=True, require_fresh=True, generated_at="2026-07-12T00:01:00Z")
            report_result = verify_roadmap_evidence_report(report, chain, require_external=True, require_fresh=True)
            payload = entry["payload"]
            report_entry = report["external_evidence_entries"][0]
            collection_payload = collection_entry["payload"]
            collection_report_entry = report["external_evidence_collection_run_entries"][0]
            self.assertTrue(report_result.ok, report_result.errors)
            self.assertEqual(EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE, collection_entry["entry_type"])
            self.assertEqual(collection_run["run_id"], collection_payload["run_id"])
            self.assertEqual(content_hash(collection_run), collection_payload["run_hash"])
            self.assertEqual(content_hash(collected_source_map), collection_payload["source_map_hash"])
            self.assertEqual(29, collection_payload["collected_count"])
            self.assertEqual(29, collection_payload["task_count"])
            self.assertTrue(collection_payload["require_live_source_uris"])
            self.assertTrue(collection_payload["require_source_snapshot_artifacts"])
            self.assertTrue(collection_payload["require_fresh_source_snapshot_artifacts"])
            self.assertEqual(1, report["summary"]["external_evidence_collection_run_entry_count"])
            self.assertTrue(report["summary"]["has_external_evidence_collection_runs"])
            self.assertEqual(1, len(report["external_evidence_collection_run_entries"]))
            self.assertEqual(collection_run["run_id"], collection_report_entry["run_id"])
            self.assertEqual(collection_payload["snapshot_ids"], collection_report_entry["snapshot_ids"])
            self.assertTrue(payload["require_live_source_uris"])
            self.assertTrue(payload["require_source_snapshot_artifacts"])
            self.assertTrue(payload["require_fresh_source_snapshot_artifacts"])
            self.assertTrue(report_entry["require_live_source_uris"])
            self.assertTrue(report_entry["require_source_snapshot_artifacts"])
            self.assertTrue(report_entry["require_fresh_source_snapshot_artifacts"])
            collection_chain = EvidenceChain.load(tmp_path / "collection-chain.json", tenant_id="retained-collection-bundle")
            append_roadmap_audit(collection_chain, audit, root=ROOT)
            append_external_evidence_collection_run(
                collection_chain,
                collection_run,
                plan,
                manifest,
                audit,
                root=ROOT,
                source_map=collected_source_map,
                require_fresh=True,
                require_live_source_uris=True,
                require_fresh_source_snapshot_artifacts=True,
                now="2026-07-12T00:00:00Z",
            )
            collection_report = build_roadmap_evidence_report(collection_chain, generated_at="2026-07-12T00:02:00Z")
            retained_source_artifacts = [
                {
                    "kind": "roadmap-audit",
                    "path": "examples/aitrade/external-evidence/source-roadmap-audit.json",
                    "description": "Retained source roadmap audit JSON",
                },
                {
                    "kind": "external-evidence-collection-run",
                    "path": "examples/aitrade/external-evidence/retained-external-evidence-collection-run.json",
                    "description": "Retained external evidence collection run JSON",
                },
                {
                    "kind": "external-evidence-source-map",
                    "path": "examples/aitrade/external-evidence/retained-external-evidence-collected-source-map.json",
                    "description": "Retained collected external evidence source map JSON",
                },
            ]
            retained_source_artifacts.extend(
                {
                    "kind": "external-evidence-source-snapshot",
                    "path": item["snapshot_artifact_path"],
                    "description": f"Retained source snapshot for {item['task']}",
                }
                for item in collection_run["collected"]
            )
            retained_source_artifacts.extend(
                {
                    "kind": "external-evidence-intake",
                    "path": item["intake_path"],
                    "description": f"Retained intake receipt for {item['task']}",
                }
                for item in collection_run["collected"]
            )
            collection_bundle = build_roadmap_evidence_bundle(
                collection_chain,
                report=collection_report,
                root=ROOT,
                source_artifacts=retained_source_artifacts,
            )
            collection_bundle_result = verify_roadmap_evidence_bundle(collection_bundle, require_source_artifacts=True)
            extracted = extract_roadmap_evidence_bundle_sources(
                collection_bundle,
                tmp_path / "collection-bundle-sources",
                require_source_artifacts=True,
            )
            expected_source_artifact_count = 3 + (2 * collection_run["summary"]["collected_count"])
            expected_source_artifact_kinds = (
                ["roadmap-audit", "external-evidence-collection-run", "external-evidence-source-map"]
                + ["external-evidence-source-snapshot"] * collection_run["summary"]["collected_count"]
                + ["external-evidence-intake"] * collection_run["summary"]["collected_count"]
            )
            self.assertTrue(collection_bundle_result.ok, collection_bundle_result.errors)
            self.assertEqual(expected_source_artifact_count, collection_bundle["summary"]["source_artifact_count"])
            self.assertEqual(1, collection_bundle["summary"]["external_evidence_collection_run_entry_count"])
            self.assertEqual(expected_source_artifact_count, len(extracted))
            self.assertEqual(expected_source_artifact_kinds, [artifact["kind"] for artifact in collection_bundle["source_artifacts"]])
            missing_source_map_bundle = copy.deepcopy(collection_bundle)
            missing_source_map_bundle["source_artifacts"] = [
                artifact for artifact in missing_source_map_bundle["source_artifacts"] if artifact["kind"] != "external-evidence-source-map"
            ]
            missing_source_map_bundle["summary"]["source_artifact_count"] = expected_source_artifact_count - 1
            missing_source_map_bundle["bundle_id"] = content_hash(without_keys(missing_source_map_bundle, "bundle_id"))
            nonstrict_missing_source_map = verify_roadmap_evidence_bundle(missing_source_map_bundle)
            strict_missing_source_map = verify_roadmap_evidence_bundle(missing_source_map_bundle, require_source_artifacts=True)
            self.assertTrue(nonstrict_missing_source_map.ok, nonstrict_missing_source_map.errors)
            self.assertTrue(any("source map referenced by embedded collection run" in warning for warning in nonstrict_missing_source_map.warnings))
            self.assertFalse(strict_missing_source_map.ok)
            self.assertTrue(any("missing an embedded source-map source artifact" in error for error in strict_missing_source_map.errors))

            missing_collection_run_bundle = copy.deepcopy(collection_bundle)
            missing_collection_run_bundle["source_artifacts"] = [
                artifact for artifact in missing_collection_run_bundle["source_artifacts"] if artifact["kind"] != "external-evidence-collection-run"
            ]
            missing_collection_run_bundle["summary"]["source_artifact_count"] = expected_source_artifact_count - 1
            missing_collection_run_bundle["bundle_id"] = content_hash(without_keys(missing_collection_run_bundle, "bundle_id"))
            strict_missing_collection_run = verify_roadmap_evidence_bundle(missing_collection_run_bundle, require_source_artifacts=True)
            self.assertFalse(strict_missing_collection_run.ok)
            self.assertTrue(any("missing an embedded collection-run source artifact" in error for error in strict_missing_collection_run.errors))


    def test_cli_external_evidence_gap_report_verifies_retained_worklist(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            report_path = tmp_path / "external-evidence-gap-report.json"
            markdown_path = tmp_path / "external-evidence-gap-report.md"
            retained_dir = ROOT / "examples/aitrade/external-evidence"
            manifest_path = retained_dir / "retained-external-evidence-manifest.json"
            plan_path = retained_dir / "remaining-external-evidence-plan.json"
            source_map_path = retained_dir / "remaining-external-evidence-source-map-template.json"
            audit_path = retained_dir / "source-roadmap-audit.json"

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-gap-report",
                    str(manifest_path),
                    str(plan_path),
                    str(source_map_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-12T00:00:00Z",
                    "--generated-at",
                    "2026-07-12T01:29:00Z",
                    "--out",
                    str(report_path),
                    "--markdown",
                    str(markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-gap-report-verify",
                    str(report_path),
                    str(manifest_path),
                    str(plan_path),
                    str(source_map_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-12T00:00:00Z",
                ],
                cwd=ROOT,
                check=True,
            )

            report = load_external_evidence_gap_report(report_path)
            manifest = load_external_evidence_manifest(manifest_path)
            plan = load_external_evidence_collection_plan(plan_path)
            source_map = json.loads(source_map_path.read_text(encoding="utf-8"))
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            result = verify_external_evidence_gap_report(
                report,
                manifest,
                plan,
                source_map,
                audit,
                root=ROOT,
                require_fresh=True,
                now="2026-07-12T00:00:00Z",
            )
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(EXTERNAL_EVIDENCE_GAP_REPORT_SCHEMA, report["schema"])
            self.assertEqual(content_hash(without_keys(report, "gap_report_id")), report["gap_report_id"])
            self.assertFalse(report["verification_options"]["require_live_source_uris"])
            self.assertFalse(report["verification_options"]["require_source_snapshots"])
            self.assertFalse(report["verification_options"]["require_fresh_source_snapshots"])
            strict_report_result = verify_external_evidence_gap_report(
                report,
                manifest,
                plan,
                source_map,
                audit,
                root=ROOT,
                require_fresh=True,
                require_live_source_uris=True,
                now="2026-07-12T00:00:00Z",
            )
            self.assertFalse(strict_report_result.ok)
            self.assertTrue(any("live source URIs" in error for error in strict_report_result.errors), strict_report_result.errors)
            self.assertEqual(29, report["summary"]["covered_authority_kind_count"])
            self.assertEqual(42, report["summary"]["missing_authority_kind_count"])
            self.assertEqual(42, report["summary"]["remaining_task_count"])
            self.assertEqual(42, report["summary"]["source_map_entry_count"])
            self.assertEqual(42, report["summary"]["placeholder_source_uri_count"])
            self.assertEqual(0, report["summary"]["live_source_uri_count"])
            first_gap = report["gaps"][0]
            self.assertEqual("design-partner-pilot-exit-criteria:regulator", first_gap["unit_ref"])
            self.assertEqual("regulator evidence for design-partner-pilot-exit-criteria", first_gap["description"])
            self.assertNotIn("source_file", first_gap)
            self.assertEqual("artifacts/external-evidence-sources/design-partner-pilot-exit-criteria/regulator.json", first_gap["snapshot_out"])
            self.assertEqual("artifacts/external-evidence-intakes/design-partner-pilot-exit-criteria/regulator.json", first_gap["intake_out"])
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("# External Evidence Gap Report", markdown)
            self.assertIn("Placeholder source URIs: 42", markdown)
            self.assertIn("- Description: regulator evidence for design-partner-pilot-exit-criteria", markdown)

            tampered = copy.deepcopy(report)
            tampered["summary"]["remaining_task_count"] = 51
            tampered["gap_report_id"] = content_hash(without_keys(tampered, "gap_report_id"))
            tampered_result = verify_external_evidence_gap_report(
                tampered,
                manifest,
                plan,
                source_map,
                audit,
                root=ROOT,
                require_fresh=True,
                now="2026-07-12T00:00:00Z",
            )
            self.assertFalse(tampered_result.ok)
            self.assertTrue(any("gap report body" in error for error in tampered_result.errors), tampered_result.errors)

    def test_cli_external_evidence_collect_git_ref_creates_snapshot_and_intake(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            audit_path = tmp_path / "roadmap-audit.json"
            manifest_path = tmp_path / "external-evidence-manifest.json"
            plan_path = tmp_path / "external-evidence-plan-all.json"
            intake_path = tmp_path / "external-evidence-git-ref-intake.json"
            remote_path = tmp_path / "remote.git"
            work_path = tmp_path / "work"
            snapshot_rel = Path("artifacts/test-external-evidence-git-ref/source-snapshot.json")
            snapshot_path = ROOT / snapshot_rel
            shutil.rmtree(snapshot_path.parent, ignore_errors=True)

            subprocess.run(["git", "init", "--bare", str(remote_path)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "init", str(work_path)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "-C", str(work_path), "config", "user.email", "trustai@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(work_path), "config", "user.name", "TrustAI Test"], check=True)
            (work_path / "README.md").write_text("# git ref evidence\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(work_path), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(work_path), "commit", "-m", "initial"], check=True, stdout=subprocess.DEVNULL)
            commit_sha = subprocess.check_output(["git", "-C", str(work_path), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", str(work_path), "push", str(remote_path), "HEAD:refs/heads/main"], check=True, stdout=subprocess.DEVNULL)

            try:
                audit = build_roadmap_audit(ROOT)
                manifest = build_external_evidence_manifest(
                    audit,
                    root=ROOT,
                    evidence=[],
                    generated_at="2026-07-09T00:00:00Z",
                )
                plan = build_external_evidence_collection_plan(
                    manifest,
                    audit,
                    root=ROOT,
                    status_filter="all",
                    generated_at="2026-07-09T00:00:00Z",
                )
                write_roadmap_audit(audit_path, audit)
                write_external_evidence_manifest(manifest_path, manifest)
                write_external_evidence_collection_plan(plan_path, plan)

                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "trustai",
                        "external-evidence-collect-git-ref",
                        str(plan_path),
                        str(manifest_path),
                        str(audit_path),
                        str(remote_path),
                        "--root",
                        str(ROOT),
                        "--task",
                        "oss-verifier-and-public-spec:provider-api",
                        "--ref",
                        "refs/heads/main",
                        "--expected-sha",
                        commit_sha,
                        "--description",
                        "Git remote main ref export",
                        "--issuer",
                        "Git remote",
                        "--subject",
                        "trustai git remote main",
                        "--issued-at",
                        "2026-07-08T00:00:00Z",
                        "--expires-at",
                        "2026-12-31T00:00:00Z",
                        "--generated-at",
                        "2026-07-09T00:00:00Z",
                        "--snapshot-out",
                        snapshot_rel.as_posix(),
                        "--intake-out",
                        str(intake_path),
                        "--require-fresh",
                        "--now",
                        "2026-07-09T00:00:00Z",
                    ],
                    cwd=ROOT,
                    check=True,
                )
                snapshot = load_external_evidence_source_snapshot(snapshot_path)
                intake = load_external_evidence_intake(intake_path)
                export = json.loads(base64.b64decode(snapshot["body_base64"]).decode("utf-8"))

                self.assertEqual(EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA, snapshot["schema"])
                self.assertEqual("git-ls-remote", snapshot["retrieval_method"])
                self.assertEqual(EXTERNAL_EVIDENCE_GIT_REMOTE_REF_EXPORT_SCHEMA, export["schema"])
                self.assertEqual(commit_sha, export["expected_sha"])
                self.assertTrue(export["expected_sha_matches"])
                self.assertEqual([{"ref": "refs/heads/main", "sha": commit_sha}], export["records"])
                self.assertEqual(snapshot_rel.as_posix(), intake["evidence_item"]["path"])
                self.assertEqual("provider-api", intake["evidence_item"]["authority_kind"])
                self.assertIn("oss-verifier-and-public-spec,provider-api", intake["evidence_argument"])
            finally:
                shutil.rmtree(snapshot_path.parent, ignore_errors=True)

    def test_cli_external_evidence_collect_batch_creates_multiple_intakes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            audit_path = tmp_path / "roadmap-audit.json"
            manifest_path = tmp_path / "external-evidence-manifest.json"
            plan_path = tmp_path / "external-evidence-plan-all.json"
            source_map_path = tmp_path / "external-evidence-source-map.json"
            run_path = tmp_path / "external-evidence-collection-run.json"
            intake_dir = tmp_path / "external-evidence-intakes"
            source_path = tmp_path / "provider-export.json"
            snapshot_dir_rel = Path("artifacts/test-external-evidence-batch")
            snapshot_dir = ROOT / snapshot_dir_rel
            shutil.rmtree(snapshot_dir, ignore_errors=True)
            source_path.write_text('{"run":"ok","status":"completed"}\n', encoding="utf-8")

            try:
                audit = build_roadmap_audit(ROOT)
                manifest = build_external_evidence_manifest(
                    audit,
                    root=ROOT,
                    evidence=[],
                    generated_at="2026-07-09T00:00:00Z",
                )
                plan = build_external_evidence_collection_plan(
                    manifest,
                    audit,
                    root=ROOT,
                    status_filter="all",
                    generated_at="2026-07-09T00:00:00Z",
                )
                write_roadmap_audit(audit_path, audit)
                write_external_evidence_manifest(manifest_path, manifest)
                write_external_evidence_collection_plan(plan_path, plan)
                source_map = {
                    "schema": EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA,
                    "defaults": {
                        "source_file": str(source_path),
                        "issuer": "Provider API",
                        "subject": "trustai external evidence batch export",
                        "content_type": "application/json",
                        "issued_at": "2026-07-08T00:00:00Z",
                        "expires_at": "2026-12-31T00:00:00Z",
                    },
                    "entries": [
                        {
                            "task": "oss-verifier-and-public-spec:ci-run",
                            "source_uri": "https://provider.example/runs/1234567890",
                            "description": "Snapshot of provider CI workflow export",
                            "snapshot_out": (snapshot_dir_rel / "ci-run.json").as_posix(),
                            "intake_out": str(intake_dir / "ci-run.json"),
                        },
                        {
                            "task": "oss-verifier-and-public-spec:provider-api",
                            "source_uri": "https://provider.example/api/runs/1234567890",
                            "description": "Snapshot of provider API workflow export",
                            "snapshot_out": (snapshot_dir_rel / "provider-api.json").as_posix(),
                            "intake_out": str(intake_dir / "provider-api.json"),
                        },
                    ],
                }
                source_map_path.write_text(json.dumps(source_map, indent=2, sort_keys=True), encoding="utf-8-sig")

                strict_batch = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "trustai",
                        "external-evidence-collect-batch",
                        str(plan_path),
                        str(manifest_path),
                        str(audit_path),
                        str(source_map_path),
                        "--root",
                        str(ROOT),
                        "--require-live-source-uris",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(0, strict_batch.returncode)
                self.assertIn("live source URIs", strict_batch.stderr)

                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "trustai",
                        "external-evidence-collect-batch",
                        str(plan_path),
                        str(manifest_path),
                        str(audit_path),
                        str(source_map_path),
                        "--root",
                        str(ROOT),
                        "--require-fresh",
                        "--now",
                        "2026-07-09T00:00:00Z",
                        "--out",
                        str(run_path),
                    ],
                    cwd=ROOT,
                    check=True,
                )
                run = load_external_evidence_collection_run(run_path)
                collection_run_result = verify_external_evidence_collection_run(
                    run,
                    plan,
                    manifest,
                    audit,
                    root=ROOT,
                    source_map=source_map,
                    require_fresh=True,
                    require_fresh_source_snapshot_artifacts=True,
                    now="2026-07-09T00:00:00Z",
                )
                self.assertTrue(collection_run_result.ok, collection_run_result.errors)
                self.assertEqual(2, collection_run_result.collected_count)
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "trustai",
                        "external-evidence-collect-batch-verify",
                        str(run_path),
                        str(plan_path),
                        str(manifest_path),
                        str(audit_path),
                        "--root",
                        str(ROOT),
                        "--require-fresh",
                        "--require-fresh-source-snapshot-artifacts",
                        "--now",
                        "2026-07-09T00:00:00Z",
                    ],
                    cwd=ROOT,
                    check=True,
                )
                tampered_run = copy.deepcopy(run)
                tampered_run["collected"][0]["snapshot_id"] = "wrong"
                tampered_run["run_id"] = content_hash(without_keys(tampered_run, "run_id"))
                tampered_result = verify_external_evidence_collection_run(
                    tampered_run,
                    plan,
                    manifest,
                    audit,
                    root=ROOT,
                    source_map=source_map,
                    require_fresh=True,
                    require_fresh_source_snapshot_artifacts=True,
                    now="2026-07-09T00:00:00Z",
                )
                self.assertFalse(tampered_result.ok)
                self.assertTrue(any("snapshot_id" in error for error in tampered_result.errors), tampered_result.errors)

                intakes = load_external_evidence_intakes(directories=[intake_dir])
                rebuilt = build_external_evidence_manifest_from_intakes(
                    plan,
                    manifest,
                    audit,
                    root=ROOT,
                    intakes=intakes,
                    require_fresh=True,
                    require_source_snapshot_artifacts=True,
                    require_fresh_source_snapshot_artifacts=True,
                    now="2026-07-09T00:00:00Z",
                    generated_at="2026-07-09T00:01:00Z",
                )

                self.assertEqual(EXTERNAL_EVIDENCE_COLLECTION_RUN_SCHEMA, run["schema"])
                self.assertEqual(2, run["summary"]["collected_count"])
                self.assertEqual(2, len(intakes))
                self.assertEqual(2, rebuilt["summary"]["covered_authority_kind_count"])
                self.assertEqual(69, rebuilt["summary"]["missing_authority_kind_count"])
                self.assertEqual(
                    ["ci-run", "provider-api"],
                    rebuilt["summary"]["covered_authority_kinds_by_requirement"]["oss-verifier-and-public-spec"],
                )
            finally:
                shutil.rmtree(snapshot_dir, ignore_errors=True)
    def test_external_evidence_manifest_from_intakes_preserves_source_and_overlays_receipts(self):
        audit = build_roadmap_audit(ROOT)
        source_manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                    "issuer": "GitHub Actions",
                    "subject": "trustai go verifier release workflow",
                    "source_uri": "https://github.com/MSBeni/trust_ai/actions",
                    "issued_at": "2026-07-08T00:00:00Z",
                    "expires_at": "2026-12-31T00:00:00Z",
                }
            ],
        )
        plan = build_external_evidence_collection_plan(
            source_manifest,
            audit,
            root=ROOT,
            status_filter="missing",
            generated_at="2026-07-09T00:00:00Z",
        )
        intake = build_external_evidence_intake(
            plan,
            source_manifest,
            audit,
            root=ROOT,
            task_ref="oss-verifier-and-public-spec:provider-api",
            artifact_path=FIXTURE,
            description="Recorded provider API export",
            issuer="GitHub API",
            subject="trustai go verifier release workflow",
            source_uri="https://github.com/MSBeni/trust_ai/actions",
            issued_at="2026-07-08T00:00:00Z",
            expires_at="2026-12-31T00:00:00Z",
            generated_at="2026-07-09T00:00:00Z",
        )

        rebuilt = build_external_evidence_manifest_from_intakes(
            plan,
            source_manifest,
            audit,
            root=ROOT,
            intakes=[intake],
            require_fresh=True,
            now="2026-07-09T00:00:00Z",
            generated_at="2026-07-09T00:01:00Z",
        )
        result = verify_external_evidence_manifest(
            rebuilt,
            audit,
            root=ROOT,
            require_fresh=True,
            now="2026-07-09T00:00:00Z",
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(2, rebuilt["summary"]["evidence_count"])
        self.assertEqual(2, rebuilt["summary"]["covered_authority_kind_count"])
        self.assertEqual(
            ["ci-run", "provider-api"],
            rebuilt["summary"]["covered_authority_kinds_by_requirement"]["oss-verifier-and-public-spec"],
        )
        self.assertEqual(69, rebuilt["summary"]["missing_authority_kind_count"])

        tampered = copy.deepcopy(intake)
        tampered["source_manifest"]["manifest_id"] = "wrong"
        tampered["intake_id"] = content_hash(without_keys(tampered, "intake_id"))
        with self.assertRaisesRegex(ValueError, "invalid external evidence intake"):
            build_external_evidence_manifest_from_intakes(
                plan,
                source_manifest,
                audit,
                root=ROOT,
                intakes=[tampered],
            )

    def test_external_evidence_freshness_windows_are_verifiable(self):
        audit = build_roadmap_audit(ROOT)
        now = "2026-07-09T00:00:00Z"
        fresh_manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                    "issuer": "GitHub Actions",
                    "subject": "trustai go verifier release workflow",
                    "source_uri": "https://github.com/MSBeni/trust_ai/actions",
                    "issued_at": "2026-07-08T00:00:00Z",
                    "expires_at": "2026-12-31T00:00:00Z",
                }
            ],
        )
        result = verify_external_evidence_manifest(
            fresh_manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            now=now,
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(1, result.fresh_evidence_count)
        self.assertEqual(0, result.stale_evidence_count)
        self.assertEqual(0, result.missing_freshness_count)
        self.assertEqual(1, fresh_manifest["summary"]["freshness_window_count"])

        missing_freshness_manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )
        nonstrict_missing = verify_external_evidence_manifest(
            missing_freshness_manifest,
            audit,
            root=ROOT,
            now=now,
        )
        strict_missing = verify_external_evidence_manifest(
            missing_freshness_manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            now=now,
        )

        self.assertTrue(nonstrict_missing.ok, nonstrict_missing.errors)
        self.assertTrue(any("freshness metadata missing" in warning for warning in nonstrict_missing.warnings))
        self.assertFalse(strict_missing.ok)
        self.assertTrue(any("freshness metadata missing" in error for error in strict_missing.errors))
        strict_missing_source_uri = verify_external_evidence_manifest(
            missing_freshness_manifest,
            audit,
            root=ROOT,
            require_live_source_uris=True,
            now=now,
        )
        self.assertFalse(strict_missing_source_uri.ok)
        self.assertTrue(
            any("source_uri is placeholder or missing" in error for error in strict_missing_source_uri.errors),
            strict_missing_source_uri.errors,
        )

        placeholder_uri_manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Placeholder source URI workflow export.",
                    "issuer": "Example Provider",
                    "subject": "placeholder source uri check",
                    "source_uri": "https://authority.example/workflow/run",
                    "issued_at": "2026-07-08T00:00:00Z",
                    "expires_at": "2026-12-31T00:00:00Z",
                }
            ],
        )
        placeholder_nonstrict = verify_external_evidence_manifest(
            placeholder_uri_manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            now=now,
        )
        placeholder_strict = verify_external_evidence_manifest(
            placeholder_uri_manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            require_live_source_uris=True,
            now=now,
        )
        self.assertTrue(placeholder_nonstrict.ok, placeholder_nonstrict.errors)
        self.assertTrue(any("source_uri is placeholder" in warning for warning in placeholder_nonstrict.warnings))
        self.assertFalse(placeholder_strict.ok)
        self.assertTrue(any("source_uri is placeholder" in error for error in placeholder_strict.errors), placeholder_strict.errors)

        expired_manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Expired workflow export.",
                    "issued_at": "2026-06-01T00:00:00Z",
                    "expires_at": "2026-07-01T00:00:00Z",
                }
            ],
        )
        expired_result = verify_external_evidence_manifest(
            expired_manifest,
            audit,
            root=ROOT,
            require_fresh=True,
            now=now,
        )

        self.assertFalse(expired_result.ok)
        self.assertEqual(1, expired_result.stale_evidence_count)
        self.assertTrue(any("expired" in error for error in expired_result.errors))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="external-evidence-fresh")
            append_roadmap_audit(chain, audit, root=ROOT)
            append_external_evidence_manifest(
                chain,
                fresh_manifest,
                audit,
                root=ROOT,
                require_fresh=True,
                now=now,
            )
            chain_result = verify_roadmap_evidence_chain(chain, require_external=True, require_fresh=True)
            report = build_roadmap_evidence_report(
                chain,
                require_external=True,
                require_fresh=True,
                generated_at=now,
            )
            report_result = verify_roadmap_evidence_report(
                report,
                chain,
                require_external=True,
                require_fresh=True,
            )
            bundle = build_roadmap_evidence_bundle(
                chain,
                require_external=True,
                require_fresh=True,
                report=report,
                generated_at=now,
            )
            bundle_result = verify_roadmap_evidence_bundle(bundle, require_external=True, require_fresh=True)

            self.assertTrue(chain_result.ok, chain_result.errors)
            self.assertEqual(1, chain_result.fresh_external_evidence_entry_count)
            self.assertTrue(report_result.ok, report_result.errors)
            self.assertEqual(1, report["summary"]["fresh_external_evidence_entry_count"])
            self.assertTrue(bundle_result.ok, bundle_result.errors)
            self.assertEqual(1, bundle["summary"]["fresh_external_evidence_entry_count"])

    def test_external_evidence_manifest_appends_to_chain(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="external-evidence-test")
            audit_entry = append_roadmap_audit(chain, audit, root=ROOT)
            entry = append_external_evidence_manifest(chain, manifest, audit, root=ROOT)

            self.assertEqual(EXTERNAL_EVIDENCE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(manifest["manifest_id"], entry["payload"]["manifest_id"])
            self.assertEqual("partial", entry["payload"]["status"])
            self.assertEqual(1, entry["payload"]["covered_requirement_count"])
            self.assertFalse(entry["payload"]["require_live_source_uris"])
            self.assertFalse(entry["payload"]["require_source_snapshot_artifacts"])
            self.assertFalse(entry["payload"]["require_fresh_source_snapshot_artifacts"])
            self.assertEqual(audit_entry["entry_id"], entry["payload"]["source_roadmap_audit_inclusion_proof"]["entry_id"])
            self.assertTrue(chain.verify_all().ok)
            semantic_result = verify_roadmap_evidence_chain(chain, require_external=True)
            strict_result = verify_roadmap_evidence_chain(chain, require_external=True, require_complete=True)
            self.assertTrue(semantic_result.ok, semantic_result.errors)
            self.assertFalse(strict_result.ok)
            self.assertTrue(any("partial" in error for error in strict_result.errors))
            tampered = EvidenceChain(chain.path, chain.tenant_id, copy.deepcopy(chain.entries))
            tampered.entries[1]["payload"]["source_roadmap_audit_inclusion_proof"]["tree_root"] = "0" * 64
            tampered_result = verify_roadmap_evidence_chain(tampered, require_external=True)
            self.assertFalse(tampered_result.ok)
            self.assertTrue(any("tree_root mismatch" in error for error in tampered_result.errors))
            report = build_roadmap_evidence_report(chain, require_external=True, generated_at="2026-07-09T00:00:00Z")
            report_result = verify_roadmap_evidence_report(report, chain, require_external=True)
            markdown = render_roadmap_evidence_markdown(report)

            self.assertEqual(ROADMAP_EVIDENCE_REPORT_SCHEMA, report["schema"])
            self.assertTrue(report_result.ok, report_result.errors)
            self.assertEqual(2, report["summary"]["chain_entry_count"])
            self.assertEqual(0, report["summary"]["fresh_external_evidence_entry_count"])
            self.assertEqual(1, report["summary"]["roadmap_audit_entry_count"])
            self.assertEqual(1, report["summary"]["external_evidence_entry_count"])
            self.assertEqual(0, report["summary"]["external_evidence_collection_run_entry_count"])
            self.assertFalse(report["summary"]["has_external_evidence_collection_runs"])
            self.assertIn("TrustAI Roadmap Evidence Report", markdown)
            self.assertIn(report["chain"]["tree"]["root"], markdown)

            bundle = build_roadmap_evidence_bundle(chain, require_external=True, generated_at="2026-07-09T00:00:00Z")
            bundle_result = verify_roadmap_evidence_bundle(bundle, require_external=True)
            bundle_markdown = render_roadmap_evidence_bundle_markdown(bundle)

            self.assertEqual(ROADMAP_EVIDENCE_BUNDLE_SCHEMA, bundle["schema"])
            self.assertTrue(bundle_result.ok, bundle_result.errors)
            self.assertEqual(report["report_id"], bundle["summary"]["report_id"])
            self.assertEqual(2, bundle["summary"]["chain_entry_count"])
            self.assertEqual(0, bundle["summary"]["source_artifact_count"])
            self.assertIn("TrustAI Roadmap Evidence Bundle", bundle_markdown)

            tampered_bundle = copy.deepcopy(bundle)
            tampered_bundle["chain"]["tree"]["root"] = "0" * 64
            tampered_bundle_result = verify_roadmap_evidence_bundle(tampered_bundle, require_external=True)
            self.assertFalse(tampered_bundle_result.ok)
            self.assertTrue(any("tree" in error for error in tampered_bundle_result.errors))
            stale_report = build_roadmap_evidence_report(chain, require_external=True, generated_at="2026-07-09T00:00:00Z")
            chain.append("trustai.test.unrelated", {"note": "new evidence"})
            stale_result = verify_roadmap_evidence_report(stale_report, chain, require_external=True)
            self.assertFalse(stale_result.ok)
            self.assertTrue(any("chain summary" in error for error in stale_result.errors))

    def test_roadmap_evidence_chain_rejects_legacy_complete_entry_without_authority_coverage(self):
        audit = build_roadmap_audit(ROOT)
        reference_requirements = {
            requirement["id"]: requirement
            for requirement in audit["requirements"]
            if requirement["status"] == STATUS_REFERENCE_ATTESTED
        }
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": requirement_id,
                    "authority_kind": authority_kind,
                    "path": FIXTURE,
                    "description": f"Fixture {authority_kind} evidence for {requirement_id}.",
                }
                for requirement_id, requirement in reference_requirements.items()
                for authority_kind in _allowed_authority_kinds_for_requirement(requirement)
            ],
        )
        summary = manifest["summary"]

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="external-evidence-legacy-complete")
            audit_entry = append_roadmap_audit(chain, audit, root=ROOT)
            legacy_payload = {
                "manifest_id": manifest["manifest_id"],
                "manifest_hash": content_hash(manifest),
                "manifest_ref": manifest.get("manifest_ref"),
                "source_roadmap_audit": manifest.get("source_roadmap_audit"),
                "source_roadmap_audit_inclusion_proof": chain.proof_for(audit_entry),
                "status": "complete",
                "require_complete": True,
                "require_fresh": False,
                "freshness_checked_at": manifest.get("generated_at"),
                "required_requirement_count": summary["required_requirement_count"],
                "covered_requirement_count": summary["covered_requirement_count"],
                "missing_requirement_count": 0,
                "evidence_count": summary["evidence_count"],
                "issued_at_count": summary["issued_at_count"],
                "expires_at_count": summary["expires_at_count"],
                "freshness_window_count": summary["freshness_window_count"],
                "fresh_evidence_count": 0,
                "stale_evidence_count": 0,
                "missing_freshness_count": summary["evidence_count"],
                "covered_requirement_ids": summary["covered_requirement_ids"],
                "missing_requirement_ids": [],
                "limitations": manifest.get("limitations", []),
            }
            chain.append(EXTERNAL_EVIDENCE_ENTRY_TYPE, legacy_payload, timestamp=manifest.get("generated_at"))

            self.assertTrue(chain.verify_all().ok)
            result = verify_roadmap_evidence_chain(chain, require_external=True, require_complete=True)

            self.assertFalse(result.ok)
            self.assertEqual(0, result.complete_external_evidence_entry_count)
            self.assertTrue(
                any("missing authority-kind coverage metadata" in error for error in result.errors),
                result.errors,
            )

    def test_roadmap_evidence_chain_rejects_unlinked_external_entry(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="external-evidence-test")
            append_external_evidence_manifest(chain, manifest, audit, root=ROOT)

            self.assertTrue(chain.verify_all().ok)
            result = verify_roadmap_evidence_chain(chain, require_external=True)
            self.assertFalse(result.ok)
            self.assertTrue(any("no roadmap audit entry" in error for error in result.errors))
            self.assertTrue(any("source roadmap audit is not chained" in error for error in result.errors))

    def test_external_evidence_append_requires_complete_when_requested(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="external-evidence-test")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                append_external_evidence_manifest(chain, manifest, audit, root=ROOT, require_complete=True)

    def test_cli_external_evidence_append_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            audit_path = tmp_path / "roadmap-audit.json"
            manifest_path = tmp_path / "external-evidence.json"
            entry_path = tmp_path / "external-evidence-entry.json"
            plan_path = tmp_path / "external-evidence-plan.json"
            all_plan_path = tmp_path / "external-evidence-plan-all.json"
            plan_markdown_path = tmp_path / "external-evidence-plan.md"
            intake_dir_path = tmp_path / "external-evidence-intakes"
            intake_path = intake_dir_path / "oss-verifier-ci-run.json"
            rebuilt_manifest_path = tmp_path / "external-evidence-manifest-from-intakes.json"
            report_path = tmp_path / "roadmap-evidence-report.json"
            report_markdown_path = tmp_path / "roadmap-evidence-report.md"
            bundle_path = tmp_path / "roadmap-evidence-bundle.json"
            bundle_markdown_path = tmp_path / "roadmap-evidence-bundle.md"
            bundle_extract_dir = tmp_path / "roadmap-evidence-bundle-sources"
            chain_path = tmp_path / "chain.json"
            bundled_fixture_path = tmp_path / FIXTURE
            bundled_fixture_path.parent.mkdir(parents=True)
            intake_dir_path.mkdir(parents=True)
            shutil.copyfile(ROOT / FIXTURE, bundled_fixture_path)
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-audit",
                    "--root",
                    str(ROOT),
                    "--out",
                    str(audit_path),
                    "--markdown",
                    str(tmp_path / "roadmap-audit.md"),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-audit-append",
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "external-evidence-cli",
                    "--out",
                    str(tmp_path / "roadmap-audit-entry.json"),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-manifest",
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--evidence",
                    f"oss-verifier-and-public-spec,ci-run,{FIXTURE},Recorded Go verifier workflow export;issuer=GitHub Actions;subject=trustai go verifier release workflow;source_uri=https://github.com/MSBeni/trust_ai/actions;issued_at=2026-07-08T00:00:00Z;expires_at=2026-12-31T00:00:00Z",
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                    "--out",
                    str(manifest_path),
                    "--markdown",
                    str(tmp_path / "external-evidence.md"),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-verify",
                    str(manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-plan",
                    str(manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--out",
                    str(plan_path),
                    "--markdown",
                    str(plan_markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-plan-verify",
                    str(plan_path),
                    str(manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-plan",
                    str(manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--status-filter",
                    "all",
                    "--out",
                    str(all_plan_path),
                    "--markdown",
                    "",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-intake",
                    str(all_plan_path),
                    str(manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--task",
                    "oss-verifier-and-public-spec:ci-run",
                    "--artifact",
                    FIXTURE,
                    "--description",
                    "Recorded verifier workflow run export",
                    "--issuer",
                    "GitHub Actions",
                    "--subject",
                    "trustai go verifier release workflow",
                    "--source-uri",
                    "https://github.com/MSBeni/trust_ai/actions",
                    "--issued-at",
                    "2026-07-08T00:00:00Z",
                    "--expires-at",
                    "2026-12-31T00:00:00Z",
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                    "--out",
                    str(intake_path),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-intake-verify",
                    str(intake_path),
                    str(all_plan_path),
                    str(manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-manifest-from-intakes",
                    str(all_plan_path),
                    str(manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--intake-dir",
                    str(intake_dir_path),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                    "--out",
                    str(rebuilt_manifest_path),
                    "--markdown",
                    "",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-verify",
                    str(rebuilt_manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "external-evidence-append",
                    str(rebuilt_manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--require-fresh",
                    "--now",
                    "2026-07-09T00:00:00Z",
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "external-evidence-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                check=True,
            )

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-evidence-verify",
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "external-evidence-cli",
                    "--require-external",
                    "--require-fresh",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-evidence-report",
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "external-evidence-cli",
                    "--require-external",
                    "--require-fresh",
                    "--out",
                    str(report_path),
                    "--markdown",
                    str(report_markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-evidence-report-verify",
                    str(report_path),
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "external-evidence-cli",
                    "--require-external",
                    "--require-fresh",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-evidence-bundle",
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "external-evidence-cli",
                    "--require-external",
                    "--require-fresh",
                    "--report",
                    str(report_path),
                    "--root",
                    str(tmp_path),
                    "--source-artifact",
                    f"roadmap-audit,{audit_path.name},Generated roadmap audit JSON",
                    "--source-artifact",
                    f"external-evidence-manifest,{rebuilt_manifest_path.name},Generated external evidence manifest JSON",
                    "--include-manifest-evidence",
                    "--require-source-artifacts",
                    "--out",
                    str(bundle_path),
                    "--markdown",
                    str(bundle_markdown_path),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-evidence-bundle-verify",
                    str(bundle_path),
                    "--require-external",
                    "--require-fresh",
                    "--require-source-artifacts",
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-evidence-bundle-extract",
                    str(bundle_path),
                    "--out-dir",
                    str(bundle_extract_dir),
                    "--require-external",
                    "--require-fresh",
                    "--require-source-artifacts",
                ],
                cwd=ROOT,
                check=True,
            )
            chain = EvidenceChain.load(chain_path, tenant_id="external-evidence-cli")
            self.assertEqual(2, len(chain.entries))
            self.assertEqual(EXTERNAL_EVIDENCE_ENTRY_TYPE, chain.entries[1]["entry_type"])
            self.assertEqual(chain.entries[0]["entry_id"], chain.entries[1]["payload"]["source_roadmap_audit_inclusion_proof"]["entry_id"])
            self.assertTrue(chain.verify_all().ok)
            plan = load_external_evidence_collection_plan(plan_path)
            intake = load_external_evidence_intake(intake_path)
            rebuilt_manifest = load_external_evidence_manifest(rebuilt_manifest_path)
            directory_intakes = load_external_evidence_intakes(directories=[intake_dir_path])
            self.assertEqual(1, len(directory_intakes))
            self.assertEqual(70, plan["summary"]["selected_task_count"])
            self.assertTrue(plan_markdown_path.exists())
            self.assertIn("External Evidence Collection Plan", plan_markdown_path.read_text(encoding="utf-8"))
            self.assertIn("oss-verifier-and-public-spec,ci-run", intake["evidence_argument"])
            self.assertEqual(1, rebuilt_manifest["summary"]["covered_authority_kind_count"])
            report = load_roadmap_evidence_report(report_path)
            self.assertEqual(2, report["summary"]["chain_entry_count"])
            self.assertEqual(1, report["summary"]["fresh_external_evidence_entry_count"])
            self.assertTrue(report_markdown_path.exists())
            bundle = load_roadmap_evidence_bundle(bundle_path)
            self.assertEqual(report["report_id"], bundle["summary"]["report_id"])
            self.assertEqual(3, bundle["summary"]["source_artifact_count"])
            self.assertEqual(1, bundle["summary"]["fresh_external_evidence_entry_count"])
            self.assertEqual(["roadmap-audit", "external-evidence-manifest", "external-evidence-file"], [artifact["kind"] for artifact in bundle["source_artifacts"]])
            self.assertTrue(bundle_markdown_path.exists())
            self.assertIn("Embedded source artifacts: 3", bundle_markdown_path.read_text(encoding="utf-8"))
            self.assertTrue((bundle_extract_dir / audit_path.name).exists())
            self.assertTrue((bundle_extract_dir / rebuilt_manifest_path.name).exists())
            self.assertTrue((bundle_extract_dir / FIXTURE).exists())
            direct_extract_dir = tmp_path / "direct-roadmap-evidence-bundle-sources"
            extracted = extract_roadmap_evidence_bundle_sources(
                bundle,
                direct_extract_dir,
                require_external=True,
                require_fresh=True,
                require_source_artifacts=True,
            )
            self.assertEqual(3, len(extracted))
            self.assertEqual(["roadmap-audit", "external-evidence-manifest", "external-evidence-file"], [record["kind"] for record in extracted])
            self.assertEqual((direct_extract_dir / audit_path.name).read_text(encoding="utf-8"), audit_path.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "already exists"):
                extract_roadmap_evidence_bundle_sources(
                    bundle,
                    direct_extract_dir,
                    require_external=True,
                    require_fresh=True,
                    require_source_artifacts=True,
                )
            tampered_bundle = copy.deepcopy(bundle)
            tampered_bundle["source_artifacts"][0]["sha256"] = "sha256:" + "0" * 64
            tampered_result = verify_roadmap_evidence_bundle(tampered_bundle, require_external=True, require_fresh=True)
            self.assertFalse(tampered_result.ok)
            self.assertTrue(any("source artifact" in error for error in tampered_result.errors))
            missing_file_bundle = copy.deepcopy(bundle)
            missing_file_bundle["source_artifacts"] = [
                artifact for artifact in missing_file_bundle["source_artifacts"] if artifact["kind"] != "external-evidence-file"
            ]
            missing_file_bundle["summary"]["source_artifact_count"] = 2
            missing_file_bundle["bundle_id"] = content_hash(without_keys(missing_file_bundle, "bundle_id"))
            missing_file_result = verify_roadmap_evidence_bundle(missing_file_bundle, require_external=True, require_fresh=True)
            self.assertTrue(missing_file_result.ok, missing_file_result.errors)
            self.assertTrue(any("referenced by embedded manifest is not embedded" in warning for warning in missing_file_result.warnings))
            strict_missing_file_result = verify_roadmap_evidence_bundle(
                missing_file_bundle,
                require_external=True,
                require_fresh=True,
                require_source_artifacts=True,
            )
            self.assertFalse(strict_missing_file_result.ok)
            self.assertTrue(any("referenced by embedded manifest is not embedded" in error for error in strict_missing_file_result.errors))
            missing_manifest_bundle = copy.deepcopy(bundle)
            missing_manifest_bundle["source_artifacts"] = [
                artifact for artifact in missing_manifest_bundle["source_artifacts"] if artifact["kind"] != "external-evidence-manifest"
            ]
            missing_manifest_bundle["summary"]["source_artifact_count"] = 2
            missing_manifest_bundle["bundle_id"] = content_hash(without_keys(missing_manifest_bundle, "bundle_id"))
            strict_missing_manifest_result = verify_roadmap_evidence_bundle(
                missing_manifest_bundle,
                require_external=True,
                require_fresh=True,
                require_source_artifacts=True,
            )
            self.assertFalse(strict_missing_manifest_result.ok)
            self.assertTrue(any("missing an embedded manifest source artifact" in error for error in strict_missing_manifest_result.errors))

    def test_external_evidence_complete_requires_all_authority_kinds(self):
        audit = build_roadmap_audit(ROOT)
        reference_requirements = {
            requirement["id"]: requirement
            for requirement in audit["requirements"]
            if requirement["status"] == STATUS_REFERENCE_ATTESTED
        }
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": requirement_id,
                    "authority_kind": _allowed_authority_kinds_for_requirement(requirement)[0],
                    "path": FIXTURE,
                    "description": f"Fixture evidence for {requirement_id}.",
                }
                for requirement_id, requirement in reference_requirements.items()
            ],
        )
        result = verify_external_evidence_manifest(manifest, audit, root=ROOT, require_complete=True)

        self.assertFalse(result.ok)
        self.assertEqual("partial", manifest["summary"]["status"])
        self.assertEqual(0, manifest["summary"]["missing_requirement_count"])
        self.assertGreater(manifest["summary"]["missing_authority_kind_count"], 0)
        self.assertTrue(any("authority-kind coverage" in error for error in result.errors), result.errors)
        self.assertTrue(any("authority kinds missing" in warning for warning in result.warnings), result.warnings)

    def test_complete_external_evidence_manifest_covers_reference_requirements(self):
        audit = build_roadmap_audit(ROOT)
        reference_requirements = {
            requirement["id"]: requirement
            for requirement in audit["requirements"]
            if requirement["status"] == STATUS_REFERENCE_ATTESTED
        }
        requirements = list(reference_requirements)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": requirement_id,
                    "authority_kind": authority_kind,
                    "path": FIXTURE,
                    "description": f"Fixture {authority_kind} evidence for {requirement_id}.",
                }
                for requirement_id in requirements
                for authority_kind in _allowed_authority_kinds_for_requirement(reference_requirements[requirement_id])
            ],
        )
        result = verify_external_evidence_manifest(manifest, audit, root=ROOT, require_complete=True)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("complete", manifest["summary"]["status"])
        self.assertEqual(len(requirements), result.covered_count)
        self.assertEqual(result.required_authority_kind_count, result.covered_authority_kind_count)
        self.assertEqual(0, result.missing_authority_kind_count)
        self.assertEqual(
            manifest["summary"]["required_authority_kind_count"],
            len(manifest["required_authority_evidence_units"]),
        )
        self.assertTrue(all(unit["coverage_status"] == "covered" for unit in manifest["required_authority_evidence_units"]))

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="external-evidence-complete")
            append_roadmap_audit(chain, audit, root=ROOT)
            entry = append_external_evidence_manifest(chain, manifest, audit, root=ROOT, require_complete=True)
            chain_result = verify_roadmap_evidence_chain(chain, require_external=True, require_complete=True)
            self.assertTrue(chain_result.ok, chain_result.errors)
            self.assertEqual(1, chain_result.complete_external_evidence_entry_count)
            self.assertEqual(0, entry["payload"]["missing_authority_kind_count"])

    def test_external_evidence_rejects_wrong_authority_kind_for_requirement(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )
        tampered = copy.deepcopy(manifest)
        item = tampered["evidence"][0]
        item["authority_kind"] = "customer"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        tampered["manifest_id"] = content_hash(without_keys(tampered, "manifest_id"))
        result = verify_external_evidence_manifest(tampered, audit, root=ROOT)
        self.assertFalse(result.ok)
        self.assertTrue(
            any(
                "authority kind customer is not accepted for requirement oss-verifier-and-public-spec" in error
                for error in result.errors
            ),
            result.errors,
        )

    def test_external_evidence_rejects_stale_authority_evidence_units(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )
        tampered = copy.deepcopy(manifest)
        tampered["required_authority_evidence_units"] = tampered["required_authority_evidence_units"][:-1]
        tampered["manifest_id"] = content_hash(without_keys(tampered, "manifest_id"))

        result = verify_external_evidence_manifest(tampered, audit, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(
            any("required_authority_evidence_units" in error for error in result.errors),
            result.errors,
        )

    def test_external_evidence_detects_artifact_hash_tamper(self):
        audit = build_roadmap_audit(ROOT)
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": "oss-verifier-and-public-spec",
                    "authority_kind": "ci-run",
                    "path": FIXTURE,
                    "description": "Recorded verifier workflow run export.",
                }
            ],
        )
        tampered = copy.deepcopy(manifest)
        tampered["evidence"][0]["sha256"] = "sha256:" + "0" * 64

        result = verify_external_evidence_manifest(tampered, audit, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("manifest_id" in error for error in result.errors))
        self.assertTrue(any("hash mismatch" in error for error in result.errors))

    def test_parse_evidence_arg(self):
        parsed = parse_evidence_arg(
            "oss-verifier-and-public-spec,ci-run,examples/aitrade/external-evidence/go-verifier-workflow-run.json,GitHub workflow export;issuer=GitHub Actions;subject=trustai go verifier;source_uri=https://github.com/MSBeni/trust_ai/actions;issued_at=2026-07-08T00:00:00Z;expires_at=2026-12-31T00:00:00Z"
        )

        self.assertEqual("oss-verifier-and-public-spec", parsed["requirement_id"])
        self.assertEqual("ci-run", parsed["authority_kind"])
        self.assertEqual(FIXTURE, parsed["path"])
        self.assertEqual("GitHub workflow export", parsed["description"])
        self.assertEqual("GitHub Actions", parsed["issuer"])
        self.assertEqual("trustai go verifier", parsed["subject"])
        self.assertEqual("2026-07-08T00:00:00Z", parsed["issued_at"])
        self.assertEqual("2026-12-31T00:00:00Z", parsed["expires_at"])
        with self.assertRaisesRegex(ValueError, "unsupported evidence metadata"):
            parse_evidence_arg(
                "oss-verifier-and-public-spec,ci-run,examples/aitrade/external-evidence/go-verifier-workflow-run.json,GitHub workflow export;unknown=value"
            )

    def test_parse_bundle_source_artifact_arg(self):
        parsed = parse_bundle_source_artifact_arg(
            "roadmap-audit,artifacts/roadmap-audit.json,Generated roadmap audit JSON"
        )

        self.assertEqual("roadmap-audit", parsed["kind"])
        self.assertEqual("artifacts/roadmap-audit.json", parsed["path"])
        self.assertEqual("Generated roadmap audit JSON", parsed["description"])
        with self.assertRaisesRegex(ValueError, "source artifact"):
            parse_bundle_source_artifact_arg("roadmap-audit,artifacts/roadmap-audit.json")


if __name__ == "__main__":
    unittest.main()
