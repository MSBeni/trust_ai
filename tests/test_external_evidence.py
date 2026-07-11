import copy
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.external_evidence import (
    EXTERNAL_EVIDENCE_ENTRY_TYPE,
    EXTERNAL_EVIDENCE_SCHEMA,
    EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA,
    EXTERNAL_EVIDENCE_INTAKE_SCHEMA,
    EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA,
    ROADMAP_EVIDENCE_REPORT_SCHEMA,
    ROADMAP_EVIDENCE_BUNDLE_SCHEMA,
    _allowed_authority_kinds_for_requirement,
    _authority_unit_id,
    append_external_evidence_manifest,
    build_external_evidence_manifest,
    build_external_evidence_manifest_from_intakes,
    build_external_evidence_collection_plan,
    build_external_evidence_intake,
    build_external_evidence_source_snapshot,
    build_roadmap_evidence_bundle,
    extract_roadmap_evidence_bundle_sources,
    build_roadmap_evidence_report,
    load_roadmap_evidence_report,
    load_external_evidence_manifest,
    load_external_evidence_collection_plan,
    load_external_evidence_intake,
    load_external_evidence_intakes,
    load_external_evidence_source_snapshot,
    load_roadmap_evidence_bundle,
    parse_evidence_arg,
    parse_bundle_source_artifact_arg,
    render_external_evidence_markdown,
    render_external_evidence_collection_plan_markdown,
    render_roadmap_evidence_markdown,
    render_roadmap_evidence_bundle_markdown,
    verify_external_evidence_manifest,
    verify_external_evidence_collection_plan,
    verify_external_evidence_intake,
    verify_external_evidence_source_snapshot,
    verify_roadmap_evidence_chain,
    verify_roadmap_evidence_bundle,
    verify_roadmap_evidence_report,
    write_external_evidence_collection_plan,
    write_external_evidence_manifest,
)
from trustai.roadmap_audit import STATUS_REFERENCE_ATTESTED, append_roadmap_audit, build_roadmap_audit, write_roadmap_audit


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
        self.assertEqual(69, plan["summary"]["selected_missing_task_count"])
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
                self.assertEqual("sha256:" + sha256(snapshot_path.read_bytes()).hexdigest(), intake["evidence_item"]["sha256"])
                self.assertIn("oss-verifier-and-public-spec,ci-run", intake["evidence_argument"])
            finally:
                shutil.rmtree(snapshot_path.parent, ignore_errors=True)

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
        self.assertEqual(68, rebuilt["summary"]["missing_authority_kind_count"])

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
            self.assertEqual(69, plan["summary"]["selected_task_count"])
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
