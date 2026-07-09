import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.external_evidence import (
    EXTERNAL_EVIDENCE_ENTRY_TYPE,
    EXTERNAL_EVIDENCE_SCHEMA,
    ROADMAP_EVIDENCE_REPORT_SCHEMA,
    ROADMAP_EVIDENCE_BUNDLE_SCHEMA,
    append_external_evidence_manifest,
    build_external_evidence_manifest,
    build_roadmap_evidence_bundle,
    build_roadmap_evidence_report,
    load_roadmap_evidence_report,
    load_roadmap_evidence_bundle,
    parse_evidence_arg,
    parse_bundle_source_artifact_arg,
    render_external_evidence_markdown,
    render_roadmap_evidence_markdown,
    render_roadmap_evidence_bundle_markdown,
    verify_external_evidence_manifest,
    verify_roadmap_evidence_chain,
    verify_roadmap_evidence_bundle,
    verify_roadmap_evidence_report,
)
from trustai.roadmap_audit import STATUS_REFERENCE_ATTESTED, append_roadmap_audit, build_roadmap_audit


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
        self.assertIn("oss-verifier-and-public-spec", markdown)

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
            report_path = tmp_path / "roadmap-evidence-report.json"
            report_markdown_path = tmp_path / "roadmap-evidence-report.md"
            bundle_path = tmp_path / "roadmap-evidence-bundle.json"
            bundle_markdown_path = tmp_path / "roadmap-evidence-bundle.md"
            chain_path = tmp_path / "chain.json"
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
                    f"oss-verifier-and-public-spec,ci-run,{FIXTURE},Recorded Go verifier workflow export",
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
                    "external-evidence-append",
                    str(manifest_path),
                    str(audit_path),
                    "--root",
                    str(ROOT),
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
                    "--report",
                    str(report_path),
                    "--root",
                    str(tmp_path),
                    "--source-artifact",
                    f"roadmap-audit,{audit_path.name},Generated roadmap audit JSON",
                    "--source-artifact",
                    f"external-evidence-manifest,{manifest_path.name},Generated external evidence manifest JSON",
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
                ],
                cwd=ROOT,
                check=True,
            )
            chain = EvidenceChain.load(chain_path, tenant_id="external-evidence-cli")
            self.assertEqual(2, len(chain.entries))
            self.assertEqual(EXTERNAL_EVIDENCE_ENTRY_TYPE, chain.entries[1]["entry_type"])
            self.assertEqual(chain.entries[0]["entry_id"], chain.entries[1]["payload"]["source_roadmap_audit_inclusion_proof"]["entry_id"])
            self.assertTrue(chain.verify_all().ok)
            report = load_roadmap_evidence_report(report_path)
            self.assertEqual(2, report["summary"]["chain_entry_count"])
            self.assertTrue(report_markdown_path.exists())
            bundle = load_roadmap_evidence_bundle(bundle_path)
            self.assertEqual(report["report_id"], bundle["summary"]["report_id"])
            self.assertEqual(2, bundle["summary"]["source_artifact_count"])
            self.assertEqual(["roadmap-audit", "external-evidence-manifest"], [artifact["kind"] for artifact in bundle["source_artifacts"]])
            self.assertTrue(bundle_markdown_path.exists())
            self.assertIn("Embedded source artifacts: 2", bundle_markdown_path.read_text(encoding="utf-8"))
            tampered_bundle = copy.deepcopy(bundle)
            tampered_bundle["source_artifacts"][0]["sha256"] = "sha256:" + "0" * 64
            tampered_result = verify_roadmap_evidence_bundle(tampered_bundle, require_external=True)
            self.assertFalse(tampered_result.ok)
            self.assertTrue(any("source artifact" in error for error in tampered_result.errors))

    def test_complete_external_evidence_manifest_covers_reference_requirements(self):
        audit = build_roadmap_audit(ROOT)
        requirements = [
            requirement["id"]
            for requirement in audit["requirements"]
            if requirement["status"] == STATUS_REFERENCE_ATTESTED
        ]
        manifest = build_external_evidence_manifest(
            audit,
            root=ROOT,
            evidence=[
                {
                    "requirement_id": requirement_id,
                    "authority_kind": "other",
                    "path": FIXTURE,
                    "description": f"Fixture evidence for {requirement_id}.",
                }
                for requirement_id in requirements
            ],
        )
        result = verify_external_evidence_manifest(manifest, audit, root=ROOT, require_complete=True)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("complete", manifest["summary"]["status"])
        self.assertEqual(len(requirements), result.covered_count)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="external-evidence-complete")
            append_roadmap_audit(chain, audit, root=ROOT)
            append_external_evidence_manifest(chain, manifest, audit, root=ROOT, require_complete=True)
            chain_result = verify_roadmap_evidence_chain(chain, require_external=True, require_complete=True)
            self.assertTrue(chain_result.ok, chain_result.errors)
            self.assertEqual(1, chain_result.complete_external_evidence_entry_count)

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
            "oss-verifier-and-public-spec,ci-run,examples/aitrade/external-evidence/go-verifier-workflow-run.json,GitHub workflow export"
        )

        self.assertEqual("oss-verifier-and-public-spec", parsed["requirement_id"])
        self.assertEqual("ci-run", parsed["authority_kind"])
        self.assertEqual(FIXTURE, parsed["path"])

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
