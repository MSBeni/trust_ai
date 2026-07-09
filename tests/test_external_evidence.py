import copy
import unittest
from pathlib import Path

from trustai.external_evidence import (
    EXTERNAL_EVIDENCE_SCHEMA,
    build_external_evidence_manifest,
    parse_evidence_arg,
    render_external_evidence_markdown,
    verify_external_evidence_manifest,
)
from trustai.roadmap_audit import STATUS_REFERENCE_ATTESTED, build_roadmap_audit


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


if __name__ == "__main__":
    unittest.main()
