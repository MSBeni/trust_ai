import copy
import unittest
from pathlib import Path

from trustai.roadmap_audit import (
    ROADMAP_AUDIT_SCHEMA,
    STATUS_IMPLEMENTED_LOCAL,
    STATUS_MISSING_LOCAL_EVIDENCE,
    STATUS_REFERENCE_ATTESTED,
    build_roadmap_audit,
    render_roadmap_audit_markdown,
    verify_roadmap_audit,
)


ROOT = Path(__file__).resolve().parents[1]


class RoadmapAuditTests(unittest.TestCase):
    def test_roadmap_audit_hashes_local_evidence_and_verifies(self):
        audit = build_roadmap_audit(ROOT)
        result = verify_roadmap_audit(audit, root=ROOT)
        statuses = {requirement["status"] for requirement in audit["requirements"]}
        requirement_ids = {requirement["id"] for requirement in audit["requirements"]}
        markdown = render_roadmap_audit_markdown(audit)

        self.assertEqual(ROADMAP_AUDIT_SCHEMA, audit["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertIn(STATUS_IMPLEMENTED_LOCAL, statuses)
        self.assertIn(STATUS_REFERENCE_ATTESTED, statuses)
        self.assertNotIn(STATUS_MISSING_LOCAL_EVIDENCE, statuses)
        self.assertIn("proof-pack-spec-and-compiler", requirement_ids)
        self.assertIn("trust-network-procurement-and-marketplace", requirement_ids)
        self.assertGreater(audit["summary"][STATUS_REFERENCE_ATTESTED], 0)
        self.assertIn("TrustAI Roadmap Audit", markdown)
        self.assertIn("Deferred External Authority", markdown)

    def test_roadmap_audit_detects_hash_tamper(self):
        audit = build_roadmap_audit(ROOT)
        tampered = copy.deepcopy(audit)
        tampered["source"]["roadmap"]["sha256"] = "sha256:" + "0" * 64

        result = verify_roadmap_audit(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("audit_id" in error for error in result.errors))
        self.assertTrue(any("source:roadmap" in error and "hash mismatch" in error for error in result.errors))

    def test_roadmap_audit_detects_missing_local_evidence(self):
        audit = build_roadmap_audit(ROOT)
        tampered = copy.deepcopy(audit)
        requirement = tampered["requirements"][0]
        requirement["evidence"][0]["path"] = "missing/local/evidence.py"

        result = verify_roadmap_audit(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("evidence path missing" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
