import copy
import unittest
from pathlib import Path

from trustai.standards import (
    REQUIRED_SPEC_PATHS,
    STANDARDS_SUBMISSION_SCHEMA,
    build_standards_submission,
    render_standards_markdown,
    verify_standards_submission,
)


ROOT = Path(__file__).resolve().parents[1]


class StandardsSubmissionTests(unittest.TestCase):
    def test_standards_submission_hashes_public_specs_and_verifies(self):
        package = build_standards_submission(ROOT)
        result = verify_standards_submission(package, root=ROOT)
        markdown = render_standards_markdown(package)
        paths = {spec["path"] for spec in package["specs"]}

        self.assertEqual(STANDARDS_SUBMISSION_SCHEMA, package["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertTrue(set(REQUIRED_SPEC_PATHS).issubset(paths))
        self.assertIn("TrustAI Standards Submission Package", markdown)
        self.assertIn("proof-pack-v0.1.md", markdown)
        self.assertIn("design-partner-pilot-v0.1.md", markdown)
        self.assertIn("design-partner-pilot-dossiers", markdown)
        self.assertIn("own-compliance-dossier-v0.1.md", markdown)
        self.assertIn("trustai-own-compliance-dossiers", markdown)
        self.assertIn("state-of-agent-reliability-report-v0.1.md", markdown)
        self.assertIn("state-of-agent-reliability-reports", markdown)
        self.assertIn("roadmap-phase-scoreboard-v0.1.md", markdown)
        self.assertIn("roadmap-phase-scoreboards", markdown)
        self.assertIn("product-scope-decision-v0.1.md", markdown)
        self.assertIn("product-scope-decisions", markdown)
        self.assertIn("mcp-gateway-v0.1.md", markdown)
        self.assertIn("mcp-proxy-capture-receipts", markdown)
        self.assertIn("traffic-holdout-export-v0.1.md", markdown)
        self.assertIn("traffic-holdout-export-receipts", markdown)
        self.assertIn("traffic-completeness-receipt-v0.1.md", markdown)
        self.assertIn("traffic-completeness", markdown)
        self.assertIn("promotion-status-receipt-v0.1.md", markdown)
        self.assertIn("promotion-status-receipts", markdown)
        self.assertIn("soak-demotion-receipt-v0.1.md", markdown)
        self.assertIn("soak-demotion-receipts", markdown)

    def test_standards_submission_detects_spec_hash_tamper(self):
        package = build_standards_submission(ROOT)
        tampered = copy.deepcopy(package)
        tampered["specs"][0]["content_hash"] = "changed"

        result = verify_standards_submission(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("package_id" in error for error in result.errors))
        self.assertTrue(any("content_hash mismatch" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
