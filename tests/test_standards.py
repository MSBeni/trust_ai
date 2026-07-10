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
        mcp_target = next(target for target in package["conformance_targets"] if target["id"] == "mcp-proxy-capture-receipts")
        self.assertIn("retained source export byte replay", mcp_target["description"])
        self.assertTrue(any("--events examples/aitrade/mcp-proxy-events.json" in command for command in mcp_target["commands"]))
        self.assertIn("traffic-holdout-export-v0.1.md", markdown)
        self.assertIn("traffic-holdout-export-receipts", markdown)
        self.assertIn("traffic-completeness-receipt-v0.1.md", markdown)
        self.assertIn("traffic-completeness", markdown)
        traffic_target = next(target for target in package["conformance_targets"] if target["id"] == "traffic-holdout-export-receipts")
        self.assertIn("retained provider export byte replay", traffic_target["description"])
        self.assertTrue(any("traffic-completeness-provider-export.json" in command for command in traffic_target["commands"]))
        self.assertIn("promotion-status-receipt-v0.1.md", markdown)
        self.assertIn("promotion-status-receipts", markdown)
        provider_delivery_target = next(target for target in package["conformance_targets"] if target["id"] == "provider-delivery-receipts")
        self.assertIn("retained payload artifact byte replay", provider_delivery_target["description"])
        provider_webhook_target = next(target for target in package["conformance_targets"] if target["id"] == "provider-webhook-receipts")
        self.assertIn("retained payload artifact byte replay", provider_webhook_target["description"])
        self.assertTrue(any("examples/webhooks/github-check-suite.json" in command for command in provider_webhook_target["commands"]))
        provider_delivery_service_target = next(target for target in package["conformance_targets"] if target["id"] == "provider-delivery-service-attestations")
        self.assertIn("retained payload artifact replay", provider_delivery_service_target["description"])
        self.assertIn("soak-demotion-receipt-v0.1.md", markdown)
        self.assertIn("soak-demotion-receipts", markdown)
        self.assertIn("deployment-manifest-v0.1.md", markdown)
        self.assertIn("helm-chart-validation-v0.1.md", markdown)
        self.assertIn("deployment-image-integrity-v0.1.md", markdown)
        self.assertIn("deployment-manifest-attestation", markdown)
        self.assertIn("BYOC API Deployment", markdown)
        self.assertIn("byoc-production-authority-dossiers", markdown)
        byoc_target = next(target for target in package["conformance_targets"] if target["id"] == "byoc-production-authority-dossiers")
        self.assertIn("retained authority artifact replay", byoc_target["description"])
        self.assertTrue(any("--authority-artifact" in command for command in byoc_target["commands"]))
        self.assertTrue(any("byoc-network-policy-authority-export.json" in command for command in byoc_target["commands"]))
        verifier_release_authority_target = next(target for target in package["conformance_targets"] if target["id"] == "verifier-public-release-authority-dossiers")
        self.assertIn("retained provider workflow export replay", verifier_release_authority_target["description"])
        self.assertTrue(any("--authority-artifact" in command for command in verifier_release_authority_target["commands"]))
        self.assertTrue(any("go-verifier-workflow-run.json" in command for command in verifier_release_authority_target["commands"]))

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
