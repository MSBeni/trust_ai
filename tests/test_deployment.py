import copy
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.deployment import (
    DEPLOYMENT_ENTRY_TYPE,
    DEPLOYMENT_MANIFEST_SCHEMA,
    append_deployment_manifest,
    build_deployment_manifest,
    render_deployment_markdown,
    verify_deployment_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


class DeploymentManifestTests(unittest.TestCase):
    def test_deployment_manifest_verifies_scaffold_and_appends(self):
        manifest = build_deployment_manifest(ROOT, environment="test-byoc")
        result = verify_deployment_manifest(manifest, root=ROOT)
        markdown = render_deployment_markdown(manifest)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="deployment-test")
            entry = append_deployment_manifest(chain, manifest, root=ROOT)

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(DEPLOYMENT_MANIFEST_SCHEMA, manifest["schema"])
            self.assertEqual("docker-image-plus-helm-chart", manifest["deployment"]["artifact_type"])
            self.assertIn("deploy/docker/Dockerfile", {source["path"] for source in manifest["source_files"]})
            self.assertIn("planned-production", entry["payload"]["control_summary"])
            self.assertIn("# TrustAI Deployment Manifest", markdown)
            self.assertEqual(DEPLOYMENT_ENTRY_TYPE, entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)

    def test_deployment_manifest_detects_source_hash_tamper(self):
        manifest = build_deployment_manifest(ROOT)
        tampered = copy.deepcopy(manifest)
        tampered["source_files"][0]["sha256"] = "0" * 64

        result = verify_deployment_manifest(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("manifest_id does not match canonical manifest body", result.errors)
        self.assertTrue(any("sha256 mismatch" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
