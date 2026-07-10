import copy
import json
import os
import subprocess
import sys
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
        source_paths = {source["path"] for source in manifest["source_files"]}
        component_ids = {component["id"] for component in manifest["components"]}
        control_ids = {control["id"] for control in manifest["controls"]}

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="deployment-test")
            entry = append_deployment_manifest(chain, manifest, root=ROOT)

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(DEPLOYMENT_MANIFEST_SCHEMA, manifest["schema"])
            self.assertEqual("docker-image-plus-helm-chart", manifest["deployment"]["artifact_type"])
            self.assertEqual("8080", manifest["deployment"]["api"]["port"])
            self.assertEqual("/data/server/evidence-chain.json", manifest["deployment"]["api"]["state_path"])
            self.assertIn("deploy/docker/Dockerfile", source_paths)
            self.assertIn("deploy/helm/trustai/templates/deployment.yaml", source_paths)
            self.assertIn("deploy/helm/trustai/templates/service.yaml", source_paths)
            self.assertIn("deploy/helm/trustai/templates/demo-job.yaml", source_paths)
            self.assertIn("local-ingestion-api", component_ids)
            self.assertIn("api-service", component_ids)
            self.assertIn("self-hosted-api-service", control_ids)
            self.assertIn("api-health-probes", control_ids)
            self.assertIn("planned-production", entry["payload"]["control_summary"])
            self.assertGreaterEqual(entry["payload"]["control_summary"].get("implemented-reference", 0), 5)
            self.assertIn("deploy/helm/trustai/templates/deployment.yaml", markdown)
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

    def test_deployment_manifest_requires_api_service_component(self):
        manifest = build_deployment_manifest(ROOT)
        tampered = copy.deepcopy(manifest)
        tampered["components"] = [component for component in tampered["components"] if component.get("id") != "api-service"]

        result = verify_deployment_manifest(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("manifest_id does not match canonical manifest body", result.errors)
        self.assertIn("deployment component missing: api-service", result.errors)

    def test_cli_deployment_manifest_resolves_env_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_path = Path(tmp_dir) / "deployment-manifest.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "TRUSTAI_TEST_SIGNING_KEY": "helm-secret"}
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "deployment-manifest",
                    "--key",
                    "env:TRUSTAI_TEST_SIGNING_KEY",
                    "--root",
                    str(ROOT),
                    "--environment",
                    "test-byoc",
                    "--out",
                    str(manifest_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        result = verify_deployment_manifest(manifest, root=ROOT, key="helm-secret")

        self.assertTrue(result.ok, result.errors)


if __name__ == "__main__":
    unittest.main()
