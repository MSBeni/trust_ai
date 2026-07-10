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
    HELM_CHART_VALIDATION_ENTRY_TYPE,
    HELM_CHART_VALIDATION_SCHEMA,
    append_deployment_manifest,
    append_helm_chart_validation_receipt,
    build_deployment_manifest,
    build_helm_chart_validation_receipt,
    render_deployment_markdown,
    verify_deployment_manifest,
    verify_helm_chart_validation_receipt,
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

    def test_helm_chart_validation_receipt_verifies_and_appends(self):
        manifest = build_deployment_manifest(ROOT, environment="test-byoc")
        receipt = build_helm_chart_validation_receipt(ROOT, deployment_manifest=manifest, generated_at="2026-07-04T00:30:00Z")
        result = verify_helm_chart_validation_receipt(receipt, root=ROOT, deployment_manifest=manifest)
        check_ids = {check["id"] for check in receipt["checks"]}
        source_paths = {source["path"] for source in receipt["source_files"]}

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="helm-validation-test")
            entry = append_helm_chart_validation_receipt(chain, receipt, root=ROOT, deployment_manifest=manifest)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(HELM_CHART_VALIDATION_SCHEMA, receipt["schema"])
            self.assertTrue(receipt["passed"])
            self.assertEqual({"failed": 0, "passed": 13, "total": 13}, receipt["summary"])
            self.assertEqual(manifest["manifest_id"], receipt["deployment_manifest"]["manifest_id"])
            self.assertIn("deployment-secret-backed-key", check_ids)
            self.assertIn("deployment-health-probes", check_ids)
            self.assertIn("service-resource", check_ids)
            self.assertIn("deploy/helm/trustai/templates/deployment.yaml", source_paths)
            self.assertIn("deploy/helm/trustai/templates/service.yaml", source_paths)
            self.assertEqual(HELM_CHART_VALIDATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertEqual({"failed": 0, "passed": 13, "total": 13}, entry["payload"]["check_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_helm_chart_validation_receipt_detects_source_tamper(self):
        manifest = build_deployment_manifest(ROOT, environment="test-byoc")
        receipt = build_helm_chart_validation_receipt(ROOT, deployment_manifest=manifest)
        tampered = copy.deepcopy(receipt)
        tampered["source_files"][0]["sha256"] = "0" * 64

        result = verify_helm_chart_validation_receipt(tampered, root=ROOT, deployment_manifest=manifest)

        self.assertFalse(result.ok)
        self.assertIn("receipt_id does not match canonical Helm chart validation body", result.errors)
        self.assertTrue(any("sha256 mismatch" in error for error in result.errors))

    def test_cli_helm_chart_validation_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest_path = tmp / "deployment-manifest.json"
            receipt_path = tmp / "helm-chart-validation.json"
            entry_path = tmp / "helm-chart-validation-entry.json"
            chain_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            subprocess.run(
                base
                + [
                    "deployment-manifest",
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
            subprocess.run(
                base
                + [
                    "helm-chart-validation",
                    str(manifest_path),
                    "--root",
                    str(ROOT),
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "helm-chart-validation-verify",
                    str(receipt_path),
                    str(manifest_path),
                    "--root",
                    str(ROOT),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "helm-chart-validation-append",
                    str(receipt_path),
                    str(manifest_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "helm-validation-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(chain_path, tenant_id="helm-validation-cli")

        self.assertTrue(receipt["passed"])
        self.assertEqual(HELM_CHART_VALIDATION_ENTRY_TYPE, entry["entry_type"])
        self.assertTrue(chain.verify_all().ok)

if __name__ == "__main__":
    unittest.main()
