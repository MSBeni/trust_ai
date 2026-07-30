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
    AIRGAP_BUNDLE_ENTRY_TYPE,
    AIRGAP_BUNDLE_SCHEMA,
    DEPLOYMENT_ENTRY_TYPE,
    DEPLOYMENT_IMAGE_INTEGRITY_ENTRY_TYPE,
    DEPLOYMENT_IMAGE_INTEGRITY_SCHEMA,
    DEPLOYMENT_IMAGE_SIGNATURE_SCHEMA,
    DEPLOYMENT_MANIFEST_SCHEMA,
    HELM_CHART_VALIDATION_ENTRY_TYPE,
    HELM_CHART_VALIDATION_SCHEMA,
    KUBERNETES_RELEASE_STATE_ENTRY_TYPE,
    KUBERNETES_RELEASE_STATE_SCHEMA,
    append_airgap_install_bundle,
    append_deployment_image_integrity_receipt,
    append_deployment_manifest,
    append_helm_chart_validation_receipt,
    append_kubernetes_release_state_receipt,
    build_airgap_install_bundle,
    build_deployment_image_integrity_receipt,
    build_deployment_image_signature_artifact,
    build_deployment_manifest,
    build_helm_chart_validation_receipt,
    build_kubernetes_release_state_receipt,
    render_deployment_markdown,
    write_deployment_image_signature_artifact,
    verify_airgap_install_bundle,
    verify_deployment_image_integrity_receipt,
    verify_deployment_manifest,
    verify_helm_chart_validation_receipt,
    verify_kubernetes_release_state_receipt,
)

ROOT = Path(__file__).resolve().parents[1]


class DeploymentManifestTests(unittest.TestCase):
    def _airgap_receipts(self, tmp: Path):
        manifest = build_deployment_manifest(ROOT, environment="test-airgap", generated_at="2026-07-04T00:00:00Z")
        helm_receipt = build_helm_chart_validation_receipt(ROOT, deployment_manifest=manifest, generated_at="2026-07-04T00:30:00Z")
        digest = "sha256:" + "f" * 64
        sbom = tmp / "trustai-image.sbom.json"
        provenance = tmp / "trustai-image.provenance.json"
        signature = tmp / "trustai-image.sig"
        sbom.write_text('{"sbom":"trustai","version":"0.1.0"}', encoding="utf-8")
        provenance.write_text('{"builder":"trustai-local","source":"git"}', encoding="utf-8")
        signature_artifact = build_deployment_image_signature_artifact(ROOT, deployment_manifest=manifest, image_digest=digest, sbom_path=sbom, provenance_path=provenance, generated_at="2026-07-04T00:44:00Z")
        write_deployment_image_signature_artifact(signature, signature_artifact)
        image_receipt = build_deployment_image_integrity_receipt(ROOT, deployment_manifest=manifest, image_digest=digest, sbom_path=sbom, provenance_path=provenance, signature_path=signature, generated_at="2026-07-04T00:45:00Z")
        release_receipt = build_kubernetes_release_state_receipt(
            ROOT,
            deployment_manifest=manifest,
            helm_chart_validation=helm_receipt,
            environment="test-airgap",
            provider="Example Kubernetes API",
            cluster_ref="k8s:cluster/aitrade-prod",
            namespace="trustai",
            release_name="trustai",
            release_revision="7",
            release_status="deployed",
            export_ref="k8s-export:aitrade-prod/trustai/2026-07-04",
            export_hash="sha256:" + "a" * 64,
            service_account_ref="k8s:sa/trustai/trustai-api",
            deployment_ref="k8s:deployment/trustai/trustai-api",
            service_ref="k8s:service/trustai/trustai-api",
            network_policy_ref="k8s:networkpolicy/trustai/trustai-api",
            secret_ref="k8s:secret/trustai/trustai-signing-key",
            desired_replicas=2,
            ready_replicas=2,
            network_policy_admitted=True,
            pod_selector_hash="sha256:" + "b" * 64,
            ingress_policy_hash="sha256:" + "c" * 64,
            egress_policy_hash="sha256:" + "d" * 64,
            audit_log_ref="audit-log:kubernetes/aitrade-prod/trustai",
            audit_log_root="sha256:" + "e" * 64,
            exported_at="2026-07-04T03:08:00Z",
            issued_at="2026-07-04T03:08:00Z",
            expires_at="2026-07-05T03:08:00Z",
            generated_at="2026-07-04T03:10:00Z",
        )
        return manifest, helm_receipt, image_receipt, release_receipt

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
            self.assertIn("deploy/helm/trustai/templates/networkpolicy.yaml", source_paths)
            self.assertIn("deploy/helm/trustai/templates/demo-job.yaml", source_paths)
            self.assertIn("local-ingestion-api", component_ids)
            self.assertIn("api-service", component_ids)
            self.assertIn("api-network-policy", component_ids)
            self.assertIn("self-hosted-api-service", control_ids)
            self.assertIn("api-health-probes", control_ids)
            self.assertIn("deployment-image-integrity-receipts", control_ids)
            self.assertIn("network-policy-egress-controls", control_ids)
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


    def test_deployment_image_integrity_receipt_verifies_and_appends(self):
        manifest = build_deployment_manifest(ROOT, environment="test-byoc")
        digest = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sbom = tmp / "trustai-image.sbom.json"
            provenance = tmp / "trustai-image.provenance.json"
            signature = tmp / "trustai-image.sig"
            sbom.write_text('{"sbom":"trustai","version":"0.1.0"}', encoding="utf-8")
            provenance.write_text('{"builder":"trustai-local","source":"git"}', encoding="utf-8")
            signature_artifact = build_deployment_image_signature_artifact(
                ROOT,
                deployment_manifest=manifest,
                image_digest=digest,
                sbom_path=sbom,
                provenance_path=provenance,
                generated_at="2026-07-04T00:44:00Z",
            )
            write_deployment_image_signature_artifact(signature, signature_artifact)
            receipt = build_deployment_image_integrity_receipt(
                ROOT,
                deployment_manifest=manifest,
                image_digest=digest,
                sbom_path=sbom,
                provenance_path=provenance,
                signature_path=signature,
                generated_at="2026-07-04T00:45:00Z",
            )
            result = verify_deployment_image_integrity_receipt(receipt, root=ROOT, deployment_manifest=manifest)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="image-integrity-test")
            entry = append_deployment_image_integrity_receipt(chain, receipt, root=ROOT, deployment_manifest=manifest)
            check_ids = {check["id"] for check in receipt["checks"]}
            artifact_kinds = {artifact["kind"] for artifact in receipt["artifacts"]}
            source_paths = {source["path"] for source in receipt["source_files"]}

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(DEPLOYMENT_IMAGE_INTEGRITY_SCHEMA, receipt["schema"])
            self.assertTrue(receipt["passed"])
            self.assertEqual({"failed": 0, "passed": 11, "total": 11}, receipt["summary"])
            self.assertEqual("trustai:0.1.0", receipt["image"]["image_ref"])
            self.assertEqual(digest, receipt["image"]["image_digest"])
            self.assertEqual(f"trustai:0.1.0@{digest}", receipt["image"]["pinned_reference"])
            self.assertEqual(manifest["manifest_id"], receipt["deployment_manifest"]["manifest_id"])
            self.assertIn("image-digest-present", check_ids)
            self.assertIn("sbom-artifact-bound", check_ids)
            self.assertIn("provenance-artifact-bound", check_ids)
            self.assertIn("signature-artifact-bound", check_ids)
            self.assertIn("signature-artifact-verifies-subject", check_ids)
            self.assertTrue(receipt["image_signature"]["verified"])
            self.assertEqual(DEPLOYMENT_IMAGE_SIGNATURE_SCHEMA, signature_artifact["schema"])
            self.assertEqual({"sbom", "provenance", "signature"}, artifact_kinds)
            self.assertIn("deploy/docker/Dockerfile", source_paths)
            self.assertIn("src/trustai/server.py", source_paths)
            self.assertEqual(DEPLOYMENT_IMAGE_INTEGRITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertEqual({"failed": 0, "passed": 11, "total": 11}, entry["payload"]["check_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_deployment_image_integrity_receipt_detects_artifact_tamper(self):
        manifest = build_deployment_manifest(ROOT, environment="test-byoc")
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sbom = tmp / "trustai-image.sbom.json"
            provenance = tmp / "trustai-image.provenance.json"
            signature = tmp / "trustai-image.sig"
            sbom.write_text('{"sbom":"trustai"}', encoding="utf-8")
            provenance.write_text('{"builder":"trustai-local"}', encoding="utf-8")
            signature_artifact = build_deployment_image_signature_artifact(
                ROOT,
                deployment_manifest=manifest,
                image_digest="b" * 64,
                sbom_path=sbom,
                provenance_path=provenance,
            )
            write_deployment_image_signature_artifact(signature, signature_artifact)
            receipt = build_deployment_image_integrity_receipt(
                ROOT,
                deployment_manifest=manifest,
                image_digest="b" * 64,
                sbom_path=sbom,
                provenance_path=provenance,
                signature_path=signature,
            )
            signature.write_text("tampered-signature", encoding="utf-8")

            result = verify_deployment_image_integrity_receipt(receipt, root=ROOT, deployment_manifest=manifest)

        self.assertFalse(result.ok)
        self.assertTrue(any("artifact signature sha256 mismatch" in error for error in result.errors))
        self.assertTrue(any("deployment image integrity artifacts does not match replayed sources" in error for error in result.errors))


    def test_deployment_image_integrity_rejects_placeholder_signature_artifact(self):
        manifest = build_deployment_manifest(ROOT, environment="test-byoc")
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sbom = tmp / "trustai-image.sbom.json"
            provenance = tmp / "trustai-image.provenance.json"
            signature = tmp / "trustai-image.sig"
            sbom.write_text('{"sbom":"trustai"}', encoding="utf-8")
            provenance.write_text('{"builder":"trustai-local"}', encoding="utf-8")
            signature.write_text("sigstore-placeholder-signature", encoding="utf-8")
            receipt = build_deployment_image_integrity_receipt(
                ROOT,
                deployment_manifest=manifest,
                image_digest="sha256:" + "d" * 64,
                sbom_path=sbom,
                provenance_path=provenance,
                signature_path=signature,
            )
            result = verify_deployment_image_integrity_receipt(receipt, root=ROOT, deployment_manifest=manifest)

        self.assertFalse(result.ok)
        self.assertFalse(receipt["passed"])
        self.assertFalse(receipt["image_signature"]["verified"])
        self.assertTrue(any("signature-artifact-verifies-subject" in error for error in result.errors))

    def test_cli_deployment_image_integrity_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest_path = tmp / "deployment-manifest.json"
            receipt_path = tmp / "deployment-image-integrity.json"
            entry_path = tmp / "deployment-image-integrity-entry.json"
            chain_path = tmp / "chain.json"
            sbom = tmp / "trustai-image.sbom.json"
            provenance = tmp / "trustai-image.provenance.json"
            signature = tmp / "trustai-image.sig"
            sbom.write_text('{"sbom":"trustai","version":"0.1.0"}', encoding="utf-8")
            provenance.write_text('{"builder":"trustai-local","source":"git"}', encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            digest = "sha256:" + "c" * 64
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
                    "deployment-image-signature",
                    str(manifest_path),
                    "--root",
                    str(ROOT),
                    "--image-digest",
                    digest,
                    "--sbom",
                    str(sbom),
                    "--provenance",
                    str(provenance),
                    "--out",
                    str(signature),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "deployment-image-integrity",
                    str(manifest_path),
                    "--root",
                    str(ROOT),
                    "--image-digest",
                    digest,
                    "--sbom",
                    str(sbom),
                    "--provenance",
                    str(provenance),
                    "--signature",
                    str(signature),
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base + ["deployment-image-integrity-verify", str(receipt_path), str(manifest_path), "--root", str(ROOT)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "deployment-image-integrity-append",
                    str(receipt_path),
                    str(manifest_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "image-integrity-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(chain_path, tenant_id="image-integrity-cli")

        self.assertTrue(receipt["passed"])
        self.assertEqual(DEPLOYMENT_IMAGE_INTEGRITY_ENTRY_TYPE, entry["entry_type"])
        self.assertTrue(chain.verify_all().ok)

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
            self.assertEqual({"failed": 0, "passed": 15, "total": 15}, receipt["summary"])
            self.assertEqual(manifest["manifest_id"], receipt["deployment_manifest"]["manifest_id"])
            self.assertIn("deployment-secret-backed-key", check_ids)
            self.assertIn("deployment-health-probes", check_ids)
            self.assertIn("service-resource", check_ids)
            self.assertIn("network-policy-resource", check_ids)
            self.assertIn("network-policy-ingress-egress", check_ids)
            self.assertIn("deploy/helm/trustai/templates/deployment.yaml", source_paths)
            self.assertIn("deploy/helm/trustai/templates/service.yaml", source_paths)
            self.assertIn("deploy/helm/trustai/templates/networkpolicy.yaml", source_paths)
            self.assertEqual(HELM_CHART_VALIDATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertEqual({"failed": 0, "passed": 15, "total": 15}, entry["payload"]["check_summary"])
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

    def test_kubernetes_release_state_receipt_verifies_and_appends(self):
        manifest = build_deployment_manifest(ROOT, environment="test-byoc")
        helm_receipt = build_helm_chart_validation_receipt(ROOT, deployment_manifest=manifest, generated_at="2026-07-04T00:30:00Z")
        receipt = build_kubernetes_release_state_receipt(
            ROOT,
            deployment_manifest=manifest,
            helm_chart_validation=helm_receipt,
            environment="test-byoc",
            provider="Example Kubernetes API",
            cluster_ref="k8s:cluster/aitrade-prod",
            namespace="trustai",
            release_name="trustai",
            release_revision="7",
            release_status="deployed",
            export_ref="k8s-export:aitrade-prod/trustai/2026-07-04",
            export_hash="sha256:" + "a" * 64,
            service_account_ref="k8s:sa/trustai/trustai-api",
            deployment_ref="k8s:deployment/trustai/trustai-api",
            service_ref="k8s:service/trustai/trustai-api",
            network_policy_ref="k8s:networkpolicy/trustai/trustai-api",
            secret_ref="k8s:secret/trustai/trustai-signing-key",
            desired_replicas=2,
            ready_replicas=2,
            network_policy_admitted=True,
            pod_selector_hash="sha256:" + "b" * 64,
            ingress_policy_hash="sha256:" + "c" * 64,
            egress_policy_hash="sha256:" + "d" * 64,
            audit_log_ref="audit-log:kubernetes/aitrade-prod/trustai",
            audit_log_root="sha256:" + "e" * 64,
            exported_at="2026-07-04T03:08:00Z",
            issued_at="2026-07-04T03:08:00Z",
            expires_at="2026-07-05T03:08:00Z",
            generated_at="2026-07-04T03:10:00Z",
        )
        result = verify_kubernetes_release_state_receipt(
            receipt,
            root=ROOT,
            deployment_manifest=manifest,
            helm_chart_validation=helm_receipt,
        )
        check_ids = {check["id"] for check in receipt["checks"]}

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="kubernetes-release-test")
            entry = append_kubernetes_release_state_receipt(
                chain,
                receipt,
                root=ROOT,
                deployment_manifest=manifest,
                helm_chart_validation=helm_receipt,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(KUBERNETES_RELEASE_STATE_SCHEMA, receipt["schema"])
            self.assertTrue(receipt["passed"])
            self.assertEqual({"failed": 0, "passed": 10, "total": 10}, receipt["summary"])
            self.assertIn("network-policy-admitted", check_ids)
            self.assertIn("network-policy-rules-hashed", check_ids)
            self.assertEqual(KUBERNETES_RELEASE_STATE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertTrue(chain.verify_all().ok)

        malformed = json.loads(json.dumps(receipt))
        malformed["workload"]["ready_replicas"] = "not-an-integer"
        malformed_result = verify_kubernetes_release_state_receipt(
            malformed,
            root=ROOT,
            deployment_manifest=manifest,
            helm_chart_validation=helm_receipt,
        )

        self.assertFalse(malformed_result.ok)
        self.assertTrue(any("workload replicas invalid" in error for error in malformed_result.errors))

    def test_cli_kubernetes_release_state_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest_path = tmp / "deployment-manifest.json"
            helm_path = tmp / "helm-chart-validation.json"
            receipt_path = tmp / "kubernetes-release-state.json"
            entry_path = tmp / "kubernetes-release-state-entry.json"
            chain_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            subprocess.run(
                base + ["deployment-manifest", "--root", str(ROOT), "--environment", "test-byoc", "--out", str(manifest_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base + ["helm-chart-validation", str(manifest_path), "--root", str(ROOT), "--out", str(helm_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "kubernetes-release-state",
                    str(manifest_path),
                    str(helm_path),
                    "--root",
                    str(ROOT),
                    "--environment",
                    "test-byoc",
                    "--provider",
                    "Example Kubernetes API",
                    "--cluster-ref",
                    "k8s:cluster/aitrade-prod",
                    "--namespace",
                    "trustai",
                    "--release-name",
                    "trustai",
                    "--release-revision",
                    "7",
                    "--release-status",
                    "deployed",
                    "--export-ref",
                    "k8s-export:aitrade-prod/trustai/2026-07-04",
                    "--export-hash",
                    "sha256:" + "a" * 64,
                    "--service-account-ref",
                    "k8s:sa/trustai/trustai-api",
                    "--deployment-ref",
                    "k8s:deployment/trustai/trustai-api",
                    "--service-ref",
                    "k8s:service/trustai/trustai-api",
                    "--network-policy-ref",
                    "k8s:networkpolicy/trustai/trustai-api",
                    "--secret-ref",
                    "k8s:secret/trustai/trustai-signing-key",
                    "--desired-replicas",
                    "2",
                    "--ready-replicas",
                    "2",
                    "--pod-selector-hash",
                    "sha256:" + "b" * 64,
                    "--ingress-policy-hash",
                    "sha256:" + "c" * 64,
                    "--egress-policy-hash",
                    "sha256:" + "d" * 64,
                    "--audit-log-ref",
                    "audit-log:kubernetes/aitrade-prod/trustai",
                    "--audit-log-root",
                    "sha256:" + "e" * 64,
                    "--exported-at",
                    "2026-07-04T03:08:00Z",
                    "--issued-at",
                    "2026-07-04T03:08:00Z",
                    "--expires-at",
                    "2026-07-05T03:08:00Z",
                    "--generated-at",
                    "2026-07-04T03:10:00Z",
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base + ["kubernetes-release-state-verify", str(receipt_path), str(manifest_path), str(helm_path), "--root", str(ROOT)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "kubernetes-release-state-append",
                    str(receipt_path),
                    str(manifest_path),
                    str(helm_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "kubernetes-release-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(chain_path, tenant_id="kubernetes-release-cli")

        self.assertTrue(receipt["passed"])
        self.assertEqual(KUBERNETES_RELEASE_STATE_ENTRY_TYPE, entry["entry_type"])
        self.assertTrue(chain.verify_all().ok)


    def test_airgap_install_bundle_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest, helm_receipt, image_receipt, release_receipt = self._airgap_receipts(tmp)
            bundle = build_airgap_install_bundle(ROOT, deployment_manifest=manifest, helm_chart_validation=helm_receipt, deployment_image_integrity=image_receipt, kubernetes_release_state=release_receipt, environment="test-airgap", bundle_ref="bundle:trustai/airgap/test-airgap", producer_ref="oidc:trustai.example/airgap-bundler", generated_at="2026-07-04T04:00:00Z")
            result = verify_airgap_install_bundle(bundle, root=ROOT, deployment_manifest=manifest, helm_chart_validation=helm_receipt, deployment_image_integrity=image_receipt, kubernetes_release_state=release_receipt)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="airgap-bundle-test")
            entry = append_airgap_install_bundle(chain, bundle, root=ROOT, deployment_manifest=manifest, helm_chart_validation=helm_receipt, deployment_image_integrity=image_receipt, kubernetes_release_state=release_receipt)
            check_ids = {check["id"] for check in bundle["checks"]}
            source_paths = {source["path"] for source in bundle["source_files"]}

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(AIRGAP_BUNDLE_SCHEMA, bundle["schema"])
            self.assertTrue(bundle["passed"])
            self.assertEqual({"failed": 0, "passed": 11, "total": 11}, bundle["summary"])
            self.assertEqual(AIRGAP_BUNDLE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
            self.assertIn("image-pinned-digest", check_ids)
            self.assertIn("network-policy-admitted", check_ids)
            self.assertIn("offline-inputs-covered", check_ids)
            self.assertIn("docs/specs/airgap-install-bundle-v0.1.md", source_paths)
            self.assertEqual(image_receipt["image"], bundle["install_package"]["image"])
            self.assertTrue(chain.verify_all().ok)

    def test_airgap_install_bundle_rejects_replayed_image_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest, helm_receipt, image_receipt, release_receipt = self._airgap_receipts(tmp)
            bundle = build_airgap_install_bundle(ROOT, deployment_manifest=manifest, helm_chart_validation=helm_receipt, deployment_image_integrity=image_receipt, kubernetes_release_state=release_receipt, bundle_ref="bundle:trustai/airgap/test-airgap", producer_ref="oidc:trustai.example/airgap-bundler", generated_at="2026-07-04T04:00:00Z")
            tampered_image = copy.deepcopy(image_receipt)
            tampered_image["image"]["image_digest"] = "sha256:" + "9" * 64
            result = verify_airgap_install_bundle(bundle, root=ROOT, deployment_manifest=manifest, helm_chart_validation=helm_receipt, deployment_image_integrity=tampered_image, kubernetes_release_state=release_receipt)

            self.assertFalse(result.ok)
            self.assertTrue(any("deployment_image_integrity" in error for error in result.errors))

    def test_cli_airgap_install_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest, helm_receipt, image_receipt, release_receipt = self._airgap_receipts(tmp)
            manifest_path = tmp / "deployment-manifest.json"
            helm_path = tmp / "helm-chart-validation.json"
            image_path = tmp / "deployment-image-integrity.json"
            release_path = tmp / "kubernetes-release-state.json"
            bundle_path = tmp / "airgap-install-bundle.json"
            entry_path = tmp / "airgap-install-bundle-entry.json"
            chain_path = tmp / "chain.json"
            for path, value in ((manifest_path, manifest), (helm_path, helm_receipt), (image_path, image_receipt), (release_path, release_receipt)):
                path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            subprocess.run(base + ["airgap-install-bundle", str(manifest_path), str(helm_path), str(image_path), str(release_path), "--root", str(ROOT), "--environment", "test-airgap", "--bundle-ref", "bundle:trustai/airgap/test-airgap", "--producer-ref", "oidc:trustai.example/airgap-bundler", "--generated-at", "2026-07-04T04:00:00Z", "--out", str(bundle_path)], cwd=ROOT, env=env, check=True)
            subprocess.run(base + ["airgap-install-bundle-verify", str(bundle_path), str(manifest_path), str(helm_path), str(image_path), str(release_path), "--root", str(ROOT)], cwd=ROOT, env=env, check=True)
            subprocess.run(base + ["airgap-install-bundle-append", str(bundle_path), str(manifest_path), str(helm_path), str(image_path), str(release_path), "--root", str(ROOT), "--state", str(chain_path), "--tenant", "airgap-bundle-cli", "--out", str(entry_path)], cwd=ROOT, env=env, check=True)
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            chain = EvidenceChain.load(chain_path, tenant_id="airgap-bundle-cli")

        self.assertTrue(bundle["passed"])
        self.assertEqual(AIRGAP_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertTrue(chain.verify_all().ok)


if __name__ == "__main__":
    unittest.main()
