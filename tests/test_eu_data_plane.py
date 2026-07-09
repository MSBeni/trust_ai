import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.byoc_operator import build_byoc_operator_attestation, write_byoc_operator_attestation
from trustai.chain import EvidenceChain
from trustai.deployment import build_deployment_manifest, write_deployment_manifest
from trustai.eu_data_plane import (
    EU_DATA_PLANE_ENTRY_TYPE,
    EU_DATA_PLANE_SCHEMA,
    append_eu_data_plane_attestation,
    build_eu_data_plane_attestation,
    verify_eu_data_plane_attestation,
)
from trustai.object_store import WORMStore


ROOT = Path(__file__).resolve().parents[1]


class EUDataPlaneTests(unittest.TestCase):
    def _source_artifacts(self, tmp: Path):
        store_root = tmp / "worm"
        store = WORMStore(store_root)
        receipt = store.store_json(
            {"artifact": "proof-pack", "pack_id": "pack-eu-123"},
            "proof-pack",
            retention_until="2033-07-04T00:00:00Z",
        )
        legal_hold = store.apply_legal_hold(
            receipt,
            case_id="eu-supervisory-review-2026-001",
            reason="Preserve EU data-plane proof sources.",
            applied_by="legal@example.eu",
            applied_at="2026-07-04T01:00:00Z",
        )
        deployment = build_deployment_manifest(ROOT, environment="aitrade-eu-byoc", generated_at="2026-07-04T00:00:00Z")
        byoc = build_byoc_operator_attestation(
            deployment,
            receipt,
            legal_hold=legal_hold,
            root=ROOT,
            store=store_root,
            environment="aitrade-eu-byoc",
            operator_ref="operator:trustai/byoc",
            operator_version="0.1.0",
            operator_image="ghcr.io/trustai/operator:0.1.0",
            operator_image_digest="sha256:trustai-byoc-operator-digest",
            namespace="trustai",
            service_account_ref="k8s:sa/trustai/operator",
            reconciler_ref="controller:trustai/byoc-operator",
            upgrade_policy_ref="policy:trustai/byoc-upgrade-v0.1",
            rollback_policy_ref="policy:trustai/byoc-rollback-v0.1",
            tenant_id="aitrade-eu",
            customer_account_ref="aws:210987654321",
            data_plane_ref="k8s:cluster/aitrade-eu-central-1",
            control_plane_ref="trustai:control-plane/eu",
            keyring_ref="keyring:.trustai/keyring.local.json",
            object_lock_provider="Example S3 Object Lock",
            object_lock_bucket="arn:aws:s3:::trustai-aitrade-eu-evidence",
            object_lock_region="eu-central-1",
            backup_policy_ref="backup:trustai/eu-daily",
            backup_schedule="rate(1 day)",
            restore_test_ref="restore-test:trustai/eu/2026-07-04",
            restore_test_at="2026-07-04T02:00:00Z",
            rpo_minutes=60,
            rto_minutes=240,
            ingress_mode="private-load-balancer",
            egress_policy_ref="egress-policy:trustai/eu-deny-by-default",
            allowed_egress_refs=["egress:eu-kms", "egress:eu-tsa"],
            audit_log_ref="audit-log:byoc/eu-operator",
            audit_log_root="sha256:byoc-eu-operator-audit-root",
            retention_until="2033-07-04T00:00:00Z",
            actor_ref="oidc:trustai.example/byoc-eu-operator",
            credential_ref="env:BYOC_OPERATOR_TOKEN",
            evidence_refs=["evidence:byoc/eu-operator"],
            attested_at="2026-07-04T03:00:00Z",
        )
        return deployment, byoc, receipt, legal_hold, store_root

    def _attestation(self, tmp: Path):
        deployment, byoc, receipt, legal_hold, store_root = self._source_artifacts(tmp)
        attestation = build_eu_data_plane_attestation(
            deployment,
            byoc,
            root=ROOT,
            environment="aitrade-eu-prod",
            tenant_id="aitrade-eu",
            data_plane_ref="k8s:cluster/aitrade-eu-central-1",
            control_plane_ref="trustai:control-plane/eu",
            primary_region="eu-central-1",
            primary_location="Frankfurt, Germany",
            availability_zones=["eu-central-1a", "eu-central-1b", "eu-central-1c"],
            replica_regions=["eu-west-1"],
            backup_regions=["eu-central-1", "eu-west-3"],
            analytics_region="eu-central-1",
            log_region="eu-central-1",
            data_categories=["agent_trace_hashes", "proof_pack_metadata", "policy_decision_metadata"],
            subprocessor_refs=["subprocessor:aws-eu", "subprocessor:example-rfc3161-tsa-eu"],
            residency_policy_ref="policy:trustai/eu-residency-v0.1",
            data_classification_policy_ref="policy:trustai/eu-data-classification-v0.1",
            dpa_ref="dpa:trustai/aitrade-eu-2026",
            transfer_impact_assessment_ref="tia:trustai/aitrade-eu-2026",
            deletion_policy_ref="policy:trustai/eu-deletion-v0.1",
            data_export_policy_ref="policy:trustai/eu-export-v0.1",
            encryption_key_ref="kms:eu-central-1:trustai/aitrade-eu/evidence",
            kms_key_region="eu-central-1",
            key_access_policy_ref="policy:kms/aitrade-eu-key-access-v0.1",
            hsm_ref="hsm:eu-central-1/trustai-eu",
            network_policy_ref="netpol:trustai/eu-deny-by-default",
            support_access_policy_ref="policy:trustai/eu-jit-support-v0.1",
            breakglass_policy_ref="policy:trustai/eu-breakglass-v0.1",
            audit_log_ref="audit-log:eu-data-plane/service",
            audit_log_root="sha256:eu-data-plane-audit-root",
            access_log_ref="access-log:eu-data-plane/sessions",
            access_log_root="sha256:eu-data-plane-access-root",
            transfer_log_ref="transfer-log:eu-data-plane/egress",
            transfer_log_root="sha256:eu-data-plane-transfer-root",
            retention_until="2033-07-04T00:00:00Z",
            actor_ref="oidc:trustai.example/eu-data-plane-operator",
            credential_ref="env:EU_DATA_PLANE_TOKEN",
            evidence_refs=["evidence:eu-data-plane/service"],
            attested_at="2026-07-04T04:00:00Z",
        )
        return attestation, deployment, byoc, receipt, legal_hold, store_root

    def test_eu_data_plane_attestation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation, deployment, byoc, _receipt, _legal_hold, _store_root = self._attestation(tmp)
            result = verify_eu_data_plane_attestation(attestation, deployment, byoc, root=ROOT)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="eu-data-plane-test")
            entry = append_eu_data_plane_attestation(chain, attestation, deployment, byoc, root=ROOT)

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(EU_DATA_PLANE_SCHEMA, attestation["schema"])
            self.assertEqual("eu-central-1", attestation["regions"]["primary_region"])
            self.assertEqual("eu-central-1", attestation["regions"]["object_lock_region"])
            self.assertEqual(EU_DATA_PLANE_ENTRY_TYPE, entry["entry_type"])
            self.assertIn("sovereignty-attested", entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_eu_data_plane_attestation_rejects_region_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            attestation, deployment, byoc, _receipt, _legal_hold, _store_root = self._attestation(Path(tmp_dir))
            tampered = copy.deepcopy(attestation)
            tampered["regions"]["primary_region"] = "us-east-1"

            result = verify_eu_data_plane_attestation(tampered, deployment, byoc, root=ROOT)

            self.assertFalse(result.ok)
            self.assertIn("attestation_id does not match canonical EU data-plane attestation body", result.errors)
            self.assertTrue(any("primary_region" in error for error in result.errors))

    def test_eu_data_plane_attestation_rejects_byoc_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation, deployment, byoc, _receipt, _legal_hold, _store_root = self._attestation(tmp)
            other_byoc = copy.deepcopy(byoc)
            other_byoc["tenancy"]["data_plane_ref"] = "k8s:cluster/other"

            result = verify_eu_data_plane_attestation(attestation, deployment, other_byoc, root=ROOT)

            self.assertFalse(result.ok)
            self.assertTrue(any("BYOC operator" in error or "source_artifacts" in error for error in result.errors))

    def test_cli_eu_data_plane_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            deployment, byoc, receipt, legal_hold, _store_root = self._source_artifacts(tmp)
            deployment_path = tmp / "deployment-manifest.json"
            byoc_path = tmp / "byoc-eu.json"
            receipt_path = tmp / "worm-receipt.json"
            hold_path = tmp / "legal-hold.json"
            attestation_path = tmp / "eu-data-plane.json"
            entry_path = tmp / "eu-data-plane-entry.json"
            write_deployment_manifest(deployment_path, deployment)
            write_byoc_operator_attestation(byoc_path, byoc)
            receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
            hold_path.write_text(json.dumps(legal_hold, indent=2, sort_keys=True), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.run(
                base
                + [
                    "eu-data-plane-attestation",
                    str(deployment_path),
                    str(byoc_path),
                    "--root",
                    str(ROOT),
                    "--environment",
                    "aitrade-eu-prod",
                    "--tenant-id",
                    "aitrade-eu",
                    "--data-plane-ref",
                    "k8s:cluster/aitrade-eu-central-1",
                    "--control-plane-ref",
                    "trustai:control-plane/eu",
                    "--primary-region",
                    "eu-central-1",
                    "--primary-location",
                    "Frankfurt, Germany",
                    "--availability-zone",
                    "eu-central-1a",
                    "--availability-zone",
                    "eu-central-1b",
                    "--replica-region",
                    "eu-west-1",
                    "--backup-region",
                    "eu-central-1",
                    "--analytics-region",
                    "eu-central-1",
                    "--log-region",
                    "eu-central-1",
                    "--data-category",
                    "agent_trace_hashes",
                    "--subprocessor-ref",
                    "subprocessor:aws-eu",
                    "--residency-policy-ref",
                    "policy:trustai/eu-residency-v0.1",
                    "--data-classification-policy-ref",
                    "policy:trustai/eu-data-classification-v0.1",
                    "--dpa-ref",
                    "dpa:trustai/aitrade-eu-2026",
                    "--transfer-impact-assessment-ref",
                    "tia:trustai/aitrade-eu-2026",
                    "--deletion-policy-ref",
                    "policy:trustai/eu-deletion-v0.1",
                    "--data-export-policy-ref",
                    "policy:trustai/eu-export-v0.1",
                    "--encryption-key-ref",
                    "kms:eu-central-1:trustai/aitrade-eu/evidence",
                    "--kms-key-region",
                    "eu-central-1",
                    "--key-access-policy-ref",
                    "policy:kms/aitrade-eu-key-access-v0.1",
                    "--network-policy-ref",
                    "netpol:trustai/eu-deny-by-default",
                    "--support-access-policy-ref",
                    "policy:trustai/eu-jit-support-v0.1",
                    "--breakglass-policy-ref",
                    "policy:trustai/eu-breakglass-v0.1",
                    "--audit-log-ref",
                    "audit-log:eu-data-plane/service",
                    "--audit-log-root",
                    "sha256:eu-data-plane-audit-root",
                    "--access-log-ref",
                    "access-log:eu-data-plane/sessions",
                    "--access-log-root",
                    "sha256:eu-data-plane-access-root",
                    "--transfer-log-ref",
                    "transfer-log:eu-data-plane/egress",
                    "--transfer-log-root",
                    "sha256:eu-data-plane-transfer-root",
                    "--retention-until",
                    "2033-07-04T00:00:00Z",
                    "--actor-ref",
                    "oidc:trustai.example/eu-data-plane-operator",
                    "--credential-ref",
                    "env:EU_DATA_PLANE_TOKEN",
                    "--evidence-ref",
                    "evidence:eu-data-plane/service",
                    "--attested-at",
                    "2026-07-04T04:00:00Z",
                    "--out",
                    str(attestation_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base + ["eu-data-plane-verify", str(attestation_path), str(deployment_path), str(byoc_path), "--root", str(ROOT)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "eu-data-plane-append",
                    str(attestation_path),
                    str(deployment_path),
                    str(byoc_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(tmp / "chain.json"),
                    "--tenant",
                    "eu-data-plane-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            self.assertTrue(attestation_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
