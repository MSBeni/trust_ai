import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.byoc_operator import (
    BYOC_OPERATOR_ENTRY_TYPE,
    BYOC_OPERATOR_SCHEMA,
    append_byoc_operator_attestation,
    build_byoc_operator_attestation,
    verify_byoc_operator_attestation,
    write_byoc_operator_attestation,
)
from trustai.chain import EvidenceChain
from trustai.deployment import build_deployment_manifest, write_deployment_manifest
from trustai.object_store import WORMStore


ROOT = Path(__file__).resolve().parents[1]


class BYOCOperatorTests(unittest.TestCase):
    def _source_artifacts(self, tmp: Path):
        store_root = tmp / "worm"
        store = WORMStore(store_root)
        receipt = store.store_json(
            {"artifact": "proof-pack", "pack_id": "pack-123"},
            "proof-pack",
            retention_until="2033-07-04T00:00:00Z",
        )
        legal_hold = store.apply_legal_hold(
            receipt,
            case_id="external-audit-2026-001",
            reason="Preserve proof pack for external audit.",
            applied_by="legal@example.com",
            applied_at="2026-07-04T01:00:00Z",
        )
        deployment = build_deployment_manifest(ROOT, environment="aitrade-byoc", generated_at="2026-07-04T00:00:00Z")
        return deployment, receipt, legal_hold, store_root

    def _attestation(self, tmp: Path):
        deployment, receipt, legal_hold, store_root = self._source_artifacts(tmp)
        attestation = build_byoc_operator_attestation(
            deployment,
            receipt,
            legal_hold=legal_hold,
            root=ROOT,
            store=store_root,
            environment="aitrade-byoc",
            operator_ref="operator:trustai/byoc",
            operator_version="0.1.0",
            operator_image="ghcr.io/trustai/operator:0.1.0",
            operator_image_digest="sha256:trustai-byoc-operator-digest",
            namespace="trustai",
            service_account_ref="k8s:sa/trustai/operator",
            reconciler_ref="controller:trustai/byoc-operator",
            upgrade_policy_ref="policy:trustai/byoc-upgrade-v0.1",
            rollback_policy_ref="policy:trustai/byoc-rollback-v0.1",
            tenant_id="aitrade-local",
            customer_account_ref="aws:123456789012",
            data_plane_ref="k8s:cluster/aitrade-prod",
            control_plane_ref="trustai:control-plane/local",
            keyring_ref="keyring:.trustai/keyring.local.json",
            object_lock_provider="Example S3 Object Lock",
            object_lock_bucket="arn:aws:s3:::trustai-aitrade-evidence",
            object_lock_region="us-east-1",
            backup_policy_ref="backup:trustai/daily",
            backup_schedule="rate(1 day)",
            restore_test_ref="restore-test:trustai/2026-07-04",
            restore_test_at="2026-07-04T02:00:00Z",
            rpo_minutes=60,
            rto_minutes=240,
            ingress_mode="private-load-balancer",
            egress_policy_ref="egress-policy:trustai/deny-by-default",
            allowed_egress_refs=["egress:kms", "egress:tsa"],
            airgap_bundle_ref="bundle:trustai/airgap/2026-07-04",
            airgap_bundle_hash="sha256:trustai-airgap-bundle",
            audit_log_ref="audit-log:byoc/operator",
            audit_log_root="sha256:byoc-operator-audit-root",
            retention_until="2033-07-04T00:00:00Z",
            actor_ref="oidc:trustai.example/byoc-operator",
            credential_ref="env:BYOC_OPERATOR_TOKEN",
            evidence_refs=["evidence:byoc/operator"],
            attested_at="2026-07-04T03:00:00Z",
        )
        return attestation, deployment, receipt, legal_hold, store_root

    def test_byoc_operator_attestation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation, deployment, receipt, legal_hold, store_root = self._attestation(tmp)
            result = verify_byoc_operator_attestation(attestation, deployment, receipt, legal_hold=legal_hold, root=ROOT, store=store_root)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="byoc-operator-test")
            entry = append_byoc_operator_attestation(chain, attestation, deployment, receipt, legal_hold=legal_hold, root=ROOT, store=store_root)

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(BYOC_OPERATOR_SCHEMA, attestation["schema"])
            self.assertEqual(receipt["receipt_id"], attestation["object_lock"]["worm_receipt"]["receipt_id"])
            self.assertEqual(legal_hold["legal_hold_id"], attestation["object_lock"]["legal_hold"]["legal_hold_id"])
            self.assertEqual(BYOC_OPERATOR_ENTRY_TYPE, entry["entry_type"])
            self.assertIn("operator-attested", entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_byoc_operator_attestation_rejects_disabled_object_lock(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation, deployment, receipt, legal_hold, store_root = self._attestation(tmp)
            tampered = copy.deepcopy(attestation)
            tampered["object_lock"]["object_lock_enabled"] = False

            result = verify_byoc_operator_attestation(tampered, deployment, receipt, legal_hold=legal_hold, root=ROOT, store=store_root)

            self.assertFalse(result.ok)
            self.assertIn("attestation_id does not match canonical BYOC operator attestation body", result.errors)
            self.assertTrue(any("object_lock_enabled" in error for error in result.errors))

    def test_byoc_operator_attestation_rejects_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation, deployment, receipt, legal_hold, store_root = self._attestation(tmp)
            other_receipt = WORMStore(store_root).store_json(
                {"artifact": "different-pack", "pack_id": "pack-456"},
                "proof-pack",
                retention_until="2033-07-04T00:00:00Z",
            )

            result = verify_byoc_operator_attestation(attestation, deployment, other_receipt, legal_hold=legal_hold, root=ROOT, store=store_root)

            self.assertFalse(result.ok)
            self.assertTrue(any("source_artifacts" in error or "source record" in error for error in result.errors))

    def test_cli_byoc_operator_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            deployment, receipt, legal_hold, store_root = self._source_artifacts(tmp)
            deployment_path = tmp / "deployment-manifest.json"
            receipt_path = tmp / "worm-receipt.json"
            hold_path = tmp / "legal-hold.json"
            attestation_path = tmp / "byoc-operator-attestation.json"
            entry_path = tmp / "byoc-operator-entry.json"
            write_deployment_manifest(deployment_path, deployment)
            write_byoc_operator_attestation(receipt_path, receipt)
            write_byoc_operator_attestation(hold_path, legal_hold)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            base = [
                sys.executable,
                "-m",
                "trustai",
            ]
            subprocess.run(
                base
                + [
                    "byoc-operator-attestation",
                    str(deployment_path),
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                    "--environment",
                    "aitrade-byoc",
                    "--operator-ref",
                    "operator:trustai/byoc",
                    "--operator-version",
                    "0.1.0",
                    "--operator-image",
                    "ghcr.io/trustai/operator:0.1.0",
                    "--operator-image-digest",
                    "sha256:trustai-byoc-operator-digest",
                    "--namespace",
                    "trustai",
                    "--service-account-ref",
                    "k8s:sa/trustai/operator",
                    "--reconciler-ref",
                    "controller:trustai/byoc-operator",
                    "--upgrade-policy-ref",
                    "policy:trustai/byoc-upgrade-v0.1",
                    "--rollback-policy-ref",
                    "policy:trustai/byoc-rollback-v0.1",
                    "--tenant-id",
                    "aitrade-local",
                    "--customer-account-ref",
                    "aws:123456789012",
                    "--data-plane-ref",
                    "k8s:cluster/aitrade-prod",
                    "--control-plane-ref",
                    "trustai:control-plane/local",
                    "--keyring-ref",
                    "keyring:.trustai/keyring.local.json",
                    "--object-lock-provider",
                    "Example S3 Object Lock",
                    "--object-lock-bucket",
                    "arn:aws:s3:::trustai-aitrade-evidence",
                    "--object-lock-region",
                    "us-east-1",
                    "--backup-policy-ref",
                    "backup:trustai/daily",
                    "--backup-schedule",
                    "rate(1 day)",
                    "--restore-test-ref",
                    "restore-test:trustai/2026-07-04",
                    "--restore-test-at",
                    "2026-07-04T02:00:00Z",
                    "--rpo-minutes",
                    "60",
                    "--rto-minutes",
                    "240",
                    "--ingress-mode",
                    "private-load-balancer",
                    "--egress-policy-ref",
                    "egress-policy:trustai/deny-by-default",
                    "--allowed-egress-ref",
                    "egress:kms",
                    "--allowed-egress-ref",
                    "egress:tsa",
                    "--airgap-bundle-ref",
                    "bundle:trustai/airgap/2026-07-04",
                    "--airgap-bundle-hash",
                    "sha256:trustai-airgap-bundle",
                    "--audit-log-ref",
                    "audit-log:byoc/operator",
                    "--audit-log-root",
                    "sha256:byoc-operator-audit-root",
                    "--retention-until",
                    "2033-07-04T00:00:00Z",
                    "--actor-ref",
                    "oidc:trustai.example/byoc-operator",
                    "--credential-ref",
                    "env:BYOC_OPERATOR_TOKEN",
                    "--evidence-ref",
                    "evidence:byoc/operator",
                    "--attested-at",
                    "2026-07-04T03:00:00Z",
                    "--out",
                    str(attestation_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "byoc-operator-verify",
                    str(attestation_path),
                    str(deployment_path),
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "byoc-operator-append",
                    str(attestation_path),
                    str(deployment_path),
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                    "--state",
                    str(tmp / "chain.json"),
                    "--tenant",
                    "byoc-operator-local",
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
