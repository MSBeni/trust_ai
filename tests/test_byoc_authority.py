import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.crypto import sign_value
from trustai.byoc_authority import (
    BYOC_AUTHORITY_ENTRY_TYPE,
    BYOC_AUTHORITY_SCHEMA,
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    append_byoc_authority_dossier,
    build_byoc_authority_dossier,
    verify_byoc_authority_dossier,
    write_byoc_authority_dossier,
)
from trustai.byoc_operator import build_byoc_operator_attestation, write_byoc_operator_attestation
from trustai.chain import EvidenceChain
from trustai.deployment import build_deployment_manifest, write_deployment_manifest
from trustai.object_store import WORMStore


ROOT = Path(__file__).resolve().parents[1]
BYOC_NETWORK_POLICY_AUTHORITY_EXPORT = ROOT / "examples" / "aitrade" / "byoc-network-policy-authority-export.json"
BYOC_NETWORK_POLICY_AUTHORITY_EXPORT_REL = "examples/aitrade/byoc-network-policy-authority-export.json"


def _sha256_ref(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


class BYOCAuthorityTests(unittest.TestCase):
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
        return deployment, attestation, receipt, legal_hold, store_root

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "live-cloud-account-binding",
                "authority_kind": "provider-api",
                "evidence_ref": "aws:account/123456789012/trustai-byoc",
                "evidence_hash": "sha256:byoc-live-cloud-account",
                "description": "Provider account export tying the TrustAI BYOC deployment to the customer-owned account.",
                "issuer": "ExampleCloud",
                "subject": "aitrade BYOC account",
                "source_uri": "https://cloud.example/accounts/123456789012/trustai",
                "issued_at": "2026-07-04T03:05:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
            {
                "requirement_id": "object-lock-compliance-mode",
                "authority_kind": "cloud-object-lock",
                "evidence_ref": "s3-object-lock:trustai-aitrade-evidence",
                "evidence_hash": "sha256:byoc-object-lock-export",
                "description": "Provider Object Lock export for the retained proof-pack bucket.",
                "issuer": "ExampleCloud Object Lock",
                "subject": "trustai-aitrade-evidence",
                "source_uri": "https://cloud.example/s3/trustai-aitrade-evidence/object-lock",
                "issued_at": "2026-07-04T03:06:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
            {
                "requirement_id": "network-policy-admission-audit-export",
                "authority_kind": "provider-api",
                "evidence_ref": "k8s:networkpolicy/trustai/trustai-api",
                "evidence_hash": _sha256_ref(BYOC_NETWORK_POLICY_AUTHORITY_EXPORT),
                "description": "Provider Kubernetes export proving the TrustAI API NetworkPolicy was admitted and audit logged.",
                "issuer": "Example Kubernetes API",
                "subject": "trustai-api NetworkPolicy",
                "source_uri": "https://cloud.example/kubernetes/aitrade-prod/networkpolicies/trustai-api",
                "issued_at": "2026-07-04T03:07:00Z",
                "expires_at": "2026-12-31T00:00:00Z",
            },
        ]

    def _authority_artifacts(self) -> list[dict]:
        return [
            {
                "requirement_id": "network-policy-admission-audit-export",
                "path": BYOC_NETWORK_POLICY_AUTHORITY_EXPORT_REL,
            }
        ]

    def _dossier(
        self,
        tmp: Path,
        *,
        mode: str = "operator-dossier",
        authority_evidence: list[dict] | None = None,
        authority_artifacts: list[dict] | None = None,
    ) -> tuple[dict, dict, dict, dict, dict, Path]:
        deployment, attestation, receipt, legal_hold, store_root = self._source_artifacts(tmp)
        if authority_artifacts is None:
            artifact_inputs = self._authority_artifacts() if authority_evidence is None else []
        else:
            artifact_inputs = authority_artifacts
        dossier = build_byoc_authority_dossier(
            deployment,
            attestation,
            root=ROOT,
            store=store_root,
            worm_receipt=receipt,
            legal_hold=legal_hold,
            mode=mode,
            environment="aitrade-byoc",
            dossier_ref="dossier:byoc-authority/aitrade-byoc",
            authority_ref="authority:byoc/aitrade-byoc",
            producer_ref="oidc:trustai.example/byoc-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            authority_artifacts=artifact_inputs,
            generated_at="2026-07-04T03:10:00Z",
        )
        return dossier, deployment, attestation, receipt, legal_hold, store_root

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "byoc_authority": body})]

    def test_byoc_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier, deployment, attestation, receipt, legal_hold, store_root = self._dossier(tmp)
            result = verify_byoc_authority_dossier(
                dossier,
                deployment_manifest=deployment,
                byoc_operator=attestation,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                require_fresh=True,
                now="2026-07-04T03:10:00Z",
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="byoc-authority-test")
            entry = append_byoc_authority_dossier(
                chain,
                dossier,
                deployment_manifest=deployment,
                byoc_operator=attestation,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                require_fresh=True,
                now="2026-07-04T03:10:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(BYOC_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(3, result.covered_count)
            self.assertEqual(1, result.replayed_artifact_count)
            self.assertEqual(1, dossier["artifact_summary"]["artifact_count"])
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertTrue(any("missing for" in warning for warning in result.warnings))
            self.assertEqual(BYOC_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(dossier["authority_evidence"][0]["source_context"], entry["payload"]["authority_evidence"][0]["source_context"])
            self.assertEqual(content_hash(dossier["source_binding"]), dossier["authority_evidence"][0]["source_context"]["source_binding_hash"])
            self.assertEqual({"deferred": 2, "passed": 10}, entry["payload"]["control_summary"])
            self.assertEqual(1, entry["payload"]["artifact_summary"]["artifact_count"])
            self.assertTrue(chain.verify_all().ok)

    def test_byoc_authority_tracks_network_policy_admission_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dossier, *_ = self._dossier(Path(tmp_dir))
            requirement_ids = [item["id"] for item in dossier["required_production_authority"]]
            control_by_id = {item["id"]: item for item in dossier["controls"]}

            self.assertIn("network-policy-admission-audit-export", PRODUCTION_AUTHORITY_REQUIREMENT_IDS)
            self.assertIn("network-policy-admission-audit-export", requirement_ids)
            self.assertIn("network-policy-admission-audit-export", dossier["summary"]["covered_requirement_ids"])
            self.assertEqual("passed", control_by_id["network-policy-admission-audit-export-covered"]["status"])

    def test_byoc_authority_rejects_resigned_source_context_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier, deployment, attestation, receipt, legal_hold, store_root = self._dossier(tmp, authority_artifacts=[])
            tampered = copy.deepcopy(dossier)
            item = tampered["authority_evidence"][0]
            item["source_context"]["source_binding_hash"] = "sha256:tampered-source-binding"
            item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
            self._resign_dossier(tampered)

            result = verify_byoc_authority_dossier(
                tampered,
                deployment_manifest=deployment,
                byoc_operator=attestation,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
            )

            self.assertFalse(result.ok)
            self.assertIn("BYOC authority source_context does not match source binding: live-cloud-account-binding", result.errors)

    def test_byoc_authority_rejects_resigned_control_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier, deployment, attestation, receipt, legal_hold, store_root = self._dossier(tmp)
            tampered = copy.deepcopy(dossier)
            tampered["controls"][0]["status"] = "deferred"
            self._resign_dossier(tampered)

            result = verify_byoc_authority_dossier(
                tampered,
                deployment_manifest=deployment,
                byoc_operator=attestation,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
            )

            self.assertFalse(result.ok)
            self.assertIn("BYOC authority controls do not match dossier body", result.errors)

    def test_byoc_authority_rejects_artifact_replay_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier, deployment, attestation, receipt, legal_hold, store_root = self._dossier(tmp)
            tampered = copy.deepcopy(dossier)
            tampered["authority_artifacts"][0]["path"] = "examples/aitrade/traffic-completeness-provider-export.json"

            result = verify_byoc_authority_dossier(
                tampered,
                deployment_manifest=deployment,
                byoc_operator=attestation,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("authority artifact" in error and "hash" in error for error in result.errors))

    def test_byoc_authority_detects_operator_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier, deployment, attestation, receipt, legal_hold, store_root = self._dossier(tmp)
            tampered = copy.deepcopy(attestation)
            tampered["network"]["private_endpoint"] = False

            result = verify_byoc_authority_dossier(
                dossier,
                deployment_manifest=deployment,
                byoc_operator=tampered,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("source_binding does not match" in error for error in result.errors))
            self.assertTrue(any("operator source" in error for error in result.errors))

    def test_byoc_authority_requires_complete_source_binding_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier, *_ = self._dossier(tmp)
            tampered = copy.deepcopy(dossier)
            tampered["source_binding"]["object_lock"]["legal_hold"].pop("legal_hold_hash")
            body = without_keys(tampered, "dossier_id", "signatures")
            dossier_id = content_hash(body)
            tampered["dossier_id"] = dossier_id
            tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "byoc_authority": body})]

            result = verify_byoc_authority_dossier(tampered, root=ROOT)

            self.assertFalse(result.ok)
            self.assertTrue(any("object_lock.legal_hold.legal_hold_hash is required" in error for error in result.errors), result.errors)

    def test_byoc_authority_requires_freshness_when_strict(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence = [dict(self._authority_evidence()[0])]
            evidence[0].pop("issued_at")
            evidence[0].pop("expires_at")
            dossier, deployment, attestation, receipt, legal_hold, store_root = self._dossier(tmp, authority_evidence=evidence)

            result = verify_byoc_authority_dossier(
                dossier,
                deployment_manifest=deployment,
                byoc_operator=attestation,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                require_fresh=True,
                now="2026-07-04T03:10:00Z",
            )

            self.assertFalse(result.ok)
            self.assertEqual(1, result.missing_freshness_count)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors))

    def test_byoc_authority_rejects_incomplete_production_claim(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier, deployment, attestation, receipt, legal_hold, store_root = self._dossier(tmp, mode="production-dossier")

            result = verify_byoc_authority_dossier(
                dossier,
                deployment_manifest=deployment,
                byoc_operator=attestation,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                now="2026-07-04T03:10:00Z",
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires" in error for error in result.errors))

    def test_cli_byoc_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            dossier_path = tmp / "byoc-authority.json"
            entry_path = tmp / "byoc-authority-entry.json"
            manifest_path = tmp / "deployment-manifest.json"
            operator_path = tmp / "byoc-operator-attestation.json"
            receipt_path = tmp / "worm-receipt.json"
            hold_path = tmp / "legal-hold.json"
            state_path = tmp / "evidence-chain.json"
            dossier, deployment, attestation, receipt, legal_hold, store_root = self._dossier(tmp)
            write_deployment_manifest(manifest_path, deployment)
            write_byoc_operator_attestation(operator_path, attestation)
            write_byoc_operator_attestation(receipt_path, receipt)
            write_byoc_operator_attestation(hold_path, legal_hold)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.run(
                base
                + [
                    "byoc-authority",
                    str(manifest_path),
                    str(operator_path),
                    "--worm-receipt",
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                    "--mode",
                    "operator-dossier",
                    "--environment",
                    "aitrade-byoc",
                    "--dossier-ref",
                    "dossier:byoc-authority/aitrade-byoc",
                    "--authority-ref",
                    "authority:byoc/aitrade-byoc",
                    "--producer-ref",
                    "oidc:trustai.example/byoc-authority-worker",
                    "--authority-evidence",
                    "live-cloud-account-binding,provider-api,aws:account/123456789012/trustai-byoc,sha256:byoc-live-cloud-account,Provider account export;issuer=ExampleCloud;subject=aitrade BYOC account;source_uri=https://cloud.example/accounts/123456789012/trustai;issued_at=2026-07-04T03:05:00Z;expires_at=2026-12-31T00:00:00Z",
                    "--authority-evidence",
                    "network-policy-admission-audit-export,provider-api,k8s:networkpolicy/trustai/trustai-api," + _sha256_ref(BYOC_NETWORK_POLICY_AUTHORITY_EXPORT) + ",Provider Kubernetes NetworkPolicy admission export;issuer=Example Kubernetes API;subject=trustai-api NetworkPolicy;source_uri=https://cloud.example/kubernetes/aitrade-prod/networkpolicies/trustai-api;issued_at=2026-07-04T03:07:00Z;expires_at=2026-12-31T00:00:00Z",
                    "--authority-artifact",
                    f"network-policy-admission-audit-export,{BYOC_NETWORK_POLICY_AUTHORITY_EXPORT_REL}",
                    "--generated-at",
                    "2026-07-04T03:10:00Z",
                    "--require-fresh",
                    "--now",
                    "2026-07-04T03:10:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "byoc-authority-verify",
                    str(dossier_path),
                    "--deployment-manifest",
                    str(manifest_path),
                    "--byoc-operator",
                    str(operator_path),
                    "--worm-receipt",
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                    "--authority-artifact",
                    f"network-policy-admission-audit-export,{BYOC_NETWORK_POLICY_AUTHORITY_EXPORT_REL}",
                    "--require-fresh",
                    "--now",
                    "2026-07-04T03:10:00Z",
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "byoc-authority-append",
                    str(dossier_path),
                    str(manifest_path),
                    str(operator_path),
                    "--worm-receipt",
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                    "--authority-artifact",
                    f"network-policy-admission-audit-export,{BYOC_NETWORK_POLICY_AUTHORITY_EXPORT_REL}",
                    "--require-fresh",
                    "--now",
                    "2026-07-04T03:10:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "byoc-authority-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            cli_dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            result = verify_byoc_authority_dossier(
                cli_dossier,
                deployment_manifest=deployment,
                byoc_operator=attestation,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
            )
            self.assertTrue(result.ok, result.errors)
            self.assertNotEqual(dossier["dossier_id"], cli_dossier["dossier_id"])
            self.assertEqual(cli_dossier["dossier_id"], entry["payload"]["dossier_id"])
            write_byoc_authority_dossier(tmp / "copy.json", cli_dossier)


if __name__ == "__main__":
    unittest.main()
