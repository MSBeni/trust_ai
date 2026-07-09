import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.regulator import build_regulator_disclosure
from trustai.regulator_view import write_regulator_html
from trustai.review_portal_service import (
    REVIEW_PORTAL_SERVICE_ENTRY_TYPE,
    REVIEW_PORTAL_SERVICE_SCHEMA,
    append_review_portal_service_attestation,
    build_review_portal_service_attestation,
    verify_review_portal_service_attestation,
)
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.supervised_access import build_supervised_access_receipt, write_supervised_access_receipt


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class ReviewPortalServiceTests(unittest.TestCase):
    def _fixtures(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="review-portal-service-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        append_runtime_attestation(chain, contract, load_action(ACTION))
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack_path = tmp / "pack.json"
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=pack_path)
        disclosure = build_regulator_disclosure(chain, pack, audience="supervisor@example.test")
        disclosure_path = tmp / "disclosure.json"
        _write_json(disclosure_path, disclosure)
        view_path = tmp / "regulator-view.html"
        write_regulator_html(view_path, disclosure)
        receipt = build_supervised_access_receipt(
            pack,
            proof_pack_path=pack_path,
            disclosure=disclosure,
            disclosure_path=disclosure_path,
            view_path=view_path,
            subject_ref="oidc:regulator.example/supervisor-123",
            organization="Example Supervisor",
            role="regulator_reviewer",
            audience_type="regulator",
            purpose="EU AI Act supervised review",
            issued_at="2026-07-08T00:00:00Z",
            expires_at="2026-08-08T00:00:00Z",
        )
        receipt_path = tmp / "supervised-access.json"
        write_supervised_access_receipt(receipt_path, receipt)
        return chain, pack, pack_path, disclosure, disclosure_path, view_path, receipt, receipt_path

    def _attestation(self, receipt, pack, pack_path, disclosure, disclosure_path, view_path, **overrides):
        values = {
            "supervised_access_receipt": receipt,
            "proof_pack": pack,
            "proof_pack_path": pack_path,
            "regulator_disclosure": disclosure,
            "disclosure_path": disclosure_path,
            "view_path": view_path,
            "environment": "aitrade-prod",
            "portal_kind": "regulator",
            "service_ref": "review-portal:trustai/regulator-prod",
            "service_version": "0.1.0",
            "endpoint_url": "https://portal.example/reviews/aitrade",
            "service_image": "ghcr.io/trustai/review-portal:0.1.0",
            "service_image_digest": "sha256:trustai-review-portal-image",
            "service_binary_hash": "sha256:trustai-review-portal-binary",
            "frontend_bundle_ref": "bundle:review-portal/regulator-ui",
            "frontend_bundle_hash": "sha256:trustai-review-portal-frontend",
            "api_ref": "api:review-portal/v0",
            "session_store_ref": "redis:review-portal/sessions",
            "auth_provider_ref": "oidc:review-portal/idp",
            "auth_policy_ref": "policy:review-portal/auth-v0.1",
            "rbac_policy_ref": "policy:review-portal/rbac-v0.1",
            "session_policy_ref": "policy:review-portal/session-v0.1",
            "selective_disclosure_policy_ref": "policy:review-portal/selective-disclosure-v0.1",
            "tenant_isolation_ref": "tenant-isolation:review-portal/aitrade",
            "rate_limit_policy_ref": "rate-limit:review-portal/regulator",
            "network_policy_ref": "netpol:review-portal/deny-by-default",
            "egress_policy_ref": "egress:review-portal/kms-tsa-only",
            "content_security_policy_ref": "csp:review-portal/regulator-v0.1",
            "encryption_key_ref": "kms:review-portal/session-store",
            "replicas_min": 3,
            "replicas_max": 9,
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "audit_log_ref": "audit-log:review-portal/service",
            "audit_log_root": "sha256:review-portal-service-audit-root",
            "access_log_ref": "access-log:review-portal/sessions",
            "access_log_root": "sha256:review-portal-access-log-root",
            "metrics_ref": "metrics:review-portal/service",
            "alert_policy_ref": "alert:review-portal/service",
            "retention_until": "2033-07-08T00:00:00Z",
            "actor_ref": "oidc:trustai.example/review-portal-operator",
            "credential_ref": "env:REVIEW_PORTAL_TOKEN",
            "evidence_refs": ["evidence:review-portal/service"],
            "attested_at": "2026-07-08T06:00:00Z",
        }
        values.update(overrides)
        return build_review_portal_service_attestation(**values)

    def test_review_portal_service_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack, pack_path, disclosure, disclosure_path, view_path, receipt, _ = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(receipt, pack, pack_path, disclosure, disclosure_path, view_path)

            result = verify_review_portal_service_attestation(
                attestation,
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                regulator_disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
            )
            entry = append_review_portal_service_attestation(
                chain,
                attestation,
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                regulator_disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(REVIEW_PORTAL_SERVICE_SCHEMA, attestation["schema"])
            self.assertEqual("portal-service-attested", attestation["mode"])
            self.assertEqual(receipt["receipt_id"], attestation["access"]["supervised_access_receipt_id"])
            self.assertEqual("env:REVIEW_PORTAL_TOKEN", attestation["operation_actor"]["credential"]["ref"])
            self.assertEqual(REVIEW_PORTAL_SERVICE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_review_portal_service_rejects_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, pack_path, disclosure, disclosure_path, view_path, receipt, _ = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(receipt, pack, pack_path, disclosure, disclosure_path, view_path)
            tampered = copy.deepcopy(receipt)
            tampered["reviewer"]["role"] = "changed"

            result = verify_review_portal_service_attestation(
                attestation,
                tampered,
                proof_pack=pack,
                proof_pack_path=pack_path,
                regulator_disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
            )

            self.assertFalse(result.ok)
            self.assertIn("review portal service source_artifacts do not match supplied source artifacts", result.errors)
            self.assertIn("supervised access source: receipt_id does not match canonical receipt body", result.errors)

    def test_review_portal_service_rejects_insecure_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, pack_path, disclosure, disclosure_path, view_path, receipt, _ = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(receipt, pack, pack_path, disclosure, disclosure_path, view_path, endpoint_url="http://portal.example/reviews/aitrade")

            result = verify_review_portal_service_attestation(attestation, receipt, proof_pack=pack, proof_pack_path=pack_path, regulator_disclosure=disclosure, disclosure_path=disclosure_path, view_path=view_path)

            self.assertFalse(result.ok)
            self.assertIn("review portal service service.endpoint_url must use HTTPS", result.errors)

    def test_review_portal_service_rejects_weak_replicas(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, pack_path, disclosure, disclosure_path, view_path, receipt, _ = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(receipt, pack, pack_path, disclosure, disclosure_path, view_path, replicas_min=1, availability_zones=["us-east-1a"])

            result = verify_review_portal_service_attestation(attestation, receipt, proof_pack=pack, proof_pack_path=pack_path, regulator_disclosure=disclosure, disclosure_path=disclosure_path, view_path=view_path)

            self.assertFalse(result.ok)
            self.assertIn("review portal service service.replicas_min must be an integer >= 2", result.errors)
            self.assertIn("review portal service service.availability_zones must include at least two zones", result.errors)

    def test_cli_review_portal_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, pack, pack_path, disclosure, disclosure_path, view_path, receipt, receipt_path = self._fixtures(tmp)
            attestation_path = tmp / "review-portal-service-attestation.json"
            entry_path = tmp / "review-portal-service-entry.json"
            state_path = tmp / "review-portal-service-chain.json"
            _write_json(pack_path, pack)
            _write_json(disclosure_path, disclosure)
            write_supervised_access_receipt(receipt_path, receipt)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(receipt_path),
                "--pack",
                str(pack_path),
                "--disclosure",
                str(disclosure_path),
                "--view",
                str(view_path),
            ]
            service_args = [
                "--environment", "aitrade-prod",
                "--portal-kind", "regulator",
                "--service-ref", "review-portal:trustai/regulator-prod",
                "--service-version", "0.1.0",
                "--endpoint-url", "https://portal.example/reviews/aitrade",
                "--service-image", "ghcr.io/trustai/review-portal:0.1.0",
                "--service-image-digest", "sha256:trustai-review-portal-image",
                "--service-binary-hash", "sha256:trustai-review-portal-binary",
                "--frontend-bundle-ref", "bundle:review-portal/regulator-ui",
                "--frontend-bundle-hash", "sha256:trustai-review-portal-frontend",
                "--api-ref", "api:review-portal/v0",
                "--session-store-ref", "redis:review-portal/sessions",
                "--auth-provider-ref", "oidc:review-portal/idp",
                "--auth-policy-ref", "policy:review-portal/auth-v0.1",
                "--rbac-policy-ref", "policy:review-portal/rbac-v0.1",
                "--session-policy-ref", "policy:review-portal/session-v0.1",
                "--selective-disclosure-policy-ref", "policy:review-portal/selective-disclosure-v0.1",
                "--tenant-isolation-ref", "tenant-isolation:review-portal/aitrade",
                "--rate-limit-policy-ref", "rate-limit:review-portal/regulator",
                "--network-policy-ref", "netpol:review-portal/deny-by-default",
                "--egress-policy-ref", "egress:review-portal/kms-tsa-only",
                "--content-security-policy-ref", "csp:review-portal/regulator-v0.1",
                "--encryption-key-ref", "kms:review-portal/session-store",
                "--replicas-min", "3",
                "--replicas-max", "9",
                "--availability-zone", "us-east-1a",
                "--availability-zone", "us-east-1b",
                "--audit-log-ref", "audit-log:review-portal/service",
                "--audit-log-root", "sha256:review-portal-service-audit-root",
                "--access-log-ref", "access-log:review-portal/sessions",
                "--access-log-root", "sha256:review-portal-access-log-root",
                "--metrics-ref", "metrics:review-portal/service",
                "--alert-policy-ref", "alert:review-portal/service",
                "--retention-until", "2033-07-08T00:00:00Z",
                "--actor-ref", "oidc:trustai.example/review-portal-operator",
                "--credential-ref", "env:REVIEW_PORTAL_TOKEN",
                "--evidence-ref", "evidence:review-portal/service",
                "--attested-at", "2026-07-08T06:00:00Z",
            ]
            subprocess.run(
                [sys.executable, "-m", "trustai", "review-portal-service-attestation", *source_args, *service_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "review-portal-service-verify", str(attestation_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "review-portal-service-append",
                    str(attestation_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "review-portal-service-local",
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
