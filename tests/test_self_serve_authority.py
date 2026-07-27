import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.crypto import sign_value
from trustai.onboarding import build_self_serve_onboarding_receipt
from trustai.self_serve_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    SELF_SERVE_AUTHORITY_ENTRY_TYPE,
    SELF_SERVE_AUTHORITY_SCHEMA,
    append_self_serve_authority_dossier,
    build_self_serve_authority_dossier,
    verify_self_serve_authority_dossier,
)


ROOT = Path(__file__).resolve().parents[1]


class SelfServeAuthorityTests(unittest.TestCase):
    def _receipt(self) -> dict:
        return build_self_serve_onboarding_receipt(
            ROOT,
            onboarding_ref="onboarding:self-serve/aitrade",
            tenant_ref="tenant:aitrade-local",
            agent_ref="agent:aitrade-risk",
            requester_ref="mailto:engineer@example.com",
            environment="local",
            generated_at="2026-07-13T00:00:00Z",
        )

    def _evidence_hash(self, requirement_id: str, authority_kind: str) -> str:
        return "sha256:" + content_hash({"self_serve_authority": requirement_id, "authority_kind": authority_kind})

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "hosted-account-creation-service",
                "authority_kind": "hosted-service",
                "evidence_ref": "service:self-serve/signup-prod",
                "evidence_hash": self._evidence_hash("hosted-account-creation-service", "hosted-service"),
                "description": "Hosted signup and tenant creation service export.",
                "issuer": "TrustAI Cloud",
                "subject": "aitrade self-serve onboarding",
                "source_uri": "https://ops.example/trustai/self-serve/signup-prod",
                "issued_at": "2026-07-13T00:10:00Z",
                "expires_at": "2026-07-20T00:10:00Z",
            },
            {
                "requirement_id": "production-identity-federation",
                "authority_kind": "identity-provider",
                "evidence_ref": "idp:self-serve/signup-prod",
                "evidence_hash": self._evidence_hash("production-identity-federation", "identity-provider"),
                "description": "Identity-provider signup session and OIDC federation export.",
                "issuer": "Example IdP",
                "subject": "aitrade self-serve signup identities",
                "source_uri": "https://idp.example/audit/self-serve/signup",
                "issued_at": "2026-07-13T00:11:00Z",
                "expires_at": "2026-07-20T00:11:00Z",
            },
        ]

    def _complete_authority_evidence(self) -> list[dict]:
        evidence = []
        for index, requirement_id in enumerate(PRODUCTION_AUTHORITY_REQUIREMENT_IDS):
            authority_kind = "identity-provider" if requirement_id in {"production-identity-federation", "tenant-isolation-rbac"} else "hosted-service"
            if requirement_id == "onboarding-audit-retention":
                authority_kind = "cloud-object-lock"
            evidence.append(
                {
                    "requirement_id": requirement_id,
                    "authority_kind": authority_kind,
                    "evidence_ref": f"authority:self-serve/{requirement_id}",
                    "evidence_hash": self._evidence_hash(requirement_id, authority_kind),
                    "description": f"Retained self-serve production authority export for {requirement_id}.",
                    "issuer": "TrustAI Cloud",
                    "subject": "aitrade self-serve onboarding",
                    "source_uri": f"https://authority.trustai.example/self-serve/{requirement_id}",
                    "issued_at": f"2026-07-13T00:{10 + index:02d}:00Z",
                    "expires_at": f"2026-07-20T00:{10 + index:02d}:00Z",
                }
            )
        return evidence

    def _dossier(self, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None) -> tuple[dict, dict]:
        receipt = self._receipt()
        dossier = build_self_serve_authority_dossier(
            receipt,
            root=ROOT,
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:self-serve-authority/aitrade-prod",
            authority_ref="authority:self-serve/aitrade-prod",
            producer_ref="oidc:trustai.example/self-serve-authority-worker",
            generated_at="2026-07-13T00:15:00Z",
        )
        return receipt, dossier

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "self_serve_onboarding_authority": body})]

    def test_self_serve_authority_verifies_and_appends(self):
        receipt, dossier = self._dossier()

        result = verify_self_serve_authority_dossier(dossier, onboarding_receipt=receipt, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="self-serve-authority-test")
            entry = append_self_serve_authority_dossier(chain, dossier, onboarding_receipt=receipt, root=ROOT)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(SELF_SERVE_AUTHORITY_SCHEMA, dossier["schema"])
        self.assertEqual(2, result.covered_count)
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
        self.assertEqual(2, result.fresh_evidence_count)
        self.assertTrue(any("evidence missing for" in warning for warning in result.warnings), result.warnings)
        self.assertEqual(SELF_SERVE_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
        self.assertEqual(receipt["receipt_id"], entry["payload"]["onboarding_receipt_id"])
        self.assertEqual({"deferred": 1, "passed": 4}, entry["payload"]["control_summary"])

    def test_self_serve_authority_normalizes_uppercase_evidence_hash(self):
        expected_hash = self._evidence_hash("hosted-account-creation-service", "hosted-service")
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0]["evidence_hash"] = "sha256:" + expected_hash.removeprefix("sha256:").upper()
        receipt, dossier = self._dossier(authority_evidence=evidence)

        result = verify_self_serve_authority_dossier(dossier, onboarding_receipt=receipt, root=ROOT)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(expected_hash, dossier["authority_evidence"][0]["evidence_hash"])

    def test_self_serve_authority_rejects_resigned_malformed_evidence_hash(self):
        receipt, dossier = self._dossier()
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["evidence_hash"] = "sha256:not-a-real-digest"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_self_serve_authority_dossier(tampered, onboarding_receipt=receipt, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn(
            "invalid self-serve onboarding authority evidence: evidence_hash must contain a 64-character sha256 digest",
            result.errors,
        )
        self.assertNotIn("dossier_id does not match canonical self-serve onboarding authority body", result.errors)
        self.assertNotIn("self-serve onboarding authority signature verification failed", result.errors)
        self.assertNotIn("self-serve onboarding authority evidence_id does not match evidence body: hosted-account-creation-service", result.errors)

    def test_self_serve_authority_production_mode_requires_complete_fresh_evidence(self):
        receipt, dossier = self._dossier(mode="production-dossier")

        result = verify_self_serve_authority_dossier(dossier, onboarding_receipt=receipt, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn(
            "self-serve onboarding authority evidence missing for: billing-plan-entitlement, usage-metering-quota-enforcement, support-slo-operations, tenant-isolation-rbac, gateway-sdk-provisioning-replay, onboarding-audit-retention",
            result.errors,
        )

    def test_self_serve_authority_complete_production_mode_verifies(self):
        receipt, dossier = self._dossier(mode="production-dossier", authority_evidence=self._complete_authority_evidence())

        result = verify_self_serve_authority_dossier(
            dossier,
            onboarding_receipt=receipt,
            root=ROOT,
            require_complete=True,
            require_fresh=True,
            now="2026-07-13T00:20:00Z",
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.covered_count)
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.fresh_evidence_count)

    def test_cli_self_serve_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt_path = tmp / "self-serve-onboarding.json"
            dossier_path = tmp / "self-serve-authority.json"
            entry_path = tmp / "self-serve-authority-entry.json"
            state_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            receipt = self._receipt()
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            evidence = self._authority_evidence()
            evidence_args = []
            for item in evidence:
                metadata = (
                    f"issuer={item['issuer']};subject={item['subject']};source_uri={item['source_uri']};"
                    f"issued_at={item['issued_at']};expires_at={item['expires_at']}"
                )
                evidence_args.extend(
                    [
                        "--authority-evidence",
                        f"{item['requirement_id']},{item['authority_kind']},{item['evidence_ref']},{item['evidence_hash']},{item['description']};{metadata}",
                    ]
                )

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "self-serve-onboarding-authority",
                    str(receipt_path),
                    "--root",
                    str(ROOT),
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:self-serve-authority/aitrade-prod",
                    "--authority-ref",
                    "authority:self-serve/aitrade-prod",
                    "--producer-ref",
                    "oidc:trustai.example/self-serve-authority-worker",
                    "--generated-at",
                    "2026-07-13T00:15:00Z",
                    "--out",
                    str(dossier_path),
                    *evidence_args,
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [sys.executable, "-m", "trustai", "self-serve-onboarding-authority-verify", str(dossier_path), str(receipt_path), "--root", str(ROOT)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)

            appended = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "self-serve-onboarding-authority-append",
                    str(dossier_path),
                    str(receipt_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "self-serve-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(SELF_SERVE_AUTHORITY_SCHEMA, json.loads(dossier_path.read_text())["schema"])
            self.assertEqual(SELF_SERVE_AUTHORITY_ENTRY_TYPE, json.loads(entry_path.read_text())["entry_type"])


if __name__ == "__main__":
    unittest.main()
