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
from trustai.product_scope import build_product_scope_decision
from trustai.product_scope_authority import (
    OPERATING_AUTHORITY_REQUIREMENT_IDS,
    PRODUCT_SCOPE_AUTHORITY_ENTRY_TYPE,
    PRODUCT_SCOPE_AUTHORITY_SCHEMA,
    append_product_scope_authority_dossier,
    build_product_scope_authority_dossier,
    verify_product_scope_authority_dossier,
)


ROOT = Path(__file__).resolve().parents[1]


class ProductScopeAuthorityTests(unittest.TestCase):
    def _decision(self, *, decision_ref: str = "scope:request/regulator-export") -> dict:
        return build_product_scope_decision(
            ROOT,
            decision_ref=decision_ref,
            requester_ref="product:gtm",
            reviewer_ref="oidc:trustai.example/product-council",
            feature_title="Regulator export evidence",
            feature_summary="Portable regulator export that strengthens third-party proof review.",
            decision="accept",
            proof_impacts=["proof-strength", "wider-acceptance"],
            generated_at="2026-07-21T00:00:00Z",
        )

    def _evidence_hash(self, requirement_id: str, authority_kind: str) -> str:
        return "sha256:" + content_hash({"product_scope_authority": requirement_id, "authority_kind": authority_kind})

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "company-governance-adoption",
                "authority_kind": "customer",
                "evidence_ref": "governance:product-council/scope-charter",
                "evidence_hash": self._evidence_hash("company-governance-adoption", "customer"),
                "description": "Product council charter adopting the proof discipline question.",
                "issuer": "TrustAI Product Council",
                "subject": "product scope discipline",
                "source_uri": "https://governance.example/trustai/product-scope/charter",
                "issued_at": "2026-07-21T00:10:00Z",
                "expires_at": "2026-07-28T00:10:00Z",
            },
            {
                "requirement_id": "anti-focus-decline-ledger",
                "authority_kind": "ci-run",
                "evidence_ref": "ci:product-scope/anti-focus-ledger",
                "evidence_hash": self._evidence_hash("anti-focus-decline-ledger", "ci-run"),
                "description": "CI export proving anti-focus decisions are retained and reviewed.",
                "issuer": "GitHub Actions",
                "subject": "product scope anti-focus ledger",
                "source_uri": "https://github.com/MSBeni/trust_ai/actions/product-scope",
                "issued_at": "2026-07-21T00:11:00Z",
                "expires_at": "2026-07-28T00:11:00Z",
            },
        ]

    def _complete_authority_evidence(self) -> list[dict]:
        authority_kind_by_requirement = {
            "company-governance-adoption": "customer",
            "product-council-enforcement": "customer",
            "anti-focus-decline-ledger": "ci-run",
            "customer-pressure-exception-review": "customer",
            "ongoing-roadmap-discipline": "ci-run",
        }
        evidence = []
        for index, requirement_id in enumerate(OPERATING_AUTHORITY_REQUIREMENT_IDS):
            authority_kind = authority_kind_by_requirement[requirement_id]
            evidence.append(
                {
                    "requirement_id": requirement_id,
                    "authority_kind": authority_kind,
                    "evidence_ref": f"authority:product-scope/{requirement_id}",
                    "evidence_hash": self._evidence_hash(requirement_id, authority_kind),
                    "description": f"Retained product-scope operating authority export for {requirement_id}.",
                    "issuer": "TrustAI Product Council",
                    "subject": "product scope discipline",
                    "source_uri": f"https://authority.trustai.example/product-scope/{requirement_id}",
                    "issued_at": f"2026-07-21T00:{10 + index:02d}:00Z",
                    "expires_at": f"2026-07-28T00:{10 + index:02d}:00Z",
                }
            )
        return evidence

    def _dossier(self, *, mode: str = "governance-dossier", authority_evidence: list[dict] | None = None) -> tuple[dict, dict]:
        decision = self._decision()
        dossier = build_product_scope_authority_dossier(
            decision,
            root=ROOT,
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:product-scope-authority/aitrade-prod",
            authority_ref="authority:product-scope/aitrade-prod",
            producer_ref="oidc:trustai.example/product-scope-authority-worker",
            generated_at="2026-07-21T00:15:00Z",
        )
        return decision, dossier

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "product_scope_authority": body})]

    def test_product_scope_authority_verifies_and_appends(self):
        decision, dossier = self._dossier()

        result = verify_product_scope_authority_dossier(dossier, decision_receipt=decision, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="product-scope-authority-test")
            entry = append_product_scope_authority_dossier(chain, dossier, decision_receipt=decision, root=ROOT)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PRODUCT_SCOPE_AUTHORITY_SCHEMA, dossier["schema"])
        self.assertEqual(2, result.covered_count)
        self.assertEqual(len(OPERATING_AUTHORITY_REQUIREMENT_IDS), result.required_count)
        self.assertEqual(2, result.fresh_evidence_count)
        self.assertTrue(any("evidence missing for" in warning for warning in result.warnings), result.warnings)
        self.assertEqual(PRODUCT_SCOPE_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
        self.assertEqual(decision["decision_id"], entry["payload"]["decision_id"])
        self.assertEqual({"deferred": 1, "passed": 4}, entry["payload"]["control_summary"])

    def test_product_scope_authority_normalizes_uppercase_evidence_hash(self):
        expected_hash = self._evidence_hash("company-governance-adoption", "customer")
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0]["evidence_hash"] = "sha256:" + expected_hash.removeprefix("sha256:").upper()
        decision, dossier = self._dossier(authority_evidence=evidence)

        result = verify_product_scope_authority_dossier(dossier, decision_receipt=decision, root=ROOT)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(expected_hash, dossier["authority_evidence"][0]["evidence_hash"])

    def test_product_scope_authority_rejects_resigned_malformed_evidence_hash(self):
        decision, dossier = self._dossier()
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["evidence_hash"] = "sha256:not-a-real-digest"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_product_scope_authority_dossier(tampered, decision_receipt=decision, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn(
            "invalid product scope authority evidence: evidence_hash must contain a 64-character sha256 digest",
            result.errors,
        )
        self.assertNotIn("dossier_id does not match canonical product scope authority body", result.errors)
        self.assertNotIn("product scope authority signature verification failed", result.errors)
        self.assertNotIn("product scope authority evidence_id does not match evidence body: company-governance-adoption", result.errors)

    def test_product_scope_authority_rejects_resigned_source_context_mismatch(self):
        decision, dossier = self._dossier()
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["source_context"]["decision_id"] = "other-decision"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_product_scope_authority_dossier(tampered, decision_receipt=decision, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn(
            "product scope authority source_context does not match decision source: company-governance-adoption",
            result.errors,
        )

    def test_product_scope_authority_production_mode_requires_complete_fresh_evidence(self):
        decision, dossier = self._dossier(mode="production-dossier")

        result = verify_product_scope_authority_dossier(dossier, decision_receipt=decision, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn(
            "product scope authority evidence missing for: product-council-enforcement, customer-pressure-exception-review, ongoing-roadmap-discipline",
            result.errors,
        )

    def test_product_scope_authority_complete_production_mode_verifies(self):
        decision, dossier = self._dossier(mode="production-dossier", authority_evidence=self._complete_authority_evidence())

        result = verify_product_scope_authority_dossier(
            dossier,
            decision_receipt=decision,
            root=ROOT,
            require_complete=True,
            require_fresh=True,
            now="2026-07-21T00:20:00Z",
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(len(OPERATING_AUTHORITY_REQUIREMENT_IDS), result.covered_count)
        self.assertEqual(len(OPERATING_AUTHORITY_REQUIREMENT_IDS), result.fresh_evidence_count)

    def test_cli_product_scope_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            decision_path = tmp / "product-scope-decision.json"
            dossier_path = tmp / "product-scope-authority.json"
            entry_path = tmp / "product-scope-authority-entry.json"
            state_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated_decision = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "product-scope-decision",
                    "--root",
                    str(ROOT),
                    "--decision-ref",
                    "scope:request/regulator-export",
                    "--requester-ref",
                    "product:gtm",
                    "--reviewer-ref",
                    "oidc:trustai.example/product-council",
                    "--feature-title",
                    "Regulator export evidence",
                    "--feature-summary",
                    "Portable regulator export that strengthens third-party proof review.",
                    "--decision",
                    "accept",
                    "--proof-impact",
                    "proof-strength",
                    "--proof-impact",
                    "wider-acceptance",
                    "--generated-at",
                    "2026-07-21T00:00:00Z",
                    "--out",
                    str(decision_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated_decision.returncode, generated_decision.stderr)
            evidence_args = []
            for item in self._authority_evidence():
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
                    "product-scope-authority",
                    str(decision_path),
                    "--root",
                    str(ROOT),
                    "--mode",
                    "governance-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:product-scope-authority/aitrade-prod",
                    "--authority-ref",
                    "authority:product-scope/aitrade-prod",
                    "--producer-ref",
                    "oidc:trustai.example/product-scope-authority-worker",
                    "--generated-at",
                    "2026-07-21T00:15:00Z",
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
                [sys.executable, "-m", "trustai", "product-scope-authority-verify", str(dossier_path), str(decision_path), "--root", str(ROOT)],
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
                    "product-scope-authority-append",
                    str(dossier_path),
                    str(decision_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "product-scope-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(PRODUCT_SCOPE_AUTHORITY_SCHEMA, json.loads(dossier_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
