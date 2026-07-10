import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.product_scope import (
    PRODUCT_SCOPE_ENTRY_TYPE,
    PRODUCT_SCOPE_SCHEMA,
    append_product_scope_decision,
    build_product_scope_decision,
    verify_product_scope_decision,
)


ROOT = Path(__file__).resolve().parents[1]


class ProductScopeDecisionTests(unittest.TestCase):
    def test_accept_decision_requires_positive_proof_impact_and_appends(self):
        decision = build_product_scope_decision(
            ROOT,
            decision_ref="scope:request/regulator-export",
            requester_ref="product:gtm",
            reviewer_ref="oidc:trustai.example/product",
            feature_title="Regulator export evidence",
            feature_summary="Portable regulator export that strengthens third-party proof review.",
            decision="accept",
            proof_impacts=["wider-acceptance", "proof-strength"],
            generated_at="2026-07-21T00:00:00Z",
        )
        result = verify_product_scope_decision(decision, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="product-scope-test")
            entry = append_product_scope_decision(chain, decision, root=ROOT)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PRODUCT_SCOPE_SCHEMA, decision["schema"])
        self.assertEqual("accept", decision["decision"])
        self.assertEqual(["proof-strength", "wider-acceptance"], decision["proof_impacts"])
        self.assertEqual({"passed": 10}, entry["payload"]["control_summary"])
        self.assertEqual(PRODUCT_SCOPE_ENTRY_TYPE, entry["entry_type"])

    def test_decline_anti_focus_request_is_valid_scope_discipline(self):
        decision = build_product_scope_decision(
            ROOT,
            decision_ref="scope:request/dashboard-builder",
            requester_ref="sales:prospect",
            reviewer_ref="oidc:trustai.example/product",
            feature_title="Full trace dashboard builder",
            feature_summary="Build a general trace-viewer dashboard unrelated to portable proof.",
            decision="decline",
            anti_focus_flags=["observability-dashboard", "trace-viewer-ux"],
            generated_at="2026-07-21T01:00:00Z",
        )
        result = verify_product_scope_decision(decision, root=ROOT)

        self.assertTrue(result.ok, result.errors)
        self.assertIn("declined decision", result.warnings[0])
        self.assertEqual([], decision["proof_impacts"])
        self.assertEqual(["observability-dashboard", "trace-viewer-ux"], decision["anti_focus_flags"])

    def test_accepting_anti_focus_request_is_rejected(self):
        decision = build_product_scope_decision(
            ROOT,
            decision_ref="scope:request/agent-framework",
            requester_ref="sales:prospect",
            reviewer_ref="oidc:trustai.example/product",
            feature_title="Agent orchestration framework",
            feature_summary="Build a new agent framework instead of neutral proof machinery.",
            decision="accept",
            proof_impacts=["cheaper-production"],
            anti_focus_flags=["agent-framework-orchestrator"],
        )

        result = verify_product_scope_decision(decision, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("violates roadmap discipline" in error for error in result.errors), result.errors)

    def test_decision_detects_source_artifact_tamper(self):
        decision = build_product_scope_decision(
            ROOT,
            decision_ref="scope:request/tamper",
            requester_ref="product:gtm",
            reviewer_ref="oidc:trustai.example/product",
            feature_title="Proof pack improvement",
            feature_summary="Improve proof pack verification semantics.",
            decision="accept",
            proof_impacts=["proof-strength"],
        )
        tampered = copy.deepcopy(decision)
        tampered["source_artifacts"][0]["sha256"] = "sha256:tampered"

        result = verify_product_scope_decision(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("decision_id does not match canonical product scope decision body", result.errors)
        self.assertTrue(any("source artifact hash mismatch" in error for error in result.errors), result.errors)

    def test_cli_product_scope_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            decision_path = tmp / "product-scope-decision.json"
            entry_path = tmp / "product-scope-decision-entry.json"
            state_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated = subprocess.run(
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
                    "oidc:trustai.example/product",
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
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [sys.executable, "-m", "trustai", "product-scope-decision-verify", str(decision_path), "--root", str(ROOT)],
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
                    "product-scope-decision-append",
                    str(decision_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "product-scope-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(PRODUCT_SCOPE_SCHEMA, json.loads(decision_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()