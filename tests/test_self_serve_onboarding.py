import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.onboarding import (
    SELF_SERVE_ONBOARDING_ENTRY_TYPE,
    SELF_SERVE_ONBOARDING_SCHEMA,
    append_self_serve_onboarding_receipt,
    build_self_serve_onboarding_receipt,
    verify_self_serve_onboarding_receipt,
)


ROOT = Path(__file__).resolve().parents[1]


class SelfServeOnboardingTests(unittest.TestCase):
    def test_receipt_binds_sdk_gateway_sources_and_appends(self):
        receipt = build_self_serve_onboarding_receipt(
            ROOT,
            onboarding_ref="onboarding:self-serve/aitrade",
            tenant_ref="tenant:aitrade-local",
            agent_ref="agent:aitrade-risk",
            requester_ref="mailto:engineer@example.com",
            environment="local",
            generated_at="2026-07-13T00:00:00Z",
        )
        result = verify_self_serve_onboarding_receipt(receipt, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="self-serve-onboarding-test")
            entry = append_self_serve_onboarding_receipt(chain, receipt, root=ROOT)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(SELF_SERVE_ONBOARDING_SCHEMA, receipt["schema"])
        self.assertEqual(10, len(receipt["source_artifacts"]))
        self.assertEqual({"passed"}, {control["status"] for control in receipt["controls"]})
        self.assertEqual(SELF_SERVE_ONBOARDING_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
        self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])

    def test_receipt_detects_source_artifact_tamper(self):
        receipt = build_self_serve_onboarding_receipt(
            ROOT,
            onboarding_ref="onboarding:self-serve/aitrade",
            tenant_ref="tenant:aitrade-local",
            agent_ref="agent:aitrade-risk",
            requester_ref="mailto:engineer@example.com",
        )
        tampered = copy.deepcopy(receipt)
        tampered["source_artifacts"][0]["sha256"] = "sha256:tampered"

        result = verify_self_serve_onboarding_receipt(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("receipt_id does not match canonical self-serve onboarding body", result.errors)
        self.assertTrue(any("source artifact hash mismatch" in error for error in result.errors), result.errors)

    def test_otel_only_mode_omits_mcp_gateway_claim(self):
        receipt = build_self_serve_onboarding_receipt(
            ROOT,
            onboarding_ref="onboarding:self-serve/otel",
            tenant_ref="tenant:otel-local",
            agent_ref="agent:otel-only",
            requester_ref="mailto:engineer@example.com",
            sdk_scope="python",
            gateway_mode="otel-only",
        )
        result = verify_self_serve_onboarding_receipt(receipt, root=ROOT)
        controls = {control["id"]: control["status"] for control in receipt["controls"]}

        self.assertTrue(result.ok, result.errors)
        self.assertEqual("not-applicable", controls["typescript-sdk-quickstart-bound"])
        self.assertEqual("not-applicable", controls["mcp-gateway-quickstart-bound"])
        self.assertIn("omits MCP gateway", result.warnings[0])

    def test_cli_self_serve_onboarding_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            receipt_path = tmp / "self-serve-onboarding.json"
            entry_path = tmp / "self-serve-onboarding-entry.json"
            state_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "self-serve-onboarding",
                    "--root",
                    str(ROOT),
                    "--onboarding-ref",
                    "onboarding:self-serve/aitrade",
                    "--tenant-ref",
                    "tenant:aitrade-local",
                    "--agent-ref",
                    "agent:aitrade-risk",
                    "--requester-ref",
                    "mailto:engineer@example.com",
                    "--generated-at",
                    "2026-07-13T00:00:00Z",
                    "--out",
                    str(receipt_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [sys.executable, "-m", "trustai", "self-serve-onboarding-verify", str(receipt_path), "--root", str(ROOT)],
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
                    "self-serve-onboarding-append",
                    str(receipt_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "self-serve-onboarding-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertTrue(receipt_path.exists())
            self.assertTrue(entry_path.exists())
            self.assertEqual(SELF_SERVE_ONBOARDING_SCHEMA, json.loads(receipt_path.read_text())["schema"])


if __name__ == "__main__":
    unittest.main()
