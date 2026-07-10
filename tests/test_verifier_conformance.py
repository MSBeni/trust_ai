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
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.framework_runtime_service_authority_recorded_export_provider_bundle import (
    write_framework_runtime_service_authority_recorded_export_provider_bundle,
)
from trustai.verifier_conformance import (
    VERIFIER_CONFORMANCE_SCHEMA,
    build_verifier_conformance_report,
    render_verifier_conformance_markdown,
    verify_verifier_conformance_report,
)

from tests import test_framework_runtime_service_authority_recorded_export_provider_bundle as provider_bundle_fixtures


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


class VerifierConformanceTests(unittest.TestCase):
    def _proof_pack(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="conformance-test")
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
        return compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

    def test_verifier_conformance_report_proves_valid_and_tamper_cases(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            report = build_verifier_conformance_report(pack)

            result = verify_verifier_conformance_report(report)
            markdown = render_verifier_conformance_markdown(report)
            cases = {case["id"]: case for case in report["test_cases"]}

            self.assertEqual(VERIFIER_CONFORMANCE_SCHEMA, report["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(5, result.case_count)
            self.assertTrue(cases["valid-proof-pack"]["actual_ok"])
            for case_id in (
                "pack-signature-tamper",
                "chain-entry-payload-tamper",
                "inclusion-proof-tamper",
                "packed-contract-body-tamper",
            ):
                self.assertFalse(cases[case_id]["actual_ok"])
                self.assertTrue(cases[case_id]["passed"])
            self.assertIn("TrustAI Verifier Conformance Report", markdown)

    def _provider_bundle(self, tmp: Path):
        helper = provider_bundle_fixtures.FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleTests()
        bundle, *_ = helper._bundle(tmp)
        return bundle

    def test_verifier_conformance_report_includes_provider_bundle_vectors(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = self._proof_pack(tmp)
            provider_bundle = self._provider_bundle(tmp)
            report = build_verifier_conformance_report(pack, provider_bundle=provider_bundle)

            result = verify_verifier_conformance_report(report)
            markdown = render_verifier_conformance_markdown(report)
            cases = {case["id"]: case for case in report["test_cases"]}

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(9, result.case_count)
            self.assertEqual(provider_bundle["bundle_id"], report["source_provider_bundle"]["bundle_id"])
            self.assertIn("Source provider bundle", markdown)
            self.assertTrue(cases["valid-provider-bundle"]["actual_ok"])
            for case_id in (
                "provider-bundle-signature-tamper",
                "provider-bundle-source-tamper",
                "provider-bundle-artifact-byte-tamper",
            ):
                self.assertFalse(cases[case_id]["actual_ok"])
                self.assertTrue(cases[case_id]["passed"])
                self.assertEqual("framework-runtime-service-authority-recorded-export-provider-bundle", cases[case_id]["target"])

    def test_cli_verifier_conformance_includes_provider_bundle_vectors(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = self._proof_pack(tmp)
            provider_bundle = self._provider_bundle(tmp)
            pack_path = tmp / "pack.json"
            bundle_path = tmp / "provider-bundle.json"
            report_path = tmp / "verifier-conformance.json"
            markdown_path = tmp / "verifier-conformance.md"
            write_framework_runtime_service_authority_recorded_export_provider_bundle(bundle_path, provider_bundle)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "verifier-conformance",
                    str(pack_path),
                    "--provider-bundle",
                    str(bundle_path),
                    "--out",
                    str(report_path),
                    "--markdown",
                    str(markdown_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "verifier-conformance-verify", str(report_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")

        self.assertEqual(9, report["summary"]["case_count"])
        self.assertIn("valid-provider-bundle", {case["id"] for case in report["test_cases"]})
        self.assertIn("Source provider bundle", markdown)

    def test_verifier_conformance_report_detects_report_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            report = build_verifier_conformance_report(pack)
            tampered = copy.deepcopy(report)
            tampered["test_cases"][0]["actual_ok"] = False

            result = verify_verifier_conformance_report(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("report_id" in error for error in result.errors))
            self.assertTrue(any("actual_ok does not match expected_ok" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
