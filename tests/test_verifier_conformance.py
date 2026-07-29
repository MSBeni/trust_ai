import copy
import hashlib
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
from trustai.go_verifier_build import (
    build_go_verifier_build_attestation,
    build_go_verifier_binary_signature_artifact,
    write_go_verifier_build_attestation,
    write_go_verifier_binary_signature_artifact,
)
from trustai.go_verifier_release_run import build_go_verifier_release_run_receipt, write_go_verifier_release_run_receipt
from trustai.proofpack import compile_proof_pack
from trustai.registry import (
    append_delegation,
    append_delegation_graph,
    append_inventory,
    build_delegation_graph,
    load_delegation,
    load_inventory,
)
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.standards import build_standards_submission, write_standards_submission
from trustai.framework_runtime_service_authority_recorded_export_provider_bundle import (
    write_framework_runtime_service_authority_recorded_export_provider_bundle,
)
from trustai.verifier_conformance import (
    VERIFIER_CONFORMANCE_SCHEMA,
    build_verifier_conformance_report,
    render_verifier_conformance_markdown,
    verify_verifier_conformance_report,
    write_verifier_conformance_report,
)
from trustai.verifier_release import build_verifier_release_manifest, write_verifier_release_manifest

from tests import test_framework_runtime_service_authority_recorded_export_provider_bundle as provider_bundle_fixtures


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"
DELEGATION = ROOT / "examples" / "aitrade" / "delegation.json"


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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

    def _proof_pack_with_delegation_graph(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "graph-chain.json", tenant_id="conformance-graph-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        append_inventory(chain, load_inventory(INVENTORY))
        delegation = load_delegation(DELEGATION)
        append_delegation(chain, delegation)
        graph = build_delegation_graph(chain, contract_hash=delegation["contract_hash"], generated_at="2026-07-03T12:04:00Z")
        append_delegation_graph(chain, graph, source_chain=chain)
        append_runtime_attestation(chain, contract, load_action(ACTION))
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        return compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "graph-pack.json")

    def _release_run_sources(self, tmp: Path, pack: dict):
        source_conformance = build_verifier_conformance_report(pack)
        standards = build_standards_submission(ROOT)
        release = build_verifier_release_manifest(
            ROOT,
            conformance_report=source_conformance,
            standards_package=standards,
        )
        binary_path = tmp / "trustai-verify-linux-amd64"
        build_log_path = tmp / "trustai-verify-linux-amd64.build.log"
        sbom_path = tmp / "trustai-verify-linux-amd64.sbom.json"
        provenance_path = tmp / "trustai-verify-linux-amd64.provenance.json"
        signature_path = tmp / "trustai-verify-linux-amd64.sig"
        binary_path.write_bytes(b"trustai verifier conformance release-run binary fixture\n")
        build_log_path.write_text('CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w"\n', encoding="utf-8")
        sbom_path.write_text(json.dumps({"schema": "trustai.go-verifier-ci-sbom/0.1", "artifact": binary_path.name}, sort_keys=True), encoding="utf-8")
        provenance_path.write_text(json.dumps({"schema": "trustai.go-verifier-ci-provenance/0.1", "artifact": binary_path.name}, sort_keys=True), encoding="utf-8")
        signature_artifact = build_go_verifier_binary_signature_artifact(
            release,
            root=ROOT,
            conformance_report=source_conformance,
            standards_package=standards,
            binary_path=binary_path,
            build_log_ref=build_log_path,
            sbom_ref=sbom_path,
            provenance_ref=provenance_path,
            generated_at="2026-07-16T00:01:30Z",
        )
        write_go_verifier_binary_signature_artifact(signature_path, signature_artifact)
        build_attestation = build_go_verifier_build_attestation(
            release,
            root=ROOT,
            conformance_report=source_conformance,
            standards_package=standards,
            binary_path=binary_path,
            mode="binary-attested",
            builder_ref="builder:github-actions/go-verifier",
            toolchain_ref="go:github-actions/setup-go",
            toolchain_version="1.23.0",
            goos="linux",
            goarch="amd64",
            build_command='CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/trustai-verify-linux-amd64 ./verifier/go/trustai-verify',
            build_log_ref=str(build_log_path),
            build_log_hash=_sha256_ref(build_log_path),
            sbom_ref=str(sbom_path),
            sbom_hash=_sha256_ref(sbom_path),
            provenance_ref=str(provenance_path),
            provenance_hash=_sha256_ref(provenance_path),
            signature_ref=str(signature_path),
            signature_hash=_sha256_ref(signature_path),
            build_started_at="2026-07-16T00:00:00Z",
            build_finished_at="2026-07-16T00:01:00Z",
            attested_at="2026-07-16T00:02:00Z",
        )
        release_run = build_go_verifier_release_run_receipt(
            release,
            build_attestation,
            root=ROOT,
            conformance_report=source_conformance,
            standards_package=standards,
            binary_path=binary_path,
            provider="github-actions",
            workflow_ref=".github/workflows/go-verifier.yml",
            workflow_run_id="1234567890",
            workflow_run_url="https://github.com/MSBeni/trust_ai/actions/runs/1234567890",
            run_attempt=1,
            commit_sha="c" * 40,
            branch_ref="refs/heads/main",
            trigger_ref="workflow_dispatch",
            runner_ref="github-hosted:ubuntu-latest",
            status="completed",
            conclusion="success",
            started_at="2026-07-16T00:00:00Z",
            completed_at="2026-07-16T00:04:00Z",
            artifacts=[
                {"name": binary_path.name, "path": str(binary_path), "kind": "binary"},
                {"name": sbom_path.name, "path": str(sbom_path), "kind": "sbom"},
                {"name": provenance_path.name, "path": str(provenance_path), "kind": "provenance"},
                {"name": signature_path.name, "path": str(signature_path), "kind": "signature"},
            ],
            checks=[
                {"name": "go test ./...", "status": "completed", "conclusion": "success", "log_ref": str(build_log_path)},
                {"name": "build linux/amd64", "status": "completed", "conclusion": "success"},
            ],
            hosted_provenance_ref=str(provenance_path),
            hosted_provenance_hash=_sha256_ref(provenance_path),
            oidc_issuer="https://token.actions.githubusercontent.com",
            oidc_subject="repo:MSBeni/trust_ai:ref:refs/heads/main",
            generated_at="2026-07-16T00:05:00Z",
        )
        return source_conformance, standards, release, build_attestation, release_run, binary_path
    def test_verifier_conformance_report_proves_valid_and_tamper_cases(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            report = build_verifier_conformance_report(pack)

            result = verify_verifier_conformance_report(report)
            markdown = render_verifier_conformance_markdown(report)
            cases = {case["id"]: case for case in report["test_cases"]}

            self.assertEqual(VERIFIER_CONFORMANCE_SCHEMA, report["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(6, result.case_count)
            self.assertTrue(cases["valid-proof-pack"]["actual_ok"])
            for case_id in (
                "pack-signature-tamper",
                "chain-entry-payload-tamper",
                "inclusion-proof-tamper",
                "packed-contract-body-tamper",
                "issued-at-tamper",
            ):
                self.assertFalse(cases[case_id]["actual_ok"])
                self.assertTrue(cases[case_id]["passed"])
            self.assertIn("TrustAI Verifier Conformance Report", markdown)

    def test_verifier_conformance_report_includes_delegation_graph_vector_when_pack_has_graph(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack_with_delegation_graph(Path(tmp_dir))
            report = build_verifier_conformance_report(pack)

            result = verify_verifier_conformance_report(report)
            cases = {case["id"]: case for case in report["test_cases"]}

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(7, result.case_count)
            self.assertEqual(1, report["source_proof_pack"]["delegation_graph_entry_count"])
            self.assertIn("delegation-graph-tamper", cases)
            self.assertFalse(cases["delegation-graph-tamper"]["actual_ok"])
            self.assertTrue(cases["delegation-graph-tamper"]["passed"])
            self.assertTrue(any("delegation graph entry" in error for error in cases["delegation-graph-tamper"]["errors"]))

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
            self.assertEqual(10, result.case_count)
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

    def test_verifier_conformance_report_includes_go_verifier_release_run_vectors(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = self._proof_pack(tmp)
            source_conformance, standards, release, build_attestation, release_run, binary_path = self._release_run_sources(tmp, pack)
            report = build_verifier_conformance_report(
                pack,
                release_run=release_run,
                release_run_verifier_release=release,
                release_run_build_attestation=build_attestation,
                release_run_conformance_report=source_conformance,
                release_run_standards_package=standards,
                release_run_root=ROOT,
                release_run_binary_path=binary_path,
            )

            result = verify_verifier_conformance_report(report)
            markdown = render_verifier_conformance_markdown(report)
            cases = {case["id"]: case for case in report["test_cases"]}

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(10, result.case_count)
            self.assertEqual(release_run["run_id"], report["source_release_run"]["run_id"])
            self.assertIn("Source Go verifier release run", markdown)
            self.assertTrue(cases["valid-go-verifier-release-run"]["actual_ok"])
            for case_id in (
                "go-verifier-release-run-signature-tamper",
                "go-verifier-release-run-workflow-tamper",
                "go-verifier-release-run-artifact-tamper",
            ):
                self.assertFalse(cases[case_id]["actual_ok"])
                self.assertTrue(cases[case_id]["passed"])
                self.assertEqual("go-verifier-release-run", cases[case_id]["target"])

    def test_cli_verifier_conformance_includes_go_verifier_release_run_vectors(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack = self._proof_pack(tmp)
            source_conformance, standards, release, build_attestation, release_run, binary_path = self._release_run_sources(tmp, pack)
            pack_path = tmp / "pack.json"
            source_conformance_path = tmp / "source-verifier-conformance.json"
            standards_path = tmp / "standards-submission.json"
            release_path = tmp / "verifier-release.json"
            build_path = tmp / "go-verifier-build.json"
            release_run_path = tmp / "go-verifier-release-run.json"
            report_path = tmp / "verifier-conformance.json"
            markdown_path = tmp / "verifier-conformance.md"
            write_verifier_conformance_report(source_conformance_path, source_conformance)
            write_standards_submission(standards_path, standards)
            write_verifier_release_manifest(release_path, release)
            write_go_verifier_build_attestation(build_path, build_attestation)
            write_go_verifier_release_run_receipt(release_run_path, release_run)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "verifier-conformance",
                    str(pack_path),
                    "--release-run",
                    str(release_run_path),
                    "--release-run-verifier-release",
                    str(release_path),
                    "--release-run-build-attestation",
                    str(build_path),
                    "--release-run-conformance-report",
                    str(source_conformance_path),
                    "--release-run-standards-package",
                    str(standards_path),
                    "--release-run-root",
                    str(ROOT),
                    "--release-run-binary",
                    str(binary_path),
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

        self.assertEqual(10, report["summary"]["case_count"])
        self.assertIn("valid-go-verifier-release-run", {case["id"] for case in report["test_cases"]})
        self.assertIn("Source Go verifier release run", markdown)
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

        self.assertEqual(10, report["summary"]["case_count"])
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
