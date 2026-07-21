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
from trustai.go_verifier_release_run import (
    GO_VERIFIER_RELEASE_RUN_ENTRY_TYPE,
    GO_VERIFIER_RELEASE_RUN_SCHEMA,
    append_go_verifier_release_run_receipt,
    build_go_verifier_release_run_receipt,
    verify_go_verifier_release_run_receipt,
    write_go_verifier_release_run_receipt,
)
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import (
    append_shadow_replay,
    append_soak_report,
    load_shadow_replay,
    load_soak_window,
    shadow_replay_to_eval_results,
)
from trustai.standards import build_standards_submission, write_standards_submission
from trustai.verifier_conformance import build_verifier_conformance_report, write_verifier_conformance_report
from trustai.verifier_release import build_verifier_release_manifest, write_verifier_release_manifest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class GoVerifierReleaseRunTests(unittest.TestCase):
    def _proof_pack(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="go-verifier-release-run-test")
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

    def _inputs(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            conformance = build_verifier_conformance_report(pack)
        standards = build_standards_submission(ROOT)
        release = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        return conformance, standards, release

    def _binary_attestation(self, tmp: Path, release, conformance, standards):
        binary_path = tmp / "trustai-verify-linux-amd64"
        build_log_path = tmp / "trustai-verify-linux-amd64.build.log"
        sbom_path = tmp / "trustai-verify-linux-amd64.sbom.json"
        provenance_path = tmp / "trustai-verify-linux-amd64.provenance.json"
        signature_path = tmp / "trustai-verify-linux-amd64.sig"
        binary_path.write_bytes(b"trustai verifier release-run binary fixture\n")
        build_log_path.write_text('CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w"\n', encoding="utf-8")
        sbom_path.write_text(json.dumps({"schema": "trustai.go-verifier-ci-sbom/0.1", "artifact": binary_path.name}, sort_keys=True), encoding="utf-8")
        provenance_path.write_text(json.dumps({"schema": "trustai.go-verifier-ci-provenance/0.1", "artifact": binary_path.name}, sort_keys=True), encoding="utf-8")
        signature_artifact = build_go_verifier_binary_signature_artifact(
            release,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
            binary_path=binary_path,
            build_log_ref=build_log_path,
            sbom_ref=sbom_path,
            provenance_ref=provenance_path,
            generated_at="2026-07-16T00:01:30Z",
        )
        write_go_verifier_binary_signature_artifact(signature_path, signature_artifact)
        attestation = build_go_verifier_build_attestation(
            release,
            root=ROOT,
            conformance_report=conformance,
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
        return attestation, binary_path, build_log_path, sbom_path, provenance_path, signature_path

    def _release_run(self, release, build_attestation, conformance, standards, binary_path, sidecars):
        build_log_path, sbom_path, provenance_path, signature_path = sidecars
        return build_go_verifier_release_run_receipt(
            release,
            build_attestation,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
            binary_path=binary_path,
            provider="github-actions",
            workflow_ref=".github/workflows/go-verifier.yml",
            workflow_run_id="1234567890",
            workflow_run_url="https://github.com/MSBeni/trust_ai/actions/runs/1234567890",
            run_attempt=1,
            commit_sha="a" * 40,
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

    def test_go_verifier_release_run_verifies_and_appends(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            build_attestation, binary_path, build_log_path, sbom_path, provenance_path, signature_path = self._binary_attestation(
                tmp, release, conformance, standards
            )
            receipt = self._release_run(
                release,
                build_attestation,
                conformance,
                standards,
                binary_path,
                (build_log_path, sbom_path, provenance_path, signature_path),
            )
            result = verify_go_verifier_release_run_receipt(
                receipt,
                release,
                build_attestation,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                binary_path=binary_path,
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="go-verifier-release-run-local")
            entry = append_go_verifier_release_run_receipt(
                chain,
                receipt,
                release,
                build_attestation,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                binary_path=binary_path,
            )

        control_status = {control["id"]: control["status"] for control in receipt["controls"]}
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(GO_VERIFIER_RELEASE_RUN_SCHEMA, receipt["schema"])
        self.assertEqual("attested", control_status["go-verifier-release-artifacts"])
        self.assertEqual("attested", control_status["go-verifier-release-hosted-provenance"])
        self.assertEqual(GO_VERIFIER_RELEASE_RUN_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["run_id"], entry["payload"]["run_id"])
        self.assertEqual(4, entry["payload"]["artifact_count"])

    def test_go_verifier_release_run_detects_workflow_hash_tamper(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            build_attestation, binary_path, build_log_path, sbom_path, provenance_path, signature_path = self._binary_attestation(
                tmp, release, conformance, standards
            )
            receipt = self._release_run(
                release,
                build_attestation,
                conformance,
                standards,
                binary_path,
                (build_log_path, sbom_path, provenance_path, signature_path),
            )
            tampered = copy.deepcopy(receipt)
            tampered["workflow"]["sha256"] = "0" * 64
            result = verify_go_verifier_release_run_receipt(
                tampered,
                release,
                build_attestation,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                binary_path=binary_path,
            )

        self.assertFalse(result.ok)
        self.assertTrue(any("workflow.sha256" in error for error in result.errors))

    def test_go_verifier_release_run_cli_writes_verifies_and_appends(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            build_attestation, binary_path, _, sbom_path, provenance_path, signature_path = self._binary_attestation(
                tmp, release, conformance, standards
            )
            conformance_path = tmp / "verifier-conformance.json"
            standards_path = tmp / "standards-submission.json"
            release_path = tmp / "verifier-release.json"
            build_path = tmp / "go-verifier-build.json"
            receipt_path = tmp / "go-verifier-release-run.json"
            entry_path = tmp / "go-verifier-release-run-entry.json"
            state_path = tmp / "go-verifier-release-run-chain.json"
            write_verifier_conformance_report(conformance_path, conformance)
            write_standards_submission(standards_path, standards)
            write_verifier_release_manifest(release_path, release)
            write_go_verifier_build_attestation(build_path, build_attestation)

            common_args = [
                str(release_path),
                str(build_path),
                "--conformance-report",
                str(conformance_path),
                "--standards-package",
                str(standards_path),
                "--root",
                str(ROOT),
                "--binary",
                str(binary_path),
            ]
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "go-verifier-release-run",
                    *common_args,
                    "--workflow-run-id",
                    "1234567890",
                    "--commit-sha",
                    "b" * 40,
                    "--started-at",
                    "2026-07-16T00:00:00Z",
                    "--completed-at",
                    "2026-07-16T00:04:00Z",
                    "--artifact",
                    f"{binary_path.name},{binary_path},binary",
                    "--artifact",
                    f"{sbom_path.name},{sbom_path},sbom",
                    "--artifact",
                    f"{provenance_path.name},{provenance_path},provenance",
                    "--artifact",
                    f"{signature_path.name},{signature_path},signature",
                    "--check",
                    "go test ./...,completed,success",
                    "--hosted-provenance-ref",
                    str(provenance_path),
                    "--hosted-provenance-hash",
                    _sha256_ref(provenance_path),
                    "--oidc-issuer",
                    "https://token.actions.githubusercontent.com",
                    "--oidc-subject",
                    "repo:MSBeni/trust_ai:ref:refs/heads/main",
                    "--generated-at",
                    "2026-07-16T00:05:00Z",
                    "--out",
                    str(receipt_path),
                ],
                check=True,
                cwd=ROOT,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-release-run-verify", str(receipt_path), *common_args],
                check=True,
                cwd=ROOT,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "go-verifier-release-run-append",
                    str(receipt_path),
                    *common_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "go-verifier-release-run-local",
                    "--out",
                    str(entry_path),
                ],
                check=True,
                cwd=ROOT,
            )

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        self.assertEqual(GO_VERIFIER_RELEASE_RUN_SCHEMA, receipt["schema"])
        self.assertEqual(GO_VERIFIER_RELEASE_RUN_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(receipt["run_id"], entry["payload"]["run_id"])

    def test_go_verifier_release_run_github_actions_cli_uses_provider_environment(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            build_attestation, binary_path, _, sbom_path, provenance_path, signature_path = self._binary_attestation(
                tmp, release, conformance, standards
            )
            conformance_path = tmp / "verifier-conformance.json"
            standards_path = tmp / "standards-submission.json"
            release_path = tmp / "verifier-release.json"
            build_path = tmp / "go-verifier-build.json"
            receipt_path = tmp / "go-verifier-github-actions-release-run.json"
            write_verifier_conformance_report(conformance_path, conformance)
            write_standards_submission(standards_path, standards)
            write_verifier_release_manifest(release_path, release)
            write_go_verifier_build_attestation(build_path, build_attestation)

            common_args = [
                str(release_path),
                str(build_path),
                "--conformance-report",
                str(conformance_path),
                "--standards-package",
                str(standards_path),
                "--root",
                str(ROOT),
                "--binary",
                str(binary_path),
            ]
            env = {
                **os.environ,
                "PYTHONPATH": str(ROOT / "src"),
                "GITHUB_REPOSITORY": "MSBeni/trust_ai",
                "GITHUB_RUN_ID": "9876543210",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_SHA": "c" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_WORKFLOW_REF": "MSBeni/trust_ai/.github/workflows/go-verifier.yml@refs/heads/main",
                "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_JOB": "build-linux-amd64",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
            }
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "go-verifier-release-run-github-actions",
                    *common_args,
                    "--completed-at",
                    "2026-07-16T00:04:00Z",
                    "--artifact",
                    f"{binary_path.name},{binary_path},binary",
                    "--artifact",
                    f"{sbom_path.name},{sbom_path},sbom",
                    "--artifact",
                    f"{provenance_path.name},{provenance_path},provenance",
                    "--artifact",
                    f"{signature_path.name},{signature_path},signature",
                    "--hosted-provenance-ref",
                    str(provenance_path),
                    "--hosted-provenance-hash",
                    _sha256_ref(provenance_path),
                    "--generated-at",
                    "2026-07-16T00:05:00Z",
                    "--out",
                    str(receipt_path),
                ],
                check=True,
                cwd=ROOT,
                env=env,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-release-run-verify", str(receipt_path), *common_args],
                check=True,
                cwd=ROOT,
            )

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

        self.assertEqual(GO_VERIFIER_RELEASE_RUN_SCHEMA, receipt["schema"])
        self.assertEqual("9876543210", receipt["workflow_run"]["workflow_run_id"])
        self.assertEqual(2, receipt["workflow_run"]["run_attempt"])
        self.assertEqual("https://github.com/MSBeni/trust_ai/actions/runs/9876543210", receipt["workflow_run"]["workflow_run_url"])
        self.assertEqual("c" * 40, receipt["workflow_run"]["commit_sha"])
        self.assertEqual("refs/heads/main", receipt["workflow_run"]["branch_ref"])
        self.assertEqual("workflow_dispatch", receipt["workflow_run"]["trigger_ref"])
        self.assertEqual("github-actions:github-hosted:Linux:X64", receipt["workflow_run"]["runner_ref"])
        self.assertEqual("repo:MSBeni/trust_ai:ref:refs/heads/main", receipt["provenance"]["oidc_subject"])
        self.assertEqual("build-linux-amd64", receipt["checks"][0]["name"])


if __name__ == "__main__":
    unittest.main()
