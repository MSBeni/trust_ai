import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import contract_hash, load_contract
from trustai.reexecution import build_reexecution_report, write_reexecution_report
from trustai.reexecution_isolation import (
    REEXECUTION_ISOLATION_ENTRY_TYPE,
    REEXECUTION_ISOLATION_SCHEMA,
    append_reexecution_isolation_attestation,
    build_reexecution_isolation_attestation,
    verify_reexecution_isolation_attestation,
    write_reexecution_isolation_attestation,
)
from trustai.reexecution_policy import load_reexecution_policy
from trustai.reexecution_runner import (
    load_reexecution_runner_plan,
    run_reexecution_plan,
    runner_results,
    write_reexecution_runner_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
POLICY = ROOT / "examples" / "aitrade" / "reexecution-policy.json"
PLAN = ROOT / "examples" / "aitrade" / "reexecution-runner-plan.json"
FIXTURE = ROOT / "examples" / "aitrade" / "reexecution_runner_fixture.py"


class ReexecutionIsolationTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        contract = load_contract(CONTRACT)
        policy = load_reexecution_policy(POLICY)
        plan = load_reexecution_runner_plan(PLAN)
        plan["command"] = ["{python}", str(FIXTURE)]
        plan["contract"] = {"id": contract["id"], "hash": contract_hash(contract), "agent": contract.get("agent")}
        for index, run in enumerate(plan["runs"], start=1):
            run["output"] = f"runner-runs/eval-results-runner-{index}.json"
        evidence = run_reexecution_plan(plan, base_dir=tmp, generated_at="2026-07-04T04:00:00Z")
        report = build_reexecution_report(
            contract,
            runner_results(evidence),
            temperature=0,
            policy=policy,
            generated_at="2026-07-04T04:05:00Z",
        )
        return evidence, policy, report

    def _attestation(self, evidence, policy, report, **overrides):
        values = {
            "runner_evidence": evidence,
            "policy": policy,
            "report": report,
            "mode": "container-attested",
            "environment": "local",
            "isolation_ref": "isolation:aitrade/reexecution/2026-07-04",
            "runner_ref": "runner:trustai-reexecution/local",
            "runner_provider": "TrustAI Local Runner",
            "orchestrator": "kubernetes",
            "container_runtime": "containerd",
            "kernel": "linux-6.8",
            "namespace_mode": "private",
            "cgroup_ref": "cgroup:trustai/reexecution/aitrade",
            "seccomp_profile_hash": "sha256:trustai-reexecution-seccomp",
            "apparmor_profile_hash": "sha256:trustai-reexecution-apparmor",
            "network_mode": "disabled",
            "filesystem_policy_ref": "fs-policy:trustai/reexecution/read-only-root",
            "read_only_rootfs": True,
            "writable_mounts": ["/tmp/trustai-runner"],
            "denied_mounts": ["/var/run/docker.sock", "/home"],
            "egress_policy_ref": "egress-policy:deny-all",
            "seed_policy": "recorded-or-fixed-seed",
            "temperature": 0,
            "entropy_source_ref": "entropy:fixed-seed-runner",
            "audit_log_ref": "audit-log:reexecution/isolation",
            "audit_log_root": "sha256:reexecution-isolation-audit-root",
            "retention_until": "2033-07-04T00:00:00Z",
            "actor_ref": "oidc:trustai.example/reexecution-runner",
            "credential_ref": "env:REEXECUTION_RUNNER_TOKEN",
            "evidence_refs": ["evidence:reexecution/isolation"],
            "attested_at": "2026-07-04T04:06:00Z",
        }
        values.update(overrides)
        return build_reexecution_isolation_attestation(**values)

    def test_reexecution_isolation_attestation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report = self._sources(Path(tmp_dir))
            attestation = self._attestation(evidence, policy, report)
            result = verify_reexecution_isolation_attestation(attestation, evidence, policy=policy, report=report)
            chain = EvidenceChain.load(Path(tmp_dir) / "isolation-chain.json", tenant_id="reexecution-isolation-test")
            entry = append_reexecution_isolation_attestation(chain, attestation, evidence, policy=policy, report=report)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(REEXECUTION_ISOLATION_SCHEMA, attestation["schema"])
            self.assertEqual("disabled", attestation["isolation"]["network_mode"])
            self.assertTrue(attestation["isolation"]["read_only_rootfs"])
            self.assertEqual([2026070301, 2026070302, 2026070303], attestation["execution_controls"]["seeds"])
            self.assertEqual(REEXECUTION_ISOLATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_reexecution_isolation_attestation_rejects_network_enabled(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report = self._sources(Path(tmp_dir))
            attestation = self._attestation(evidence, policy, report)
            tampered = copy.deepcopy(attestation)
            tampered["isolation"]["network_mode"] = "egress"

            result = verify_reexecution_isolation_attestation(tampered, evidence, policy=policy, report=report)

            self.assertFalse(result.ok)
            self.assertTrue(any("attestation_id" in error for error in result.errors))
            self.assertIn("re-execution isolation isolation.network_mode must be disabled", result.errors)
            self.assertIn("isolation.network_mode does not match re-execution policy sandbox.network", result.errors)

    def test_reexecution_isolation_attestation_rejects_report_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report = self._sources(Path(tmp_dir))
            attestation = self._attestation(evidence, policy, report)
            tampered_report = copy.deepcopy(report)
            tampered_report["source_runs"][0]["results_hash"] = "changed"

            result = verify_reexecution_isolation_attestation(attestation, evidence, policy=policy, report=tampered_report)

            self.assertFalse(result.ok)
            self.assertTrue(any("source report invalid" in error for error in result.errors))
            self.assertIn("re-execution isolation source_artifacts do not match supplied source artifacts", result.errors)

    def test_cli_reexecution_isolation_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence, policy, report = self._sources(tmp)
            evidence_path = tmp / "reexecution-runner-evidence.json"
            policy_path = tmp / "reexecution-policy.json"
            report_path = tmp / "reexecution-report.json"
            attestation_path = tmp / "reexecution-isolation-attestation.json"
            entry_path = tmp / "reexecution-isolation-entry.json"
            state_path = tmp / "isolation-chain.json"
            write_reexecution_runner_evidence(evidence_path, evidence)
            policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True), encoding="utf-8")
            write_reexecution_report(report_path, report)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base_args = [
                str(evidence_path),
                "--policy",
                str(policy_path),
                "--report",
                str(report_path),
            ]
            isolation_args = [
                "--isolation-ref",
                "isolation:aitrade/reexecution/2026-07-04",
                "--runner-ref",
                "runner:trustai-reexecution/local",
                "--runner-provider",
                "TrustAI Local Runner",
                "--orchestrator",
                "kubernetes",
                "--container-runtime",
                "containerd",
                "--kernel",
                "linux-6.8",
                "--namespace-mode",
                "private",
                "--cgroup-ref",
                "cgroup:trustai/reexecution/aitrade",
                "--seccomp-profile-hash",
                "sha256:trustai-reexecution-seccomp",
                "--apparmor-profile-hash",
                "sha256:trustai-reexecution-apparmor",
                "--network-mode",
                "disabled",
                "--filesystem-policy-ref",
                "fs-policy:trustai/reexecution/read-only-root",
                "--read-only-rootfs",
                "--writable-mount",
                "/tmp/trustai-runner",
                "--denied-mount",
                "/var/run/docker.sock",
                "--egress-policy-ref",
                "egress-policy:deny-all",
                "--seed-policy",
                "recorded-or-fixed-seed",
                "--temperature",
                "0",
                "--entropy-source-ref",
                "entropy:fixed-seed-runner",
                "--audit-log-ref",
                "audit-log:reexecution/isolation",
                "--audit-log-root",
                "sha256:reexecution-isolation-audit-root",
                "--retention-until",
                "2033-07-04T00:00:00Z",
                "--actor-ref",
                "oidc:trustai.example/reexecution-runner",
                "--credential-ref",
                "env:REEXECUTION_RUNNER_TOKEN",
                "--evidence-ref",
                "evidence:reexecution/isolation",
                "--attested-at",
                "2026-07-04T04:06:00Z",
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reexecution-isolation-attestation",
                    *base_args,
                    *isolation_args,
                    "--out",
                    str(attestation_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reexecution-isolation-verify",
                    str(attestation_path),
                    *base_args,
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reexecution-isolation-append",
                    str(attestation_path),
                    *base_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "reexecution-isolation-local",
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
