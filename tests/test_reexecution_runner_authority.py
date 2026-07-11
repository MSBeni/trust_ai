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
from trustai.reexecution import write_reexecution_report
from trustai.reexecution_isolation import write_reexecution_isolation_attestation
from trustai.reexecution_runner import write_reexecution_runner_evidence
from trustai.reexecution_runner_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    REEXECUTION_RUNNER_AUTHORITY_ENTRY_TYPE,
    REEXECUTION_RUNNER_AUTHORITY_SCHEMA,
    append_reexecution_runner_authority_dossier,
    build_reexecution_runner_authority_dossier,
    verify_reexecution_runner_authority_dossier,
    write_reexecution_runner_authority_dossier,
)
from trustai.reexecution_runner_service import write_reexecution_runner_service_attestation
from trustai.reexecution_runner_worker import write_reexecution_runner_worker_receipt

from tests import test_reexecution_runner_worker as worker_fixtures

ROOT = worker_fixtures.ROOT


class ReexecutionRunnerAuthorityTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = worker_fixtures.ReexecutionRunnerWorkerTests()
        evidence, policy, report, isolation, service = helper._sources(tmp)
        worker = helper._receipt(evidence, policy, report, isolation, service)
        return evidence, policy, report, isolation, service, worker

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "production-runner-fleet",
                "authority_kind": "hosted-service",
                "evidence_ref": "runner-fleet:trustai/reexecution-prod",
                "evidence_hash": "sha256:reexecution-runner-prod-fleet",
                "description": "Hosted re-execution runner fleet export for production replay jobs.",
                "issuer": "TrustAI Hosted Ops",
                "subject": "aitrade-prod re-execution runner fleet",
                "source_uri": "https://runner.example/audit/fleet/aitrade-prod",
                "issued_at": "2026-07-04T04:09:00Z",
                "expires_at": "2026-07-11T04:09:00Z",
            },
            {
                "requirement_id": "immutable-runtime-audit-logs",
                "authority_kind": "cloud-object-lock",
                "evidence_ref": "s3-object-lock:runner/audit/aitrade-prod",
                "evidence_hash": "sha256:reexecution-runner-immutable-audit-root",
                "description": "Object Lock audit-log root for runner service, worker, runtime, and kernel events.",
                "issuer": "Example Cloud Object Lock",
                "subject": "aitrade-prod runner audit retention",
                "source_uri": "https://object-lock.example/runner/audit/aitrade-prod",
                "issued_at": "2026-07-04T04:09:30Z",
                "expires_at": "2026-07-11T04:09:30Z",
            },
        ]

    def _dossier(self, service, worker, isolation, evidence, policy, report, *, mode: str = "runner-service-dossier", authority_evidence: list[dict] | None = None) -> dict:
        return build_reexecution_runner_authority_dossier(
            service,
            worker_receipts=[worker],
            isolation_attestation=isolation,
            runner_evidence=evidence,
            policy=policy,
            report=report,
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:reexecution-runner-authority/aitrade-prod",
            authority_ref="authority:reexecution-runner/prod",
            producer_ref="oidc:trustai.example/reexecution-runner-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-04T04:10:00Z",
        )

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "reexecution_runner_authority": body})]

    def test_reexecution_runner_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service, worker = self._sources(Path(tmp_dir))
            dossier = self._dossier(service, worker, isolation, evidence, policy, report)
            result = verify_reexecution_runner_authority_dossier(
                dossier,
                service_attestation=service,
                worker_receipts=[worker],
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "runner-authority-chain.json", tenant_id="runner-authority-test")
            entry = append_reexecution_runner_authority_dossier(
                chain,
                dossier,
                service_attestation=service,
                worker_receipts=[worker],
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(REEXECUTION_RUNNER_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertEqual(2, result.fresh_evidence_count)
            self.assertEqual(1, dossier["source_binding"]["worker_count"])
            self.assertEqual(service["attestation_id"], dossier["source_binding"]["service_attestation_id"])
            self.assertEqual([worker["worker_operation_id"]], dossier["source_binding"]["worker_operation_ids"])
            self.assertTrue(any("evidence missing for" in warning for warning in result.warnings), result.warnings)
            self.assertEqual(REEXECUTION_RUNNER_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual({"deferred": 2, "passed": 4}, entry["payload"]["control_summary"])
            self.assertEqual(dossier["authority_evidence"][0]["source_context"], entry["payload"]["authority_evidence"][0]["source_context"])
            self.assertEqual(content_hash(dossier["source_binding"]), dossier["authority_evidence"][0]["source_context"]["source_binding_hash"])
            self.assertTrue(chain.verify_all().ok)

    def test_reexecution_runner_authority_rejects_resigned_source_context_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service, worker = self._sources(Path(tmp_dir))
            dossier = self._dossier(service, worker, isolation, evidence, policy, report)
            tampered = copy.deepcopy(dossier)
            item = tampered["authority_evidence"][0]
            item["source_context"]["worker_count"] = 999
            item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
            self._resign_dossier(tampered)

            result = verify_reexecution_runner_authority_dossier(
                tampered,
                service_attestation=service,
                worker_receipts=[worker],
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertFalse(result.ok)
            self.assertIn("re-execution runner authority source_context does not match source binding: production-runner-fleet", result.errors)

    def test_reexecution_runner_authority_rejects_resigned_control_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service, worker = self._sources(Path(tmp_dir))
            dossier = self._dossier(service, worker, isolation, evidence, policy, report)
            tampered = copy.deepcopy(dossier)
            tampered["controls"][0]["status"] = "failed"
            self._resign_dossier(tampered)

            result = verify_reexecution_runner_authority_dossier(
                tampered,
                service_attestation=service,
                worker_receipts=[worker],
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertFalse(result.ok)
            self.assertIn("re-execution runner authority controls do not match dossier body", result.errors)

    def test_reexecution_runner_authority_detects_worker_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service, worker = self._sources(Path(tmp_dir))
            dossier = self._dossier(service, worker, isolation, evidence, policy, report)
            tampered_worker = copy.deepcopy(worker)
            tampered_worker["execution"]["response_status"] = 500

            result = verify_reexecution_runner_authority_dossier(
                dossier,
                service_attestation=service,
                worker_receipts=[tampered_worker],
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("source_binding does not match" in error or "worker source" in error for error in result.errors), result.errors)

    def test_reexecution_runner_authority_requires_complete_source_binding_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service, worker = self._sources(Path(tmp_dir))
            dossier = self._dossier(service, worker, isolation, evidence, policy, report)
            tampered = copy.deepcopy(dossier)
            tampered["source_binding"]["worker_operation_records"][0].pop("response_hash")
            body = without_keys(tampered, "dossier_id", "signatures")
            dossier_id = content_hash(body)
            tampered["dossier_id"] = dossier_id
            tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "reexecution_runner_authority": body})]

            result = verify_reexecution_runner_authority_dossier(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("worker_operation_records[0].response_hash is required" in error for error in result.errors), result.errors)

    def test_reexecution_runner_authority_requires_freshness_when_strict(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service, worker = self._sources(Path(tmp_dir))
            authority = [dict(self._authority_evidence()[0])]
            authority[0].pop("issued_at")
            authority[0].pop("expires_at")
            dossier = self._dossier(service, worker, isolation, evidence, policy, report, authority_evidence=authority)

            result = verify_reexecution_runner_authority_dossier(
                dossier,
                service_attestation=service,
                worker_receipts=[worker],
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
                require_fresh=True,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_reexecution_runner_authority_rejects_incomplete_production_claim(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence, policy, report, isolation, service, worker = self._sources(Path(tmp_dir))
            dossier = self._dossier(service, worker, isolation, evidence, policy, report, mode="production-dossier")

            result = verify_reexecution_runner_authority_dossier(
                dossier,
                service_attestation=service,
                worker_receipts=[worker],
                isolation_attestation=isolation,
                runner_evidence=evidence,
                policy=policy,
                report=report,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_cli_reexecution_runner_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence, policy, report, isolation, service, worker = self._sources(tmp)
            evidence_path = tmp / "reexecution-runner-evidence.json"
            policy_path = tmp / "reexecution-policy.json"
            report_path = tmp / "reexecution-report.json"
            isolation_path = tmp / "reexecution-isolation-attestation.json"
            service_path = tmp / "reexecution-runner-service-attestation.json"
            worker_path = tmp / "reexecution-runner-worker.json"
            dossier_path = tmp / "reexecution-runner-authority.json"
            entry_path = tmp / "reexecution-runner-authority-entry.json"
            state_path = tmp / "runner-authority-chain.json"
            write_reexecution_runner_evidence(evidence_path, evidence)
            policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True), encoding="utf-8")
            write_reexecution_report(report_path, report)
            write_reexecution_isolation_attestation(isolation_path, isolation)
            write_reexecution_runner_service_attestation(service_path, service)
            write_reexecution_runner_worker_receipt(worker_path, worker)

            evidence_arg = (
                "production-runner-fleet,hosted-service,runner-fleet:trustai/reexecution-prod,"
                "sha256:reexecution-runner-prod-fleet,Hosted re-execution runner fleet export for production replay jobs;"
                "issuer=TrustAI Hosted Ops;subject=aitrade-prod re-execution runner fleet;"
                "source_uri=https://runner.example/audit/fleet/aitrade-prod;"
                "issued_at=2026-07-04T04:09:00Z;expires_at=2026-07-11T04:09:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(service_path),
                "--worker-receipt",
                str(worker_path),
                str(isolation_path),
                str(evidence_path),
                "--policy",
                str(policy_path),
                "--report",
                str(report_path),
            ]
            authority_args = [
                "--environment",
                "aitrade-prod",
                "--dossier-ref",
                "dossier:reexecution-runner-authority/aitrade-prod",
                "--authority-ref",
                "authority:reexecution-runner/prod",
                "--producer-ref",
                "oidc:trustai.example/reexecution-runner-authority-worker",
                "--authority-evidence",
                evidence_arg,
                "--generated-at",
                "2026-07-04T04:10:00Z",
            ]

            subprocess.run(
                [sys.executable, "-m", "trustai", "reexecution-runner-authority", *source_args, *authority_args, "--out", str(dossier_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "reexecution-runner-authority-verify", str(dossier_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "reexecution-runner-authority-append",
                    str(dossier_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "reexecution-runner-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(dossier_path.exists())
            self.assertTrue(entry_path.exists())
            dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(1, entry["payload"]["summary"]["covered_requirement_count"])
            self.assertEqual(1, entry["payload"]["source_binding"]["worker_count"])


if __name__ == "__main__":
    unittest.main()
