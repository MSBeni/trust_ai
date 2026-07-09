import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_identity_provider_lifecycle_operation import IdentityProviderLifecycleOperationTests
from trustai.chain import EvidenceChain
from trustai.identity_provider_attestation import write_identity_provider_attestation
from trustai.identity_provider_lifecycle_operation import write_identity_provider_lifecycle_operation_receipt
from trustai.identity_provider_lifecycle_worker import (
    IDENTITY_PROVIDER_LIFECYCLE_WORKER_ENTRY_TYPE,
    IDENTITY_PROVIDER_LIFECYCLE_WORKER_SCHEMA,
    append_identity_provider_lifecycle_worker_receipt,
    build_identity_provider_lifecycle_worker_receipt,
    verify_identity_provider_lifecycle_worker_receipt,
)
from trustai.identity_provider_session import write_identity_provider_session_receipt
from trustai.trust_network import write_trust_network_manifest
from trustai.vendor_identity import write_vendor_identity_receipt


ROOT = Path(__file__).resolve().parents[1]


class IdentityProviderLifecycleWorkerTests(unittest.TestCase):
    def _sources(self, tmp: Path) -> dict:
        helper = IdentityProviderLifecycleOperationTests()
        sources = helper._sources(tmp)
        sources["lifecycle_operation"] = helper._receipt(sources)
        return sources

    def _receipt(self, sources: dict) -> dict:
        return build_identity_provider_lifecycle_worker_receipt(
            sources["lifecycle_operation"],
            identity_provider_attestation=sources["attestation"],
            identity_provider_session_receipt=sources["session"],
            identity_payload=sources["identity_payload"],
            identity_payload_path=sources["identity_payload_path"],
            vendor_identity_receipt=sources["vendor"],
            proof_packs=[sources["pack"]],
            trust_network_manifest=sources["manifest"],
            mode="hosted-worker",
            environment="aitrade-prod",
            worker_ref="worker:identity-provider/lifecycle/okta",
            run_ref="worker-run:identity-provider/lifecycle/2026-07-12T02:01:05Z",
            operation_kind="app_assignment_propagation",
            actor_ref="oidc:trustai.example/identity-lifecycle-worker",
            schedule_ref="schedule:identity-provider/lifecycle/1m",
            cadence_seconds=60,
            lease_ref="lease:identity-provider/lifecycle/2026-07-12T02:01:05Z",
            checkpoint_ref="checkpoint:identity-provider/lifecycle/okta",
            checkpoint_hash="sha256:identity-provider-lifecycle-worker-checkpoint",
            previous_cursor_ref="okta:system-log/cursor/before-assignment",
            next_cursor_ref="okta:system-log/cursor/after-assignment",
            queue_ref="queue:identity-provider/lifecycle",
            queue_message_ref="queue-message:identity-provider/lifecycle/app-assignment",
            destination_ref="identity-provider:okta/example-org",
            propagation_log_ref="propagation-log:identity-provider/lifecycle/okta",
            propagation_log_root="sha256:identity-provider-lifecycle-worker-propagation-root",
            account_state_log_ref="account-state-log:identity-provider/okta",
            account_state_log_root="sha256:identity-provider-lifecycle-worker-account-root",
            request_hash="sha256:identity-provider-lifecycle-worker-request",
            response_status=200,
            response_hash="sha256:identity-provider-lifecycle-worker-response",
            metrics_ref="metrics:identity-provider/lifecycle-worker",
            audit_log_ref="audit-log:identity-provider/lifecycle-worker",
            audit_log_root="sha256:identity-provider-lifecycle-worker-audit-root",
            credential_ref="env:OKTA_LIFECYCLE_WORKER_TOKEN",
            started_at="2026-07-12T02:01:05Z",
            completed_at="2026-07-12T02:01:07Z",
            next_run_at="2026-07-12T02:02:05Z",
            retention_until="2033-07-12T00:00:00Z",
            evidence_refs=["evidence:identity-provider/lifecycle-worker"],
        )

    def test_identity_provider_lifecycle_worker_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            receipt = self._receipt(sources)
            result = verify_identity_provider_lifecycle_worker_receipt(
                receipt,
                lifecycle_operation_receipt=sources["lifecycle_operation"],
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            chain = EvidenceChain.load(tmp / "worker-chain.json", tenant_id="identity-provider-lifecycle-worker-local")
            entry = append_identity_provider_lifecycle_worker_receipt(
                chain,
                receipt,
                lifecycle_operation_receipt=sources["lifecycle_operation"],
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(IDENTITY_PROVIDER_LIFECYCLE_WORKER_SCHEMA, receipt["schema"])
            self.assertEqual(sources["lifecycle_operation"]["operation_id"], receipt["source_operation"]["operation_id"])
            self.assertEqual(IDENTITY_PROVIDER_LIFECYCLE_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])

    def test_identity_provider_lifecycle_worker_detects_source_operation_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            tampered = copy.deepcopy(sources["lifecycle_operation"])
            tampered["operation"]["identity_id"] = "okta-agent-other"

            result = verify_identity_provider_lifecycle_worker_receipt(
                receipt,
                lifecycle_operation_receipt=tampered,
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("source identity provider lifecycle operation invalid" in error for error in result.errors))
            self.assertTrue(any("source operation does not match" in error for error in result.errors))

    def test_identity_provider_lifecycle_worker_replays_identity_payload_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            receipt = self._receipt(sources)
            payload_path = sources["identity_payload_path"]
            payload_path.write_text(payload_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            replay_payload = json.loads(payload_path.read_text(encoding="utf-8"))

            result = verify_identity_provider_lifecycle_worker_receipt(
                receipt,
                lifecycle_operation_receipt=sources["lifecycle_operation"],
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=replay_payload,
                identity_payload_path=payload_path,
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )

            self.assertFalse(result.ok)
            self.assertTrue(
                any(
                    "source identity provider lifecycle operation invalid" in error and "source_artifacts do not match supplied identity payload artifact" in error
                    for error in result.errors
                )
            )

    def test_cli_identity_provider_lifecycle_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            paths = {
                "pack": tmp / "pack.json",
                "manifest": tmp / "manifest.json",
                "vendor": tmp / "vendor.json",
                "identity_payload": tmp / "identity-payload.json",
                "attestation": tmp / "identity-attestation.json",
                "session": tmp / "identity-session.json",
                "lifecycle": tmp / "identity-lifecycle-operation.json",
                "worker": tmp / "identity-lifecycle-worker.json",
                "entry": tmp / "identity-lifecycle-worker-entry.json",
                "chain": tmp / "identity-lifecycle-worker-chain.json",
            }
            paths["pack"].write_text(json.dumps(sources["pack"], indent=2, sort_keys=True), encoding="utf-8")
            write_trust_network_manifest(paths["manifest"], sources["manifest"])
            write_vendor_identity_receipt(paths["vendor"], sources["vendor"])
            paths["identity_payload"].write_text(sources["identity_payload_path"].read_text(encoding="utf-8"), encoding="utf-8")
            write_identity_provider_attestation(paths["attestation"], sources["attestation"])
            write_identity_provider_session_receipt(paths["session"], sources["session"])
            write_identity_provider_lifecycle_operation_receipt(paths["lifecycle"], sources["lifecycle_operation"])

            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            source_args = [
                str(paths["lifecycle"]),
                str(paths["attestation"]),
                "--identity-payload",
                str(paths["identity_payload"]),
                "--vendor-identity",
                str(paths["vendor"]),
                "--manifest",
                str(paths["manifest"]),
                "--pack",
                str(paths["pack"]),
                "--identity-session",
                str(paths["session"]),
            ]
            build_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "identity-lifecycle-worker",
                *source_args,
                "--mode",
                "hosted-worker",
                "--environment",
                "aitrade-prod",
                "--worker-ref",
                "worker:identity-provider/lifecycle/okta",
                "--run-ref",
                "worker-run:identity-provider/lifecycle/2026-07-12T02:01:05Z",
                "--operation-kind",
                "app_assignment_propagation",
                "--actor-ref",
                "oidc:trustai.example/identity-lifecycle-worker",
                "--schedule-ref",
                "schedule:identity-provider/lifecycle/1m",
                "--cadence-seconds",
                "60",
                "--lease-ref",
                "lease:identity-provider/lifecycle/2026-07-12T02:01:05Z",
                "--checkpoint-ref",
                "checkpoint:identity-provider/lifecycle/okta",
                "--checkpoint-hash",
                "sha256:identity-provider-lifecycle-worker-checkpoint",
                "--previous-cursor-ref",
                "okta:system-log/cursor/before-assignment",
                "--next-cursor-ref",
                "okta:system-log/cursor/after-assignment",
                "--queue-ref",
                "queue:identity-provider/lifecycle",
                "--queue-message-ref",
                "queue-message:identity-provider/lifecycle/app-assignment",
                "--destination-ref",
                "identity-provider:okta/example-org",
                "--propagation-log-ref",
                "propagation-log:identity-provider/lifecycle/okta",
                "--propagation-log-root",
                "sha256:identity-provider-lifecycle-worker-propagation-root",
                "--account-state-log-ref",
                "account-state-log:identity-provider/okta",
                "--account-state-log-root",
                "sha256:identity-provider-lifecycle-worker-account-root",
                "--request-hash",
                "sha256:identity-provider-lifecycle-worker-request",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:identity-provider-lifecycle-worker-response",
                "--metrics-ref",
                "metrics:identity-provider/lifecycle-worker",
                "--audit-log-ref",
                "audit-log:identity-provider/lifecycle-worker",
                "--audit-log-root",
                "sha256:identity-provider-lifecycle-worker-audit-root",
                "--credential-ref",
                "env:OKTA_LIFECYCLE_WORKER_TOKEN",
                "--started-at",
                "2026-07-12T02:01:05Z",
                "--completed-at",
                "2026-07-12T02:01:07Z",
                "--next-run-at",
                "2026-07-12T02:02:05Z",
                "--retention-until",
                "2033-07-12T00:00:00Z",
                "--evidence-ref",
                "evidence:identity-provider/lifecycle-worker",
                "--out",
                str(paths["worker"]),
            ]
            verify_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "identity-lifecycle-worker-verify",
                str(paths["worker"]),
                *source_args,
            ]
            append_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "identity-lifecycle-worker-append",
                str(paths["worker"]),
                *source_args,
                "--state",
                str(paths["chain"]),
                "--tenant",
                "identity-provider-lifecycle-worker-local",
                "--out",
                str(paths["entry"]),
            ]

            for command in (build_cmd, verify_cmd, append_cmd):
                completed = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(0, completed.returncode, completed.stderr)

            receipt = json.loads(paths["worker"].read_text(encoding="utf-8"))
            entry = json.loads(paths["entry"].read_text(encoding="utf-8"))
            self.assertEqual("hosted-worker", receipt["mode"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])


if __name__ == "__main__":
    unittest.main()
