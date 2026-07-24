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
from trustai.identity_provider_attestation import build_identity_provider_attestation, write_identity_provider_attestation
from trustai.identity_provider_lifecycle_operation import (
    IDENTITY_PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE,
    IDENTITY_PROVIDER_LIFECYCLE_OPERATION_SCHEMA,
    append_identity_provider_lifecycle_operation_receipt,
    build_identity_provider_lifecycle_operation_receipt,
    verify_identity_provider_lifecycle_operation_receipt,
)
from trustai.identity_provider_session import build_identity_provider_session_receipt, write_identity_provider_session_receipt
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.trust_network import build_trust_network_manifest, write_trust_network_manifest
from trustai.vendor_identity import build_vendor_identity_receipt, write_vendor_identity_receipt


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
IDENTITY = ROOT / "examples" / "aitrade" / "identity-inventory.json"


class IdentityProviderLifecycleOperationTests(unittest.TestCase):
    def _sources(self, tmp: Path) -> dict:
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="identity-provider-lifecycle-test")
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
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        manifest = build_trust_network_manifest([pack], vendor_names=["aitrade"], buyer="finserv-buyer")
        vendor = build_vendor_identity_receipt(
            [pack],
            vendor="aitrade",
            legal_name="Aitrade Labs Inc.",
            subject_ref="did:web:aitrade.example",
            domain="aitrade.example",
            identity_provider="okta",
            identity_id="okta-agent-aitrade-risk",
            issued_at="2026-07-10T00:00:00Z",
            expires_at="2027-07-10T00:00:00Z",
            trust_network_manifest=manifest,
        )
        payload_path = tmp / "identity-payload.json"
        payload_path.write_text(IDENTITY.read_text(encoding="utf-8"), encoding="utf-8")
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        attestation = build_identity_provider_attestation(
            payload,
            identity_payload_path=payload_path,
            vendor_identity_receipt=vendor,
            proof_packs=[pack],
            trust_network_manifest=manifest,
            provider="okta",
            identity_id="okta-agent-aitrade-risk",
            issuer="trustai-local",
            tenant_ref="okta:example-org",
            authentication_method="recorded-export",
            issued_at="2026-07-10T01:00:00Z",
            expires_at="2027-07-10T01:00:00Z",
        )
        session = build_identity_provider_session_receipt(
            attestation,
            identity_payload=payload,
            identity_payload_path=payload_path,
            vendor_identity_receipt=vendor,
            proof_packs=[pack],
            trust_network_manifest=manifest,
            mode="provider-event-stream",
            environment="aitrade-prod",
            provider_tenant_ref="okta:example-org",
            session_ref="okta-session:aitrade-risk/2026-07-12T02:00:00Z",
            event_ref="okta-event:evt_20260712_aitrade_token_introspection",
            event_kind="token_introspection",
            provider_event_id="evt_20260712_aitrade_token_introspection",
            actor_ref="oidc:trustai.example/identity-session-worker",
            authn_method="oauth2-client-credentials",
            assurance_level="aal2",
            scope_refs=["scope:trustai/proof-pack.read"],
            audience_refs=["audience:trustai-registry"],
            decision="allowed",
            risk_level="low",
            endpoint_url="https://okta.example/oauth2/v1/introspect",
            credential_ref="env:OKTA_INTROSPECTION_TOKEN",
            request_hash="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            response_status=200,
            response_hash="sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            session_log_ref="okta:system-log/query/aitrade-session",
            session_log_root="sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            audit_log_ref="audit-log:identity-provider/session-worker",
            audit_log_root="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            source_ip_hash="sha256:1111111111111111111111111111111111111111111111111111111111111111",
            device_ref="workload:trustai/identity-session-worker",
            user_agent_hash="sha256:2222222222222222222222222222222222222222222222222222222222222222",
            session_started_at="2026-07-12T02:00:00Z",
            session_expires_at="2026-07-12T03:00:00Z",
            observed_at="2026-07-12T02:00:05Z",
            recorded_at="2026-07-12T02:00:06Z",
            retention_until="2033-07-12T00:00:00Z",
            evidence_refs=["evidence:identity-provider/session"],
        )
        return {
            "pack": pack,
            "manifest": manifest,
            "vendor": vendor,
            "identity_payload": payload,
            "identity_payload_path": payload_path,
            "attestation": attestation,
            "session": session,
        }

    def _receipt(self, sources: dict) -> dict:
        return build_identity_provider_lifecycle_operation_receipt(
            sources["attestation"],
            identity_provider_session_receipt=sources["session"],
            identity_payload=sources["identity_payload"],
            identity_payload_path=sources["identity_payload_path"],
            vendor_identity_receipt=sources["vendor"],
            proof_packs=[sources["pack"]],
            trust_network_manifest=sources["manifest"],
            mode="hosted-lifecycle-worker",
            environment="aitrade-prod",
            provider_tenant_ref="okta:example-org",
            operation_ref="okta-lifecycle:aitrade-risk/app-assignment/2026-07-12",
            operation_kind="app_assignment",
            provider_operation_id="evt_20260712_aitrade_app_assignment",
            actor_ref="oidc:trustai.example/identity-lifecycle-worker",
            target_state="assigned",
            endpoint_url="https://okta.example/api/v1/apps/app123/users",
            credential_ref="env:OKTA_LIFECYCLE_TOKEN",
            request_hash="sha256:identity-provider-lifecycle-request",
            response_status=200,
            response_hash="sha256:identity-provider-lifecycle-response",
            system_log_ref="okta:system-log/query/aitrade-lifecycle",
            system_log_root="sha256:identity-provider-lifecycle-system-log-root",
            audit_log_ref="audit-log:identity-provider/lifecycle-worker",
            audit_log_root="sha256:identity-provider-lifecycle-audit-root",
            requested_at="2026-07-12T02:01:00Z",
            completed_at="2026-07-12T02:01:02Z",
            recorded_at="2026-07-12T02:01:03Z",
            retention_until="2033-07-12T00:00:00Z",
            reason_ref="change:aitrade-risk/app-assignment",
            approval_ref="approval:aitrade-risk/app-assignment",
            change_ticket_ref="ticket:IDENTITY-1234",
            resulting_identity_record_hash="sha256:identity-provider-lifecycle-resulting-record",
            evidence_refs=["evidence:identity-provider/lifecycle"],
        )

    def test_identity_provider_lifecycle_operation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            receipt = self._receipt(sources)
            result = verify_identity_provider_lifecycle_operation_receipt(
                receipt,
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            chain = EvidenceChain.load(tmp / "lifecycle-chain.json", tenant_id="identity-provider-lifecycle-local")
            entry = append_identity_provider_lifecycle_operation_receipt(
                chain,
                receipt,
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(IDENTITY_PROVIDER_LIFECYCLE_OPERATION_SCHEMA, receipt["schema"])
            self.assertEqual("okta-agent-aitrade-risk", receipt["operation"]["identity_id"])
            self.assertEqual(IDENTITY_PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["operation_id"], entry["payload"]["operation_id"])

    def test_identity_provider_lifecycle_operation_detects_session_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            tampered = copy.deepcopy(sources["session"])
            tampered["session"]["identity_id"] = "okta-agent-other"

            result = verify_identity_provider_lifecycle_operation_receipt(
                receipt,
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=tampered,
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("source identity provider session invalid" in error for error in result.errors))
            self.assertTrue(any("session binding" in error for error in result.errors))

    def test_identity_provider_lifecycle_operation_replays_identity_payload_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            receipt = self._receipt(sources)
            payload_path = sources["identity_payload_path"]
            payload_path.write_text(payload_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            replay_payload = json.loads(payload_path.read_text(encoding="utf-8"))

            result = verify_identity_provider_lifecycle_operation_receipt(
                receipt,
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
                    "source identity provider attestation invalid: identity provider source_artifacts do not match supplied identity payload artifact" in error
                    for error in result.errors
                )
            )

    def test_cli_identity_provider_lifecycle_operation_round_trip(self):
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
                "entry": tmp / "identity-lifecycle-operation-entry.json",
                "chain": tmp / "identity-lifecycle-operation-chain.json",
            }
            paths["pack"].write_text(json.dumps(sources["pack"], indent=2, sort_keys=True), encoding="utf-8")
            write_trust_network_manifest(paths["manifest"], sources["manifest"])
            write_vendor_identity_receipt(paths["vendor"], sources["vendor"])
            paths["identity_payload"].write_text(sources["identity_payload_path"].read_text(encoding="utf-8"), encoding="utf-8")
            write_identity_provider_attestation(paths["attestation"], sources["attestation"])
            write_identity_provider_session_receipt(paths["session"], sources["session"])

            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            source_args = [
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
                "identity-lifecycle-operation",
                *source_args,
                "--mode",
                "hosted-lifecycle-worker",
                "--environment",
                "aitrade-prod",
                "--provider-tenant-ref",
                "okta:example-org",
                "--operation-ref",
                "okta-lifecycle:aitrade-risk/app-assignment/2026-07-12",
                "--operation-kind",
                "app_assignment",
                "--provider-operation-id",
                "evt_20260712_aitrade_app_assignment",
                "--actor-ref",
                "oidc:trustai.example/identity-lifecycle-worker",
                "--target-state",
                "assigned",
                "--endpoint-url",
                "https://okta.example/api/v1/apps/app123/users",
                "--credential-ref",
                "env:OKTA_LIFECYCLE_TOKEN",
                "--request-hash",
                "sha256:identity-provider-lifecycle-request",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:identity-provider-lifecycle-response",
                "--system-log-ref",
                "okta:system-log/query/aitrade-lifecycle",
                "--system-log-root",
                "sha256:identity-provider-lifecycle-system-log-root",
                "--audit-log-ref",
                "audit-log:identity-provider/lifecycle-worker",
                "--audit-log-root",
                "sha256:identity-provider-lifecycle-audit-root",
                "--requested-at",
                "2026-07-12T02:01:00Z",
                "--completed-at",
                "2026-07-12T02:01:02Z",
                "--recorded-at",
                "2026-07-12T02:01:03Z",
                "--retention-until",
                "2033-07-12T00:00:00Z",
                "--reason-ref",
                "change:aitrade-risk/app-assignment",
                "--approval-ref",
                "approval:aitrade-risk/app-assignment",
                "--change-ticket-ref",
                "ticket:IDENTITY-1234",
                "--resulting-identity-record-hash",
                "sha256:identity-provider-lifecycle-resulting-record",
                "--evidence-ref",
                "evidence:identity-provider/lifecycle",
                "--out",
                str(paths["lifecycle"]),
            ]
            verify_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "identity-lifecycle-operation-verify",
                str(paths["lifecycle"]),
                *source_args,
            ]
            append_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "identity-lifecycle-operation-append",
                str(paths["lifecycle"]),
                *source_args,
                "--state",
                str(paths["chain"]),
                "--tenant",
                "identity-provider-lifecycle-local",
                "--out",
                str(paths["entry"]),
            ]

            for command in (build_cmd, verify_cmd, append_cmd):
                completed = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(0, completed.returncode, completed.stderr)

            receipt = json.loads(paths["lifecycle"].read_text(encoding="utf-8"))
            entry = json.loads(paths["entry"].read_text(encoding="utf-8"))
            self.assertEqual("hosted-lifecycle-worker", receipt["mode"])
            self.assertEqual(receipt["operation_id"], entry["payload"]["operation_id"])


if __name__ == "__main__":
    unittest.main()
