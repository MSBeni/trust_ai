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
from trustai.identity_provider_session import (
    IDENTITY_PROVIDER_SESSION_ENTRY_TYPE,
    IDENTITY_PROVIDER_SESSION_SCHEMA,
    append_identity_provider_session_receipt,
    build_identity_provider_session_receipt,
    verify_identity_provider_session_receipt,
)
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


class IdentityProviderSessionTests(unittest.TestCase):
    def _sources(self, tmp: Path) -> dict:
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="identity-provider-session-test")
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
        payload = json.loads(IDENTITY.read_text(encoding="utf-8"))
        attestation = build_identity_provider_attestation(
            payload,
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
        return {
            "pack": pack,
            "manifest": manifest,
            "vendor": vendor,
            "identity_payload": payload,
            "attestation": attestation,
        }

    def _receipt(self, sources: dict) -> dict:
        return build_identity_provider_session_receipt(
            sources["attestation"],
            identity_payload=sources["identity_payload"],
            vendor_identity_receipt=sources["vendor"],
            proof_packs=[sources["pack"]],
            trust_network_manifest=sources["manifest"],
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
            scope_refs=["scope:trustai/proof-pack.read", "scope:trustai/vendor.identity"],
            audience_refs=["audience:trustai-registry"],
            decision="allowed",
            risk_level="low",
            endpoint_url="https://okta.example/oauth2/v1/introspect",
            credential_ref="env:OKTA_INTROSPECTION_TOKEN",
            request_hash="sha256:identity-provider-session-request",
            response_status=200,
            response_hash="sha256:identity-provider-session-response",
            session_log_ref="okta:system-log/query/aitrade-session",
            session_log_root="sha256:identity-provider-session-log-root",
            audit_log_ref="audit-log:identity-provider/session-worker",
            audit_log_root="sha256:identity-provider-session-audit-root",
            source_ip_hash="sha256:identity-provider-session-source-ip",
            device_ref="workload:trustai/identity-session-worker",
            user_agent_hash="sha256:identity-provider-session-user-agent",
            session_started_at="2026-07-12T02:00:00Z",
            session_expires_at="2026-07-12T03:00:00Z",
            observed_at="2026-07-12T02:00:05Z",
            recorded_at="2026-07-12T02:00:06Z",
            retention_until="2033-07-12T00:00:00Z",
            evidence_refs=["evidence:identity-provider/session"],
        )

    def test_identity_provider_session_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            receipt = self._receipt(sources)
            result = verify_identity_provider_session_receipt(
                receipt,
                identity_provider_attestation=sources["attestation"],
                identity_payload=sources["identity_payload"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            chain = EvidenceChain.load(tmp / "session-chain.json", tenant_id="identity-provider-session-local")
            entry = append_identity_provider_session_receipt(
                chain,
                receipt,
                identity_provider_attestation=sources["attestation"],
                identity_payload=sources["identity_payload"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(IDENTITY_PROVIDER_SESSION_SCHEMA, receipt["schema"])
            self.assertEqual("okta-agent-aitrade-risk", receipt["session"]["identity_id"])
            self.assertEqual(IDENTITY_PROVIDER_SESSION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["session_id"], entry["payload"]["session_id"])

    def test_identity_provider_session_detects_attestation_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            tampered = copy.deepcopy(sources["attestation"])
            tampered["subject"]["identity_id"] = "okta-agent-other"

            result = verify_identity_provider_session_receipt(
                receipt,
                identity_provider_attestation=tampered,
                identity_payload=sources["identity_payload"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("source identity provider attestation invalid" in error for error in result.errors))
            self.assertTrue(any("attestation binding" in error for error in result.errors))

    def test_cli_identity_provider_session_round_trip(self):
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
                "entry": tmp / "identity-session-entry.json",
                "chain": tmp / "identity-session-chain.json",
            }
            paths["pack"].write_text(json.dumps(sources["pack"], indent=2, sort_keys=True), encoding="utf-8")
            write_trust_network_manifest(paths["manifest"], sources["manifest"])
            write_vendor_identity_receipt(paths["vendor"], sources["vendor"])
            paths["identity_payload"].write_text(json.dumps(sources["identity_payload"], indent=2, sort_keys=True), encoding="utf-8")
            write_identity_provider_attestation(paths["attestation"], sources["attestation"])

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
            ]
            build_cmd = [
                sys.executable,
                "-m",
                "trustai",
                "identity-session",
                *source_args,
                "--mode",
                "provider-event-stream",
                "--environment",
                "aitrade-prod",
                "--provider-tenant-ref",
                "okta:example-org",
                "--session-ref",
                "okta-session:aitrade-risk/2026-07-12T02:00:00Z",
                "--event-ref",
                "okta-event:evt_20260712_aitrade_token_introspection",
                "--event-kind",
                "token_introspection",
                "--provider-event-id",
                "evt_20260712_aitrade_token_introspection",
                "--actor-ref",
                "oidc:trustai.example/identity-session-worker",
                "--scope-ref",
                "scope:trustai/proof-pack.read",
                "--audience-ref",
                "audience:trustai-registry",
                "--endpoint-url",
                "https://okta.example/oauth2/v1/introspect",
                "--credential-ref",
                "env:OKTA_INTROSPECTION_TOKEN",
                "--request-hash",
                "sha256:identity-provider-session-request",
                "--response-status",
                "200",
                "--response-hash",
                "sha256:identity-provider-session-response",
                "--session-log-ref",
                "okta:system-log/query/aitrade-session",
                "--session-log-root",
                "sha256:identity-provider-session-log-root",
                "--audit-log-ref",
                "audit-log:identity-provider/session-worker",
                "--audit-log-root",
                "sha256:identity-provider-session-audit-root",
                "--source-ip-hash",
                "sha256:identity-provider-session-source-ip",
                "--device-ref",
                "workload:trustai/identity-session-worker",
                "--user-agent-hash",
                "sha256:identity-provider-session-user-agent",
                "--session-started-at",
                "2026-07-12T02:00:00Z",
                "--session-expires-at",
                "2026-07-12T03:00:00Z",
                "--observed-at",
                "2026-07-12T02:00:05Z",
                "--recorded-at",
                "2026-07-12T02:00:06Z",
                "--retention-until",
                "2033-07-12T00:00:00Z",
                "--evidence-ref",
                "evidence:identity-provider/session",
                "--out",
                str(paths["session"]),
            ]
            subprocess.run(build_cmd, cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            subprocess.run(
                [sys.executable, "-m", "trustai", "identity-session-verify", str(paths["session"]), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "identity-session-append",
                    str(paths["session"]),
                    *source_args,
                    "--state",
                    str(paths["chain"]),
                    "--tenant",
                    "identity-provider-session-test",
                    "--out",
                    str(paths["entry"]),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            receipt = json.loads(paths["session"].read_text(encoding="utf-8"))
            entry = json.loads(paths["entry"].read_text(encoding="utf-8"))
            self.assertEqual(IDENTITY_PROVIDER_SESSION_SCHEMA, receipt["schema"])
            self.assertEqual(IDENTITY_PROVIDER_SESSION_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["session_id"], entry["payload"]["session_id"])


if __name__ == "__main__":
    unittest.main()
