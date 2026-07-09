import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.actuarial import build_actuarial_corpus, build_actuarial_product, write_actuarial_corpus, write_actuarial_product
from trustai.chain import EvidenceChain
from trustai.consent import INSURER_SCOPE, append_consent_grant, consent_status, load_consent
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.insurer import build_insurer_telemetry, write_insurer_telemetry
from trustai.insurer_partner_service import (
    INSURER_PARTNER_SERVICE_ENTRY_TYPE,
    INSURER_PARTNER_SERVICE_SCHEMA,
    append_insurer_partner_service_attestation,
    build_insurer_partner_service_attestation,
    verify_insurer_partner_service_attestation,
    write_insurer_partner_service_attestation,
)
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.underwriting_quote import build_underwriting_quote, write_underwriting_quote


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
CONSENT = ROOT / "examples" / "aitrade" / "insurer-consent.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class InsurerPartnerServiceTests(unittest.TestCase):
    def _fixtures(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="insurer-partner-service-test")
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
        consent = load_consent(CONSENT)
        append_consent_grant(chain, consent)
        active = consent_status(
            chain,
            consent["consent_id"],
            INSURER_SCOPE,
            pack_id=pack["pack_id"],
            contract_id=pack["gate_decision"]["contract_id"],
            now="2026-07-08T00:00:00Z",
        )
        telemetry = build_insurer_telemetry(pack, consent_id=consent["consent_id"], consent=active)
        quote = build_underwriting_quote(
            telemetry,
            underwriter="Example AI Liability Underwriter",
            coverage_limit_usd=1_000_000,
            base_premium_usd=25_000,
            term_start="2026-07-08T00:00:00Z",
            term_end="2027-07-08T00:00:00Z",
            issued_at="2026-07-08T00:00:00Z",
            expires_at="2026-08-08T00:00:00Z",
        )
        corpus = build_actuarial_corpus(
            chain,
            [pack],
            consent_id=consent["consent_id"],
            require_consent=True,
            now="2026-07-08T00:00:00Z",
        )
        product = build_actuarial_product(
            [corpus],
            product_name="TrustAI reliability benchmark",
            publisher="trustai-local",
            issued_at="2026-07-08T01:00:00Z",
        )
        return chain, telemetry, quote, corpus, product

    def _attestation(self, telemetry, quote, corpus, product, **overrides):
        values = {
            "telemetry": telemetry,
            "underwriting_quote": quote,
            "actuarial_product": product,
            "actuarial_corpora": [corpus],
            "environment": "aitrade-prod",
            "service_kind": "underwriting-integration",
            "service_ref": "insurer-partner:trustai/underwriting-prod",
            "service_version": "0.1.0",
            "endpoint_url": "https://insurer.example/trustai/aitrade",
            "partner_api_endpoint": "https://underwriter.example/api/v1/quotes",
            "service_image": "ghcr.io/trustai/insurer-partner:0.1.0",
            "service_image_digest": "sha256:trustai-insurer-partner-image",
            "service_binary_hash": "sha256:trustai-insurer-partner-binary",
            "frontend_bundle_ref": "bundle:insurer-partner/underwriter-ui",
            "frontend_bundle_hash": "sha256:trustai-insurer-partner-frontend",
            "api_ref": "api:insurer-partner/v0",
            "queue_ref": "queue:insurer-partner/delivery",
            "policy_system_ref": "policy-system:underwriter/bindings",
            "partner_contract_ref": "partner-contract:underwriter/trustai-2026",
            "auth_provider_ref": "oidc:insurer-partner/idp",
            "partner_auth_policy_ref": "policy:insurer-partner/partner-auth-v0.1",
            "rbac_policy_ref": "policy:insurer-partner/rbac-v0.1",
            "consent_policy_ref": "policy:insurer-partner/consent-v0.1",
            "data_minimization_policy_ref": "policy:insurer-partner/data-minimization-v0.1",
            "pii_redaction_policy_ref": "policy:insurer-partner/pii-redaction-v0.1",
            "tenant_isolation_ref": "tenant-isolation:insurer-partner/aitrade",
            "rate_limit_policy_ref": "rate-limit:insurer-partner/underwriter",
            "request_signing_ref": "sigv4:insurer-partner/underwriter",
            "network_policy_ref": "netpol:insurer-partner/deny-by-default",
            "egress_policy_ref": "egress:insurer-partner/underwriter-only",
            "encryption_key_ref": "kms:insurer-partner/customer-data",
            "replicas_min": 3,
            "replicas_max": 9,
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "audit_log_ref": "audit-log:insurer-partner/service",
            "audit_log_root": "sha256:insurer-partner-audit-root",
            "access_log_ref": "access-log:insurer-partner/sessions",
            "access_log_root": "sha256:insurer-partner-access-root",
            "delivery_log_ref": "delivery-log:insurer-partner/underwriter",
            "delivery_log_root": "sha256:insurer-partner-delivery-root",
            "metrics_ref": "metrics:insurer-partner/service",
            "alert_policy_ref": "alert:insurer-partner/service",
            "retention_until": "2033-07-08T00:00:00Z",
            "actor_ref": "oidc:trustai.example/insurer-partner-operator",
            "credential_ref": "env:INSURER_PARTNER_TOKEN",
            "partner_credential_ref": "env:UNDERWRITER_API_TOKEN",
            "evidence_refs": ["evidence:insurer-partner/service"],
            "attested_at": "2026-07-08T06:00:00Z",
            "now": "2026-07-09T00:00:00Z",
        }
        values.update(overrides)
        return build_insurer_partner_service_attestation(**values)

    def test_insurer_partner_service_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, telemetry, quote, corpus, product = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(telemetry, quote, corpus, product)

            result = verify_insurer_partner_service_attestation(
                attestation,
                telemetry,
                quote,
                actuarial_product=product,
                actuarial_corpora=[corpus],
                now="2026-07-09T00:00:00Z",
            )
            entry = append_insurer_partner_service_attestation(
                chain,
                attestation,
                telemetry,
                quote,
                actuarial_product=product,
                actuarial_corpora=[corpus],
                now="2026-07-09T00:00:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(INSURER_PARTNER_SERVICE_SCHEMA, attestation["schema"])
            self.assertEqual("partner-service-attested", attestation["mode"])
            self.assertEqual(quote["quote_id"], attestation["partner"]["quote_id"])
            self.assertEqual(telemetry["consent"]["consent_id"], attestation["risk_transfer"]["consent_id"])
            self.assertEqual("env:UNDERWRITER_API_TOKEN", attestation["operation_actor"]["partner_credential"]["ref"])
            self.assertEqual(INSURER_PARTNER_SERVICE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(attestation["attestation_id"], entry["payload"]["attestation_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_insurer_partner_service_rejects_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, telemetry, quote, corpus, product = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(telemetry, quote, corpus, product)
            tampered = copy.deepcopy(telemetry)
            tampered["risk_score"] = 1

            result = verify_insurer_partner_service_attestation(
                attestation,
                tampered,
                quote,
                actuarial_product=product,
                actuarial_corpora=[corpus],
                now="2026-07-09T00:00:00Z",
            )

            self.assertFalse(result.ok)
            self.assertIn("insurer partner service source_artifacts do not match supplied source artifacts", result.errors)
            self.assertIn("underwriting quote source: risk evidence telemetry_hash mismatch", result.errors)

    def test_insurer_partner_service_rejects_insecure_partner_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, telemetry, quote, corpus, product = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(telemetry, quote, corpus, product, partner_api_endpoint="http://underwriter.example/api/v1/quotes")

            result = verify_insurer_partner_service_attestation(attestation, telemetry, quote, actuarial_product=product, actuarial_corpora=[corpus], now="2026-07-09T00:00:00Z")

            self.assertFalse(result.ok)
            self.assertIn("insurer partner service service.partner_api_endpoint must use HTTPS", result.errors)

    def test_insurer_partner_service_rejects_weak_replicas(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, telemetry, quote, corpus, product = self._fixtures(Path(tmp_dir))
            attestation = self._attestation(telemetry, quote, corpus, product, replicas_min=1, availability_zones=["us-east-1a"])

            result = verify_insurer_partner_service_attestation(attestation, telemetry, quote, actuarial_product=product, actuarial_corpora=[corpus], now="2026-07-09T00:00:00Z")

            self.assertFalse(result.ok)
            self.assertIn("insurer partner service service.replicas_min must be an integer >= 2", result.errors)
            self.assertIn("insurer partner service service.availability_zones must include at least two zones", result.errors)

    def test_cli_insurer_partner_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, telemetry, quote, corpus, product = self._fixtures(tmp)
            telemetry_path = tmp / "insurer-risk-telemetry.json"
            quote_path = tmp / "underwriting-quote.json"
            corpus_path = tmp / "actuarial-corpus.json"
            product_path = tmp / "actuarial-product.json"
            attestation_path = tmp / "insurer-partner-service-attestation.json"
            entry_path = tmp / "insurer-partner-service-entry.json"
            state_path = tmp / "insurer-partner-service-chain.json"
            write_insurer_telemetry(telemetry_path, telemetry)
            write_underwriting_quote(quote_path, quote)
            write_actuarial_corpus(corpus_path, corpus)
            write_actuarial_product(product_path, product)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(telemetry_path),
                str(quote_path),
                "--actuarial-product",
                str(product_path),
                "--actuarial-corpus",
                str(corpus_path),
                "--now",
                "2026-07-09T00:00:00Z",
            ]
            service_args = [
                "--environment", "aitrade-prod",
                "--service-kind", "underwriting-integration",
                "--service-ref", "insurer-partner:trustai/underwriting-prod",
                "--service-version", "0.1.0",
                "--endpoint-url", "https://insurer.example/trustai/aitrade",
                "--partner-api-endpoint", "https://underwriter.example/api/v1/quotes",
                "--service-image", "ghcr.io/trustai/insurer-partner:0.1.0",
                "--service-image-digest", "sha256:trustai-insurer-partner-image",
                "--service-binary-hash", "sha256:trustai-insurer-partner-binary",
                "--frontend-bundle-ref", "bundle:insurer-partner/underwriter-ui",
                "--frontend-bundle-hash", "sha256:trustai-insurer-partner-frontend",
                "--api-ref", "api:insurer-partner/v0",
                "--queue-ref", "queue:insurer-partner/delivery",
                "--policy-system-ref", "policy-system:underwriter/bindings",
                "--partner-contract-ref", "partner-contract:underwriter/trustai-2026",
                "--auth-provider-ref", "oidc:insurer-partner/idp",
                "--partner-auth-policy-ref", "policy:insurer-partner/partner-auth-v0.1",
                "--rbac-policy-ref", "policy:insurer-partner/rbac-v0.1",
                "--consent-policy-ref", "policy:insurer-partner/consent-v0.1",
                "--data-minimization-policy-ref", "policy:insurer-partner/data-minimization-v0.1",
                "--pii-redaction-policy-ref", "policy:insurer-partner/pii-redaction-v0.1",
                "--tenant-isolation-ref", "tenant-isolation:insurer-partner/aitrade",
                "--rate-limit-policy-ref", "rate-limit:insurer-partner/underwriter",
                "--request-signing-ref", "sigv4:insurer-partner/underwriter",
                "--network-policy-ref", "netpol:insurer-partner/deny-by-default",
                "--egress-policy-ref", "egress:insurer-partner/underwriter-only",
                "--encryption-key-ref", "kms:insurer-partner/customer-data",
                "--replicas-min", "3",
                "--replicas-max", "9",
                "--availability-zone", "us-east-1a",
                "--availability-zone", "us-east-1b",
                "--audit-log-ref", "audit-log:insurer-partner/service",
                "--audit-log-root", "sha256:insurer-partner-audit-root",
                "--access-log-ref", "access-log:insurer-partner/sessions",
                "--access-log-root", "sha256:insurer-partner-access-root",
                "--delivery-log-ref", "delivery-log:insurer-partner/underwriter",
                "--delivery-log-root", "sha256:insurer-partner-delivery-root",
                "--metrics-ref", "metrics:insurer-partner/service",
                "--alert-policy-ref", "alert:insurer-partner/service",
                "--retention-until", "2033-07-08T00:00:00Z",
                "--actor-ref", "oidc:trustai.example/insurer-partner-operator",
                "--credential-ref", "env:INSURER_PARTNER_TOKEN",
                "--partner-credential-ref", "env:UNDERWRITER_API_TOKEN",
                "--evidence-ref", "evidence:insurer-partner/service",
                "--attested-at", "2026-07-08T06:00:00Z",
            ]
            subprocess.run(
                [sys.executable, "-m", "trustai", "insurer-partner-service-attestation", *source_args, *service_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "insurer-partner-service-verify", str(attestation_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "insurer-partner-service-append",
                    str(attestation_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "insurer-partner-service-local",
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
