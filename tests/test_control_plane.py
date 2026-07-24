import json
import tempfile
import unittest
from pathlib import Path

from tests import test_identity_provider_authority as identity_authority_fixtures
from tests import test_insurer_partner_authority as insurer_authority_fixtures
from tests import test_review_portal_service as service_fixtures
from tests import test_standards_body_status as standards_status_fixtures
from tests import test_trust_authority_kms_enforcement as trust_authority_kms_fixtures
from tests import test_trust_authority_provider as trust_authority_provider_fixtures
from tests import test_auditor_program_governance as auditor_governance_fixtures
from trustai.actuarial import ACTUARIAL_PRODUCT_ENTRY_TYPE
from trustai.auditor_accreditation import append_auditor_accreditation_receipt, build_auditor_accreditation_receipt
from trustai.auditor_program_governance import append_auditor_program_governance_receipt, build_auditor_program_governance_receipt
from trustai.anchor_provider import append_anchor_provider_receipt, build_anchor_provider_receipt
from trustai.approvals import append_approval, load_approval
from trustai.byoc_authority import append_byoc_authority_dossier, build_byoc_authority_dossier
from trustai.byoc_operator import append_byoc_operator_attestation, build_byoc_operator_attestation
from trustai.control_plane import ControlPlane, _sqlite_nolock_uri
from trustai.canonical import content_hash
from trustai.chain import EvidenceChain
from trustai.compliance_authority import COMPLIANCE_AUTHORITY_ENTRY_TYPE
from trustai.consent import CONSENT_GRANTED_ENTRY_TYPE, CONSENT_REVOKED_ENTRY_TYPE
from trustai.cicd import append_promotion_status_receipt, build_promotion_check_payload, build_promotion_status_receipt
from trustai.delivery import PROVIDER_DELIVERY_ENTRY_TYPE, build_provider_delivery
from trustai.design_partner import append_design_partner_dossier, build_design_partner_dossier
from trustai.deployment import build_deployment_manifest
from trustai.contracts import load_contract, register_contract
from trustai.external_evidence import (
    EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE,
    append_external_evidence_manifest,
    build_external_evidence_manifest,
)
from trustai.eu_ai_act import build_eu_ai_act_document
from trustai.eu_data_plane import EU_DATA_PLANE_ENTRY_TYPE
from trustai.framework_adapter_authority import (
    append_framework_adapter_authority_dossier,
    build_framework_adapter_authority_dossier,
)
from trustai.framework_adapter_matrix import append_framework_adapter_matrix, build_framework_adapter_matrix, load_framework_adapter_matrix_source
from trustai.framework_hook_operation import append_framework_hook_operation, build_framework_hook_operation, load_framework_trace_payload
from trustai.framework_hook_release import append_framework_hook_release, build_framework_hook_release, load_framework_hook_release_source
from trustai.gate import append_eval_and_gate
from trustai.ingest import append_events, load_events
from trustai.identity_provider_attestation import append_identity_provider_attestation
from trustai.identity_provider_authority import append_identity_provider_authority_dossier
from trustai.identity_provider_lifecycle_operation import append_identity_provider_lifecycle_operation_receipt
from trustai.identity_provider_lifecycle_worker import append_identity_provider_lifecycle_worker_receipt
from trustai.identity_provider_session import append_identity_provider_session_receipt
from trustai.insurer_partner_authority import INSURER_PARTNER_AUTHORITY_ENTRY_TYPE, append_insurer_partner_authority_dossier
from trustai.insurer_partner_service import INSURER_PARTNER_SERVICE_ENTRY_TYPE
from trustai.insurer_partner_worker import INSURER_PARTNER_WORKER_ENTRY_TYPE
from trustai.insurer_partner_worker_bundle import INSURER_PARTNER_WORKER_BUNDLE_ENTRY_TYPE
from trustai.mcp_gateway import (
    append_mcp_proxy_capture,
    append_mcp_transcript,
    build_mcp_proxy_capture,
    load_mcp_proxy_events,
    load_mcp_transcript,
)
from trustai.onboarding import SELF_SERVE_ONBOARDING_ENTRY_TYPE
from trustai.mcp_gateway_authority import (
    append_mcp_gateway_authority_dossier,
    append_mcp_gateway_authority_evidence_bundle,
    build_mcp_gateway_authority_dossier,
    build_mcp_gateway_authority_evidence_bundle,
)
from trustai.marketplace import MARKETPLACE_DISTRIBUTION_ENTRY_TYPE
from trustai.marketplace_author import MARKETPLACE_AUTHOR_ENTRY_TYPE
from trustai.marketplace_settlement import MARKETPLACE_SETTLEMENT_ENTRY_TYPE
from trustai.phase_scoreboard import append_phase_scoreboard, build_phase_scoreboard
from trustai.procurement_clause import PROCUREMENT_CLAUSE_ENTRY_TYPE
from trustai.procurement_integration import PROCUREMENT_INTEGRATION_ENTRY_TYPE
from trustai.product_scope import append_product_scope_decision, build_product_scope_decision
from trustai.provider_approval_authority import PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE
from trustai.provider_audit import PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE
from trustai.provider_audit_stream import PROVIDER_AUDIT_STREAM_ENTRY_TYPE
from trustai.provider_audit_worker import PROVIDER_AUDIT_WORKER_ENTRY_TYPE
from trustai.provider_callback_storage import PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE
from trustai.provider_callback_store import PROVIDER_CALLBACK_STORE_ENTRY_TYPE
from trustai.provider_credential_custody import PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE
from trustai.provider_delivery_authority import PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE
from trustai.provider_delivery_service import PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE
from trustai.provider_delivery_worker import PROVIDER_DELIVERY_WORKER_ENTRY_TYPE
from trustai.provider_delivery_worker_bundle import PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE
from trustai.provider_ingress import PROVIDER_INGRESS_ENTRY_TYPE
from trustai.provider_installation import PROVIDER_INSTALLATION_ENTRY_TYPE
from trustai.provider_lifecycle import PROVIDER_LIFECYCLE_ENTRY_TYPE
from trustai.provider_lifecycle_operation import PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE
from trustai.provider_operations_authority import PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE
from trustai.provider_operations_service import PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE
from trustai.provider_webhook import PROVIDER_WEBHOOK_ENTRY_TYPE
from trustai.policy_backend_authority import (
    POLICY_BACKEND_AUTHORITY_ENTRY_TYPE,
    POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
)
from trustai.policy_backend_enforcement import POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE
from trustai.policy_backend_provider import POLICY_BACKEND_PROVIDER_ENTRY_TYPE
from trustai.policy_backend_provider_bundle import POLICY_BACKEND_PROVIDER_BUNDLE_ENTRY_TYPE
from trustai.policy_backend_service import POLICY_BACKEND_SERVICE_ENTRY_TYPE
from trustai.policy_backend_service_bundle import POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE
from trustai.policy_backend_worker import POLICY_BACKEND_WORKER_ENTRY_TYPE
from trustai.lifecycle import (
    append_demotion,
    append_incident,
    append_rollback,
    append_soak_demotion_receipt,
    append_soak_failure_demotion,
    build_soak_demotion_receipt,
    load_incident,
)
from trustai.object_store import WORMStore
from trustai.own_compliance import append_own_compliance_dossier, build_own_compliance_dossier
from trustai.reliability_report import append_reliability_report, build_reliability_report
from trustai.regulator_acceptance import append_regulator_acceptance, build_regulator_acceptance
from trustai.review_portal_authority import (
    REVIEW_PORTAL_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
    append_review_portal_authority_dossier,
    append_review_portal_authority_evidence_bundle,
    build_review_portal_authority_dossier,
    build_review_portal_authority_evidence_bundle,
)
from trustai.review_portal_service import append_review_portal_service_attestation
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.policy_engine import append_policy_engine_receipt, build_policy_engine_receipt
from trustai.policy_export import export_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.registry import (
    append_delegation,
    append_delegation_graph,
    append_inventory,
    build_delegation_graph,
    load_delegation,
    load_inventory,
)
from trustai.roadmap_audit import append_roadmap_audit, build_roadmap_audit
from trustai.anchor import append_anchor
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import (
    append_shadow_replay,
    append_soak_report,
    append_temporal_holdout_manifest,
    append_traffic_completeness_receipt,
    append_traffic_holdout_export,
    build_traffic_completeness_receipt,
    build_traffic_holdout_export,
    load_shadow_replay,
    load_soak_window,
    load_traffic_completeness_provider_export,
)
from trustai.shadow_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENTS as SHADOW_AUTHORITY_REQUIREMENTS,
    append_shadow_authority_dossier,
    build_shadow_authority_dossier,
)
from trustai.standards_body_status import append_standards_body_status_receipt, build_standards_body_status_receipt
from trustai.standards_body_submission import append_standards_body_submission_receipt
from trustai.trust_authority import append_trust_authority_receipt
from trustai.trust_authority_kms_enforcement import append_trust_authority_kms_enforcement_receipt
from trustai.trust_authority_provider import append_trust_authority_provider_attestation
from trustai.trust_network_authority import TRUST_NETWORK_AUTHORITY_ENTRY_TYPE
from trustai.trust_network_registry import TRUST_NETWORK_REGISTRY_ENTRY_TYPE
from trustai.trust_network_registry_status import TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE
from trustai.trust_network_service import TRUST_NETWORK_SERVICE_ENTRY_TYPE
from trustai.trust_network_worker import TRUST_NETWORK_WORKER_ENTRY_TYPE
from trustai.trust_network_worker_bundle import TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE
from trustai.supervised_access import append_supervised_access_receipt
from trustai.underwriting_quote import UNDERWRITING_QUOTE_ENTRY_TYPE, append_underwriting_quote
from trustai.vendor_identity import append_vendor_identity_receipt
from trustai.vertical_pack import append_vertical_pack, build_vertical_pack
from trustai.verifier import verify_proof_pack



def _complete_shadow_authority_evidence() -> list[dict]:
    rows = []
    for requirement in SHADOW_AUTHORITY_REQUIREMENTS:
        requirement_id = requirement["id"]
        authority_kind = requirement["authority_kinds"][0]
        rows.append(
            {
                "requirement_id": requirement_id,
                "authority_kind": authority_kind,
                "evidence_ref": f"authority:shadow-control/{requirement_id}",
                "evidence_hash": "sha256:" + content_hash({"shadow_control_authority": requirement_id, "authority_kind": authority_kind}),
                "description": f"Control-plane shadow authority evidence for {requirement_id}",
                "issuer": "TrustAI authority exporter",
                "subject": f"aitrade shadow holdout {requirement_id}",
                "source_uri": f"https://authority.trustai.ai/shadow-control/{requirement_id}",
                "issued_at": "2026-07-12T00:00:00Z",
                "expires_at": "2026-08-12T00:00:00Z",
            }
        )
    return rows

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"
DELEGATION = ROOT / "examples" / "aitrade" / "delegation.json"
EVENTS = ROOT / "examples" / "aitrade" / "otel-events.json"
MCP = ROOT / "examples" / "aitrade" / "mcp-transcript.json"
MCP_PROXY = ROOT / "examples" / "aitrade" / "mcp-proxy-events.json"
FRAMEWORK_MATRIX = ROOT / "examples" / "aitrade" / "framework-adapter-matrix.json"
FRAMEWORK_HOOK_RELEASE = ROOT / "examples" / "aitrade" / "framework-hook-release.json"
FRAMEWORK_TRACES = ROOT / "examples" / "aitrade" / "framework-traces.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
FAILED_SOAK = ROOT / "examples" / "aitrade" / "failed-soak-window.json"
APPROVAL_MODEL_RISK = ROOT / "examples" / "aitrade" / "approval-model-risk.json"
APPROVAL_TRADING_OPS = ROOT / "examples" / "aitrade" / "approval-trading-ops.json"
TRAFFIC_COMPLETENESS_PROVIDER_EXPORT = ROOT / "examples" / "aitrade" / "traffic-completeness-provider-export.json"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class ControlPlaneTests(unittest.TestCase):
    def test_sqlite_nolock_uri_preserves_unc_path(self):
        uri = _sqlite_nolock_uri(Path("//wsl.localhost/Ubuntu/home/app/control.sqlite"))
        self.assertEqual("file:////wsl.localhost/Ubuntu/home/app/control.sqlite?nolock=1", uri)

    def test_exposes_insurer_partner_evidence_surface(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="insurer-partner-control")
            consent_id = "consent-pack-risk-telemetry"
            chain.append(
                CONSENT_GRANTED_ENTRY_TYPE,
                {
                    "consent_id": consent_id,
                    "consent_hash": content_hash({"consent_id": consent_id, "scope": "proof-pack-risk-telemetry"}),
                    "scope": "proof-pack-risk-telemetry",
                    "granted_to": "underwriter:example",
                    "granted_at": "2026-07-04T01:00:00Z",
                },
                timestamp="2026-07-04T01:00:00Z",
            )
            chain.append(
                UNDERWRITING_QUOTE_ENTRY_TYPE,
                {
                    "quote_id": "quote-aitrade-1",
                    "quote_hash": "sha256:quote-aitrade-1",
                    "underwriter": {"name": "Example Underwriter", "mode": "partner-api"},
                    "applicant_risk": {
                        "pack_id": "pack-aitrade-1",
                        "contract_id": "contract-aitrade-1",
                        "risk_score": 0.12,
                        "risk_tier": "low",
                        "gate_outcome": "passed",
                    },
                    "quote": {
                        "product": "ai-liability",
                        "quote_ref": "quote:example/aitrade-1",
                        "status": "quoted",
                        "currency": "USD",
                        "coverage_limit_usd": 1000000,
                        "base_premium_usd": 25000,
                        "discount_percent": 12.5,
                        "quoted_premium_usd": 21875,
                        "term_start": "2026-08-01",
                        "term_end": "2027-08-01",
                    },
                    "risk_evidence": {
                        "consent_id": consent_id,
                        "consent_active": True,
                        "pack_id": "pack-aitrade-1",
                        "contract_id": "contract-aitrade-1",
                        "chain_root": "sha256:aitrade-chain-root",
                        "telemetry_hash": "sha256:insurer-telemetry",
                    },
                    "limitations": [],
                },
                timestamp="2026-07-04T01:05:00Z",
            )
            chain.append(
                INSURER_PARTNER_SERVICE_ENTRY_TYPE,
                {
                    "attestation_id": "service-attestation-1",
                    "attestation_hash": "sha256:service-attestation-1",
                    "mode": "partner-service-attested",
                    "environment": "aitrade-prod",
                    "attested_at": "2026-07-04T01:10:00Z",
                    "service": {
                        "service_ref": "insurer-partner:trustai/underwriting",
                        "kind": "underwriting-integration",
                        "partner_api_endpoint": "https://underwriter.example/api/v1/quotes",
                    },
                    "partner": {
                        "underwriter": "Example Underwriter",
                        "partner_api_endpoint": "https://underwriter.example/api/v1/quotes",
                    },
                    "risk_transfer": {"telemetry_hash": "sha256:insurer-telemetry", "risk_tier": "low"},
                    "source_artifacts": [{"type": "underwriting-quote", "id": "quote-aitrade-1"}],
                    "controls": [{"name": "partner_auth", "passed": True}],
                },
                timestamp="2026-07-04T01:10:00Z",
            )
            chain.append(
                INSURER_PARTNER_WORKER_ENTRY_TYPE,
                {
                    "worker_operation_id": "worker-run-1",
                    "worker_operation_hash": "sha256:worker-run-1",
                    "mode": "hosted-worker",
                    "environment": "aitrade-prod",
                    "recorded_at": "2026-07-04T01:15:00Z",
                    "service": {"service_ref": "insurer-partner:trustai/underwriting"},
                    "worker": {"worker_ref": "worker:insurer-delivery", "success": True},
                    "delivery": {"destination_ref": "underwriter:example/quotes", "response_status": 202},
                    "policy_system": {"workflow_status": "accepted"},
                    "source_artifacts": [{"type": "service-attestation", "id": "service-attestation-1"}],
                    "controls": [{"name": "delivery_log_bound", "passed": True}],
                },
                timestamp="2026-07-04T01:15:00Z",
            )
            chain.append(
                INSURER_PARTNER_WORKER_BUNDLE_ENTRY_TYPE,
                {
                    "bundle_id": "worker-bundle-1",
                    "bundle_hash": "sha256:worker-bundle-1",
                    "mode": "underwriter-review",
                    "environment": "aitrade-prod",
                    "bundle_ref": "bundle:insurer/worker-run-1",
                    "reviewer_ref": "underwriter:example/reviewer",
                    "generated_at": "2026-07-04T01:20:00Z",
                    "source_artifacts": [{"type": "worker-receipt", "id": "worker-run-1"}],
                    "summary": {"status": "ready", "worker_receipt_count": 1},
                    "controls": [{"name": "offline_replay", "passed": True}],
                },
                timestamp="2026-07-04T01:20:00Z",
            )
            chain.append(
                ACTUARIAL_PRODUCT_ENTRY_TYPE,
                {
                    "product_id": "actuarial-product-1",
                    "product_hash": "sha256:actuarial-product-1",
                    "issued_at": "2026-07-04T01:25:00Z",
                    "product": {"name": "TrustAI low-risk agent benchmark"},
                    "source_corpora": [],
                    "aggregate": {},
                },
                timestamp="2026-07-04T01:25:00Z",
            )
            chain.append(
                INSURER_PARTNER_AUTHORITY_ENTRY_TYPE,
                {
                    "dossier_id": "insurer-authority-1",
                    "dossier_hash": "sha256:insurer-authority-1",
                    "mode": "production-dossier",
                    "environment": "aitrade-prod",
                    "dossier_ref": "dossier:insurer/aitrade-1",
                    "authority_ref": "authority:insurer-partner/example",
                    "producer_ref": "trustai:control-plane",
                    "service_attestation_binding": {
                        "attestation_id": "service-attestation-1",
                        "attestation_hash": "sha256:service-attestation-1",
                        "service_ref": "insurer-partner:trustai/underwriting",
                        "partner_api_endpoint": "https://underwriter.example/api/v1/quotes",
                        "underwriter": "Example Underwriter",
                        "quote_id": "quote-aitrade-1",
                        "quote_ref": "quote:example/aitrade-1",
                        "telemetry_hash": "sha256:insurer-telemetry",
                        "consent_id": consent_id,
                        "risk_tier": "low",
                    },
                    "worker_receipt_bindings": [{"worker_operation_id": "worker-run-1"}],
                    "worker_bundle_bindings": [{"bundle_id": "worker-bundle-1", "bundle_ref": "bundle:insurer/worker-run-1"}],
                    "summary": {
                        "required_requirement_count": 3,
                        "covered_requirement_count": 3,
                        "missing_requirement_count": 0,
                        "evidence_count": 0,
                        "status": "ready",
                    },
                    "control_summary": {"passed": 3, "failed": 0},
                    "authority_evidence": [],
                    "generated_at": "2026-07-04T01:30:00Z",
                },
                timestamp="2026-07-04T01:30:00Z",
            )
            chain.append(
                CONSENT_REVOKED_ENTRY_TYPE,
                {"consent_id": consent_id, "reason": "customer-request", "revoked_at": "2026-07-04T02:00:00Z"},
                timestamp="2026-07-04T02:00:00Z",
            )
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                evidence = control.insurer_evidence()
                partner_evidence = evidence["insurer_partner_evidence"]
                kinds = {item["artifact_kind"] for item in partner_evidence}

                self.assertEqual(8, indexed["insurer_partner_evidence"])
                self.assertEqual(1, len(evidence["underwriting_quotes"]))
                self.assertEqual(1, len(evidence["insurer_partner_authority_dossiers"]))
                self.assertEqual(
                    {
                        "insurer-consent-grant",
                        "underwriting-quote",
                        "insurer-partner-service",
                        "insurer-partner-worker",
                        "insurer-partner-worker-bundle",
                        "actuarial-product",
                        "insurer-partner-authority",
                        "insurer-consent-revocation",
                    },
                    kinds,
                )
                service = next(item for item in partner_evidence if item["artifact_kind"] == "insurer-partner-service")
                self.assertEqual("insurer-partner:trustai/underwriting", service["service_ref"])
                self.assertEqual("https://underwriter.example/api/v1/quotes", service["partner_api_endpoint"])
                worker = next(item for item in partner_evidence if item["artifact_kind"] == "insurer-partner-worker")
                self.assertTrue(worker["success"])
                self.assertEqual(202, worker["response_status"])
                consent_items = [item for item in partner_evidence if item["artifact_kind"].startswith("insurer-consent-")]
                self.assertEqual(2, len(consent_items))
                self.assertIn("insurer_partner_evidence", control.roadmap_evidence()["insurer_evidence"])
            finally:
                control.close()

    def test_exposes_evidence_chain_trust_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="evidence-chain-trust-control")
            anchor_entry = append_anchor(chain)
            anchor_provider = build_anchor_provider_receipt(
                anchor_entry,
                source_chain=chain,
                mode="provider-anchored",
                environment="aitrade-prod",
                provider="Example Transparency Log",
                endpoint="https://transparency.example/anchor",
                publication_ref="transparency-log:trustai/anchor/2026-07-04",
                request_hash="sha256:anchor-provider-request",
                response_status=200,
                response_hash="sha256:anchor-provider-response",
                public_log_ref="public-log:trustai-example",
                public_log_root="sha256:anchor-provider-public-log-root",
                public_log_size=42,
                public_log_entry_ref="public-log-entry:trustai-example/42",
                inclusion_proof_hash="sha256:anchor-provider-inclusion-proof",
                consistency_proof_hash="sha256:anchor-provider-consistency-proof",
                witness_refs=["witness:example/auditor"],
                actor_ref="oidc:trustai.example/anchor-publisher",
                credential_ref="env:ANCHOR_PROVIDER_TOKEN",
                audit_log_ref="audit-log:anchor-provider/example",
                audit_log_root="sha256:anchor-provider-audit-root",
                retention_until="2033-07-04T00:00:00Z",
                evidence_refs=["evidence:anchor/provider"],
                published_at="2026-07-04T03:03:00Z",
            )
            append_anchor_provider_receipt(chain, anchor_provider, anchor_entry, source_chain=chain)

            provider_fixture = trust_authority_provider_fixtures.TrustAuthorityProviderTests()
            source_chain, keyring, pack, trust_authority = provider_fixture._sources(tmp)
            trust_entry = append_trust_authority_receipt(chain, trust_authority, source_chain=source_chain, keyring=keyring, proof_pack=pack)
            provider = provider_fixture._attestation(source_chain, keyring, pack, trust_authority)
            provider_entry = append_trust_authority_provider_attestation(
                chain,
                provider,
                trust_authority,
                source_chain,
                keyring,
                proof_pack=pack,
            )
            kms_fixture = trust_authority_kms_fixtures.TrustAuthorityKmsEnforcementTests()
            kms_enforcement = kms_fixture._receipt(source_chain, keyring, pack, trust_authority, provider)
            kms_entry = append_trust_authority_kms_enforcement_receipt(
                chain,
                kms_enforcement,
                provider_attestation=provider,
                trust_authority_receipt=trust_authority,
                source_chain=source_chain,
                keyring=keyring,
                proof_pack=pack,
            )
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                evidence = control.evidence_chain_trust_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(1, indexed["anchors"])
                self.assertEqual(1, len(evidence["anchor_publications"]))
                self.assertEqual(anchor_entry["entry_id"], evidence["anchor_publications"][0]["entry_id"])
                self.assertEqual("chain-anchor-publication", evidence["anchor_publications"][0]["artifact_kind"])

                trust_receipts = evidence["trust_receipts"]
                self.assertEqual(4, len(trust_receipts))
                self.assertEqual(
                    {
                        "anchor-provider-receipt",
                        "trust-authority-receipt",
                        "trust-authority-provider-attestation",
                        "trust-authority-kms-enforcement",
                    },
                    {item["artifact_kind"] for item in trust_receipts},
                )
                self.assertIn(trust_entry["entry_id"], {item["entry_id"] for item in trust_receipts})
                self.assertIn(provider_entry["payload"]["attestation_id"], {item["artifact_id"] for item in trust_receipts})
                self.assertIn(kms_entry["payload"]["enforcement_id"], {item["artifact_id"] for item in trust_receipts})
                self.assertEqual(evidence, roadmap["evidence_chain_trust_evidence"])
            finally:
                control.close()

    def test_indexes_self_serve_onboarding_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            payload = {
                "receipt_id": "onboarding-receipt-001",
                "receipt_hash": "sha256:onboarding-receipt-hash",
                "onboarding_ref": "onboarding:self-serve/aitrade",
                "tenant_ref": "tenant:aitrade-local",
                "agent_ref": "agent:aitrade-risk",
                "requester_ref": "mailto:engineer@example.com",
                "environment": "local",
                "sdk_scope": "python-typescript",
                "gateway_mode": "sdk-gateway",
                "source_artifact_count": 22,
                "quickstart_step_count": 8,
                "quickstart_replay_count": 8,
                "control_summary": {"passed": 8},
            }
            entry = chain.append(SELF_SERVE_ONBOARDING_ENTRY_TYPE, payload, timestamp="2026-07-13T00:00:00Z")
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.onboarding_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(1, indexed["self_serve_onboarding_receipts"])
                self.assertEqual(1, summary["counts"]["self_serve_onboarding_receipts"])
                self.assertEqual("onboarding-receipt-001", summary["latest_self_serve_onboarding_receipt"]["receipt_id"])
                self.assertEqual({"passed": 8}, summary["latest_self_serve_onboarding_receipt"]["control_summary"])

                receipts = evidence["self_serve_onboarding_receipts"]
                self.assertEqual(1, len(receipts))
                self.assertEqual(entry["entry_id"], receipts[0]["entry_id"])
                self.assertEqual("tenant:aitrade-local", receipts[0]["tenant_ref"])
                self.assertEqual("agent:aitrade-risk", receipts[0]["agent_ref"])
                self.assertEqual("python-typescript", receipts[0]["sdk_scope"])
                self.assertEqual("sdk-gateway", receipts[0]["gateway_mode"])
                self.assertEqual(22, receipts[0]["source_artifact_count"])
                self.assertEqual(8, receipts[0]["quickstart_replay_count"])
                self.assertEqual(8, receipts[0]["control_passed_count"])
                self.assertEqual({"passed": 8}, receipts[0]["control_summary"])
                self.assertEqual(payload, receipts[0]["body"])
                self.assertEqual(evidence, roadmap["onboarding_evidence"])
            finally:
                control.close()

    def test_indexes_chain_and_proof_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            append_inventory(chain, load_inventory(INVENTORY))
            append_events(chain, load_events(EVENTS))
            shadow = load_shadow_replay(SHADOW)
            shadow_entry = append_shadow_replay(chain, contract, shadow)
            temporal_entry = append_temporal_holdout_manifest(
                chain,
                shadow_entry["payload"]["temporal_holdout_manifest"],
                contract=contract,
                replay=shadow,
            )
            soak_entry = append_soak_report(chain, contract, load_soak_window(SOAK))
            traffic_export = build_traffic_holdout_export(
                contract,
                shadow,
                export_ref="traffic-export:aitrade/prod-traffic-holdout-20260702",
                source_ref="collector:aitrade-prod/redpanda/trustai.otel.events",
                exporter_ref="oidc:trustai.example/traffic-exporter",
                window_start="2026-07-02T00:00:00Z",
                window_end="2026-07-03T23:59:59Z",
                query_ref="query:shadow-holdout/btcusdt-prod-write",
                cursor_start="redpanda:0:100",
                cursor_end="redpanda:0:102",
                produced_at="2026-07-03T12:20:00Z",
            )
            traffic_export_entry = append_traffic_holdout_export(
                chain,
                traffic_export,
                contract=contract,
                replay=shadow,
            )
            traffic_provider_export = load_traffic_completeness_provider_export(TRAFFIC_COMPLETENESS_PROVIDER_EXPORT)
            traffic_completeness = build_traffic_completeness_receipt(
                traffic_export,
                traffic_provider_export,
                mode="production-export",
                authority_ref="authority:traffic-completeness/aitrade-prod",
                endpoint_url="https://provider.example/aitrade/traffic-holdout/export",
                request_hash="sha256:traffic-completeness-request",
                response_status=200,
                response_hash="sha256:traffic-completeness-response",
                actor_ref="oidc:trustai.example/traffic-completeness-worker",
                produced_at="2026-07-03T12:25:00Z",
            )
            traffic_completeness_entry = append_traffic_completeness_receipt(
                chain,
                traffic_completeness,
                traffic_export=traffic_export,
                provider_export=traffic_provider_export,
            )
            shadow_authority = build_shadow_authority_dossier(
                contract,
                shadow,
                shadow_entry["payload"]["temporal_holdout_manifest"],
                traffic_export,
                traffic_completeness,
                provider_export=traffic_provider_export,
                mode="production-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:shadow-control/aitrade-prod",
                authority_ref="authority:traffic-completeness/aitrade-prod",
                producer_ref="service:trustai-shadow-authority",
                authority_evidence=_complete_shadow_authority_evidence(),
                generated_at="2026-07-19T00:05:00Z",
            )
            shadow_authority_entry = append_shadow_authority_dossier(
                chain,
                shadow_authority,
                contract=contract,
                replay=shadow,
                temporal_holdout=shadow_entry["payload"]["temporal_holdout_manifest"],
                traffic_export=traffic_export,
                traffic_completeness=traffic_completeness,
                provider_export=traffic_provider_export,
                require_complete=True,
                require_fresh=True,
                now="2026-07-19T00:05:00Z",
            )
            results = json.loads(RESULTS.read_text(encoding="utf-8"))
            eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
            append_anchor(chain)
            chain.save()
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
            verification = verify_proof_pack(pack)
            payload = build_promotion_check_payload(
                pack,
                verification,
                provider="github",
                commit_sha="0123456789abcdef0123456789abcdef01234567",
                repository="volelabs/trust_ai",
                target_url="https://example.test/proof-pack",
            )
            delivery = build_provider_delivery(
                payload,
                endpoint_base="https://api.github.com",
                credential_ref="env:GITHUB_TOKEN",
                mode="dry-run",
                delivered_at="2026-07-04T00:00:00Z",
            )
            receipt = build_promotion_status_receipt(
                pack,
                verification,
                payload,
                delivery=delivery,
                attested_at="2026-07-04T00:01:00Z",
            )
            append_promotion_status_receipt(
                chain,
                receipt,
                proof_pack=pack,
                verification=verification,
                payload=payload,
                delivery=delivery,
            )
            action = load_action(ACTION)
            append_runtime_attestation(chain, contract, action)
            policy = {**load_policy_pack(POLICY), "proof_decay": {}}
            policy_decision = append_policy_decision(
                chain,
                policy,
                action,
                proof_pack=pack,
                now="2026-07-04T02:00:00Z",
            )
            policy_export = export_policy_pack(policy)
            engine_receipt = build_policy_engine_receipt(
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
                engine="opa",
            )
            append_policy_engine_receipt(
                chain,
                engine_receipt,
                policy,
                action,
                pack,
                policy_decision,
                policy_export=policy_export,
            )
            append_incident(chain, load_incident(INCIDENT))
            audit = build_roadmap_audit(ROOT)
            audit_entry = append_roadmap_audit(chain, audit, root=ROOT)
            external_manifest = build_external_evidence_manifest(
                audit,
                root=ROOT,
                generated_at="2026-07-12T00:00:00Z",
            )
            collection_payload = {
                "run_id": "collection-run-control-001",
                "run_hash": "sha256:collection-run-control-001",
                "source_map": {"source_map_id": "source-map-control-001"},
                "source_map_hash": "sha256:source-map-control-001",
                "source_plan": {"plan_id": "roadmap-plan-control-001", "plan_hash": "sha256:roadmap-plan-control-001"},
                "source_manifest": {
                    "manifest_id": external_manifest["manifest_id"],
                    "manifest_ref": external_manifest.get("manifest_ref"),
                    "manifest_hash": content_hash(external_manifest),
                },
                "source_roadmap_audit": external_manifest["source_roadmap_audit"],
                "source_roadmap_audit_inclusion_proof": chain.proof_for(audit_entry),
                "require_fresh": True,
                "require_live_source_uris": True,
                "require_source_snapshot_artifacts": True,
                "require_fresh_source_snapshot_artifacts": True,
                "freshness_checked_at": "2026-07-12T00:05:00Z",
                "collected_count": 2,
                "task_count": 2,
                "collected_tasks": ["oss-verifier-and-public-spec:provider-api", "oss-verifier-and-public-spec:ci-run"],
                "snapshot_ids": ["snapshot:github-main-ref", "snapshot:github-actions-run"],
                "intake_ids": ["intake:github-main-ref", "intake:github-actions-run"],
                "limitations": [
                    "Control-plane fixture for collection-run indexing; collection-run verification is covered separately.",
                ],
            }
            chain.append(
                EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE,
                collection_payload,
                timestamp="2026-07-12T00:04:00Z",
            )
            append_external_evidence_manifest(chain, external_manifest, audit, root=ROOT)
            phase_scoreboard = build_phase_scoreboard(
                ROOT,
                scoreboard_ref="scoreboard:trustai/roadmap/readiness",
                producer_ref="oidc:trustai.example/strategy",
                generated_at="2026-07-20T00:00:00Z",
            )
            append_phase_scoreboard(chain, phase_scoreboard, root=ROOT)
            design_partner_dossier = build_design_partner_dossier(
                ROOT,
                dossier_ref="dossier:design-partner/phase1-readiness",
                producer_ref="oidc:trustai.example/gtm-ops",
                partners=[
                    {
                        "partner_ref": "partner:bank-a",
                        "industry": "finserv",
                        "agent_ref": "agent:payments-risk",
                        "pilot_value_usd": 60000,
                        "contract_status": "negotiating",
                    },
                    {
                        "partner_ref": "partner:insurer-b",
                        "industry": "insurance",
                        "agent_ref": "agent:claims-triage",
                        "pilot_value_usd": 90000,
                        "contract_status": "negotiating",
                    },
                    {
                        "partner_ref": "partner:fintech-c",
                        "industry": "fintech",
                        "agent_ref": "agent:treasury-ops",
                        "pilot_value_usd": 100000,
                        "contract_status": "negotiating",
                    },
                ],
                scrutiny_events=[
                    {
                        "scrutiny_ref": "scrutiny:model-risk-a",
                        "party_type": "model-risk",
                        "party_ref": "team:model-risk",
                        "partner_ref": "partner:bank-a",
                        "outcome": "submitted",
                    }
                ],
                generated_at="2026-07-21T00:00:00Z",
            )
            append_design_partner_dossier(chain, design_partner_dossier, root=ROOT)
            own_compliance_dossier = build_own_compliance_dossier(
                ROOT,
                dossier_ref="dossier:trustai/own-compliance-readiness",
                producer_ref="oidc:trustai.example/compliance-ops",
                scope_ref="scope:trustai/company",
                generated_at="2026-07-22T00:00:00Z",
            )
            append_own_compliance_dossier(chain, own_compliance_dossier, root=ROOT)
            product_scope_decision = build_product_scope_decision(
                ROOT,
                decision_ref="scope:request/regulator-export",
                requester_ref="product:gtm",
                reviewer_ref="oidc:trustai.example/product",
                feature_title="Regulator export evidence",
                feature_summary="Portable regulator export that strengthens third-party proof review.",
                decision="accept",
                proof_impacts=["proof-strength", "wider-acceptance"],
                generated_at="2026-07-22T00:10:00Z",
            )
            append_product_scope_decision(chain, product_scope_decision, root=ROOT)
            vertical_pack = build_vertical_pack(
                ROOT,
                pack_ref="vertical-pack:trading-treasury/readiness",
                vertical="trading-treasury",
                producer_ref="oidc:trustai.example/vertical-pack",
                reviewer_ref="oidc:trustai.example/model-risk",
                generated_at="2026-07-22T00:20:00Z",
            )
            append_vertical_pack(chain, vertical_pack, root=ROOT)
            reliability_report = build_reliability_report(
                ROOT,
                report_ref="report:state-of-agent-reliability/readiness",
                producer_ref="oidc:trustai.example/reliability",
                period_start="2026-01-01T00:00:00Z",
                period_end="2026-07-01T00:00:00Z",
                cohorts=[
                    {
                        "segment_ref": "segment:finserv-agents",
                        "contributing_org_count": 3,
                        "agent_count": 4,
                        "proof_pack_count": 5,
                        "promotion_pass_count": 4,
                        "promotion_fail_count": 1,
                        "incident_count": 1,
                        "total_action_count": 100000,
                    }
                ],
                generated_at="2026-07-22T00:30:00Z",
            )
            append_reliability_report(chain, reliability_report, root=ROOT)
            mcp_calls = load_mcp_transcript(MCP)
            mcp_entries = append_mcp_transcript(chain, mcp_calls)
            mcp_proxy_capture = build_mcp_proxy_capture(
                load_mcp_proxy_events(MCP_PROXY),
                agent=mcp_calls[0]["agent"],
                contract_hash=mcp_calls[0]["contract_hash"],
                proxy_ref="mcp-proxy:trustai/local",
                upstream_ref="mcp-server:aitrade/tools",
                captured_at="2026-07-03T12:00:12Z",
                source_events_path=MCP_PROXY,
            )
            mcp_proxy_entry = append_mcp_proxy_capture(chain, mcp_proxy_capture, source_events_path=MCP_PROXY)
            mcp_authority_evidence = [
                {
                    "requirement_id": "production-mcp-proxy-worker-fleet",
                    "authority_kind": "hosted-service",
                    "evidence_ref": "mcp-proxy:fleet/aitrade-prod",
                    "evidence_hash": "sha256:mcp-proxy-worker-fleet",
                    "description": "Hosted MCP proxy worker fleet export for governed tool-call capture.",
                    "issuer": "TrustAI Hosted Ops",
                    "subject": "aitrade-prod MCP proxy fleet",
                    "source_uri": "https://authority.trustai.ai/mcp-gateway/proxy-prod/production-mcp-proxy-worker-fleet/hosted-service",
                    "issued_at": "2026-07-12T03:10:00Z",
                    "expires_at": "2026-07-19T03:10:00Z",
                },
                {
                    "requirement_id": "immutable-mcp-audit-logs",
                    "authority_kind": "cloud-object-lock",
                    "evidence_ref": "s3-object-lock:mcp/audit/aitrade-prod",
                    "evidence_hash": "sha256:mcp-immutable-audit-root",
                    "description": "Object Lock audit-log root for MCP proxy and tool server events.",
                    "issuer": "Example Cloud Object Lock",
                    "subject": "aitrade-prod MCP audit retention",
                    "source_uri": "https://authority.trustai.ai/mcp-gateway/proxy-prod/immutable-mcp-audit-logs/cloud-object-lock",
                    "issued_at": "2026-07-12T03:11:00Z",
                    "expires_at": "2026-07-19T03:11:00Z",
                },
            ]
            mcp_authority_bundle = build_mcp_gateway_authority_evidence_bundle(
                authority_evidence=mcp_authority_evidence,
                mode="authority-export",
                environment="aitrade-prod",
                bundle_ref="bundle:mcp-gateway-authority/proxy-prod/2026-07-12",
                issuer_ref="authority:trustai-mcp-gateway-authority",
                subject_ref="mcp-gateway:aitrade-prod/proxy",
                authority_ref="authority:mcp-gateway/proxy-prod",
                generated_at="2026-07-12T03:12:00Z",
            )
            append_mcp_gateway_authority_evidence_bundle(
                chain,
                mcp_authority_bundle,
                require_fresh=True,
                now="2026-07-15T00:00:00Z",
            )
            mcp_authority = build_mcp_gateway_authority_dossier(
                mcp_calls,
                mode="proxy-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:mcp-gateway-authority/aitrade-prod",
                authority_ref="authority:mcp-gateway/proxy-prod",
                producer_ref="oidc:trustai.example/mcp-gateway-authority-worker",
                authority_evidence=mcp_authority_evidence,
                generated_at="2026-07-12T03:12:00Z",
            )
            append_mcp_gateway_authority_dossier(chain, mcp_authority, transcript_calls=mcp_calls)
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                counts = control.index_chain(chain)
                control.index_proof_pack(pack, tmp / "pack.json")
                summary = control.summary()

                self.assertGreaterEqual(counts["chain_entries"], 5)
                self.assertEqual(1, summary["counts"]["contracts"])
                self.assertEqual(1, counts["contracts"])
                self.assertEqual(2, summary["counts"]["agents"])
                self.assertEqual(1, summary["counts"]["eval_runs"])
                self.assertEqual(1, summary["counts"]["gate_decisions"])
                self.assertEqual(1, counts["eval_runs"])
                self.assertEqual(1, counts["gate_decisions"])
                self.assertEqual(1, summary["counts"]["proof_packs"])
                self.assertEqual(1, summary["counts"]["anchors"])
                self.assertEqual(2, summary["counts"]["ingest_events"])
                self.assertEqual(2, counts["ingest_events"])
                self.assertEqual(1, summary["counts"]["mcp_tool_calls"])
                self.assertEqual(1, summary["counts"]["mcp_proxy_captures"])
                self.assertEqual(1, summary["counts"]["mcp_gateway_authority_evidence_bundles"])
                self.assertEqual(1, counts["mcp_tool_calls"])
                self.assertEqual(1, counts["mcp_proxy_captures"])
                self.assertEqual(1, counts["mcp_gateway_authority_evidence_bundles"])
                self.assertEqual(1, summary["counts"]["promotion_statuses"])
                self.assertEqual(1, counts["promotion_statuses"])
                self.assertEqual(1, summary["counts"]["runtime_attestations"])
                self.assertEqual(1, summary["counts"]["policy_decisions"])
                self.assertEqual(1, summary["counts"]["policy_engine_receipts"])
                self.assertEqual(1, summary["counts"]["incidents"])
                self.assertEqual(1, summary["counts"]["roadmap_audits"])
                self.assertEqual(1, summary["counts"]["external_evidence_collection_runs"])
                self.assertEqual(1, summary["counts"]["external_evidence_manifests"])
                self.assertEqual(2, summary["counts"]["authority_dossiers"])
                self.assertEqual(1, summary["counts"]["phase_scoreboards"])
                self.assertEqual(1, summary["counts"]["design_partner_dossiers"])
                self.assertEqual(1, summary["counts"]["own_compliance_dossiers"])
                self.assertEqual(1, summary["counts"]["product_scope_decisions"])
                self.assertEqual(1, summary["counts"]["vertical_packs"])
                self.assertEqual(1, summary["counts"]["reliability_reports"])
                self.assertEqual(1, summary["counts"]["temporal_holdout_manifests"])
                self.assertEqual(1, summary["counts"]["shadow_replays"])
                self.assertEqual(1, summary["counts"]["soak_reports"])
                self.assertEqual(1, summary["counts"]["traffic_holdout_exports"])
                self.assertEqual(1, summary["counts"]["traffic_completeness_receipts"])
                self.assertEqual(2, summary["counts"]["authority_dossiers"])
                self.assertEqual(1, counts["runtime_attestations"])
                self.assertEqual(1, counts["policy_decisions"])
                self.assertEqual(1, counts["policy_engine_receipts"])
                self.assertEqual(1, counts["incidents"])
                self.assertEqual(1, counts["roadmap_audits"])
                self.assertEqual(1, counts["external_evidence_collection_runs"])
                self.assertEqual(1, counts["external_evidence_manifests"])
                self.assertEqual(2, counts["authority_dossiers"])
                self.assertEqual(1, counts["phase_scoreboards"])
                self.assertEqual(1, counts["design_partner_dossiers"])
                self.assertEqual(1, counts["own_compliance_dossiers"])
                self.assertEqual(1, counts["product_scope_decisions"])
                self.assertEqual(1, counts["vertical_packs"])
                self.assertEqual(1, counts["reliability_reports"])
                self.assertEqual(1, counts["temporal_holdout_manifests"])
                self.assertEqual(1, counts["shadow_replays"])
                self.assertEqual(1, counts["soak_reports"])
                self.assertEqual(1, counts["traffic_holdout_exports"])
                self.assertEqual(1, counts["traffic_completeness_receipts"])
                self.assertEqual(audit["audit_id"], summary["latest_roadmap_audit"]["audit_id"])
                self.assertEqual("local-reference-complete-with-external-authority-deferred", summary["latest_roadmap_audit"]["completion_position"])
                self.assertEqual("collection-run-control-001", summary["latest_external_evidence_collection_run"]["run_id"])
                self.assertTrue(summary["latest_external_evidence_collection_run"]["require_fresh"])
                self.assertEqual(2, summary["latest_external_evidence_collection_run"]["collected_count"])
                self.assertEqual("partial", summary["latest_external_evidence_manifest"]["status"])
                self.assertGreater(summary["latest_external_evidence_manifest"]["missing_authority_kind_count"], 0)
                self.assertEqual(mcp_authority_bundle["bundle_id"], summary["latest_mcp_gateway_authority_evidence_bundle"]["bundle_id"])
                self.assertEqual(2, summary["latest_mcp_gateway_authority_evidence_bundle"]["covered_requirement_count"])
                self.assertEqual(shadow_authority_entry["payload"]["dossier_id"], summary["latest_authority_dossier"]["dossier_id"])
                self.assertTrue(summary["latest_authority_dossier"]["production_ready"])
                self.assertEqual("scoreboard:trustai/roadmap/readiness", summary["latest_phase_scoreboard"]["scoreboard_ref"])
                self.assertEqual("readiness", summary["latest_phase_scoreboard"]["mode"])
                self.assertEqual({"external-required": 10, "passed": 2}, summary["latest_phase_scoreboard"]["control_summary"])
                self.assertEqual("dossier:design-partner/phase1-readiness", summary["latest_design_partner_dossier"]["dossier_ref"])
                self.assertEqual("readiness", summary["latest_design_partner_dossier"]["mode"])
                self.assertEqual(3, summary["latest_design_partner_dossier"]["partner_count"])
                self.assertEqual(0, summary["latest_design_partner_dossier"]["signed_pilot_value_usd"])
                self.assertEqual({"external-required": 2, "passed": 6}, summary["latest_design_partner_dossier"]["control_summary"])
                self.assertEqual("dossier:trustai/own-compliance-readiness", summary["latest_own_compliance_dossier"]["dossier_ref"])
                self.assertEqual("readiness", summary["latest_own_compliance_dossier"]["mode"])
                self.assertEqual(0, summary["latest_own_compliance_dossier"]["required_certification_evidence_count"])
                self.assertEqual({"external-required": 2, "passed": 6}, summary["latest_own_compliance_dossier"]["control_summary"])
                self.assertEqual("scope:request/regulator-export", summary["latest_product_scope_decision"]["decision_ref"])
                self.assertEqual("accept", summary["latest_product_scope_decision"]["decision"])
                self.assertEqual(["proof-strength", "wider-acceptance"], summary["latest_product_scope_decision"]["proof_impacts"])
                self.assertEqual({"passed": 10}, summary["latest_product_scope_decision"]["control_summary"])
                self.assertEqual("vertical-pack:trading-treasury/readiness", summary["latest_vertical_pack"]["pack_ref"])
                self.assertEqual("trading-treasury", summary["latest_vertical_pack"]["vertical"])
                self.assertEqual(2, summary["latest_vertical_pack"]["external_requirement_count"])
                self.assertEqual({"external-required": 1, "passed": 7}, summary["latest_vertical_pack"]["control_summary"])
                self.assertEqual("report:state-of-agent-reliability/readiness", summary["latest_reliability_report"]["report_ref"])
                self.assertEqual("draft", summary["latest_reliability_report"]["mode"])
                self.assertEqual(1, summary["latest_reliability_report"]["cohort_count"])
                self.assertEqual(0, summary["latest_reliability_report"]["source_product_count"])
                self.assertEqual(8000, summary["latest_reliability_report"]["gate_pass_rate_bps"])
                self.assertEqual({"external-required": 2, "passed": 6}, summary["latest_reliability_report"]["control_summary"])
                self.assertEqual(temporal_entry["payload"]["manifest_id"], summary["latest_temporal_holdout_manifest"]["manifest_id"])
                self.assertTrue(summary["latest_temporal_holdout_manifest"]["passed"])
                self.assertEqual(shadow_entry["entry_id"], summary["latest_shadow_replay"]["entry_id"])
                self.assertTrue(summary["latest_shadow_replay"]["passed"])
                self.assertTrue(summary["latest_shadow_replay"]["holdout_passed"])
                self.assertEqual(soak_entry["entry_id"], summary["latest_soak_report"]["entry_id"])
                self.assertTrue(summary["latest_soak_report"]["passed"])
                self.assertEqual(traffic_export_entry["payload"]["export_id"], summary["latest_traffic_holdout_export"]["export_id"])
                self.assertTrue(summary["latest_traffic_holdout_export"]["passed"])
                self.assertEqual(traffic_completeness_entry["payload"]["completeness_id"], summary["latest_traffic_completeness_receipt"]["completeness_id"])
                self.assertEqual("production-export", summary["latest_traffic_completeness_receipt"]["mode"])
                self.assertTrue(summary["latest_traffic_completeness_receipt"]["passed"])
                self.assertEqual(shadow_authority_entry["payload"]["dossier_id"], summary["latest_authority_dossier"]["dossier_id"])
                self.assertTrue(summary["latest_authority_dossier"]["production_ready"])
                self.assertEqual("passed", summary["latest_proof_pack"]["outcome"])
                self.assertEqual("aitrade-btcusdt-canary", summary["latest_eval_run"]["contract_id"])
                self.assertEqual("passed", summary["latest_gate_decision"]["outcome"])
                self.assertTrue(summary["latest_gate_decision"]["passed"])
                self.assertTrue(summary["latest_gate_decision"]["holdout_passed"])
                self.assertTrue(summary["latest_gate_decision"]["approvals_passed"])
                self.assertEqual("gen_ai.tool.call", summary["latest_ingest_event"]["event_name"])
                self.assertEqual("place_shadow_order", summary["latest_mcp_tool_call"]["tool_name"])
                self.assertEqual(mcp_proxy_capture["capture_id"], summary["latest_mcp_proxy_capture"]["capture_id"])
                self.assertEqual("mcp-proxy:trustai/local", summary["latest_mcp_proxy_capture"]["proxy_ref"])
                self.assertEqual("github", summary["latest_promotion_status"]["provider"])
                self.assertTrue(summary["latest_promotion_status"]["passed"])
                self.assertEqual("shadow-order-20260703-001", summary["latest_runtime_attestation"]["action_id"])
                self.assertTrue(summary["latest_runtime_attestation"]["passed"])
                self.assertEqual("trading-runtime-policy-v0", summary["latest_policy_decision"]["policy_pack_id"])
                self.assertTrue(summary["latest_policy_decision"]["passed"])
                self.assertEqual("opa", summary["latest_policy_engine_receipt"]["engine_name"])
                self.assertTrue(summary["latest_policy_engine_receipt"]["decision_passed"])
                self.assertEqual("high", summary["latest_incident"]["severity"])
                contracts = control.contracts()
                self.assertEqual(1, len(contracts))
                self.assertEqual("aitrade-btcusdt-canary", contracts[0]["contract_id"])
                contract_hash = contracts[0]["contract_hash"]
                contract_evidence = control.contract_evidence(contract_id="aitrade-btcusdt-canary")
                self.assertEqual("aitrade-btcusdt-canary", contract_evidence["scope"]["contract_id"])
                self.assertEqual(contract_hash, contract_evidence["scope"]["contract_hash"])
                self.assertEqual(1, contract_evidence["counts"]["contracts"])
                self.assertGreaterEqual(contract_evidence["counts"]["chain_entries"], 4)
                self.assertEqual(1, contract_evidence["counts"]["eval_runs"])
                self.assertEqual(1, contract_evidence["counts"]["gate_decisions"])
                self.assertEqual(1, contract_evidence["counts"]["temporal_holdout_manifests"])
                self.assertEqual(1, contract_evidence["counts"]["shadow_replays"])
                self.assertEqual(1, contract_evidence["counts"]["soak_reports"])
                self.assertEqual(1, contract_evidence["counts"]["traffic_holdout_exports"])
                self.assertEqual(1, contract_evidence["counts"]["traffic_completeness_receipts"])
                self.assertEqual(1, contract_evidence["counts"]["proof_packs"])
                self.assertEqual(2, contract_evidence["counts"]["ingest_events"])
                self.assertEqual(1, contract_evidence["counts"]["mcp_tool_calls"])
                self.assertEqual(1, contract_evidence["counts"]["mcp_proxy_captures"])
                self.assertEqual(1, contract_evidence["counts"]["promotion_statuses"])
                self.assertEqual(1, contract_evidence["counts"]["runtime_attestations"])
                self.assertEqual(1, contract_evidence["counts"]["policy_decisions"])
                self.assertEqual(1, contract_evidence["counts"]["policy_engine_receipts"])
                self.assertEqual(1, contract_evidence["counts"]["incidents"])
                self.assertEqual("passed", contract_evidence["gate_decisions"][0]["outcome"])
                self.assertTrue(contract_evidence["gate_decisions"][0]["passed"])
                self.assertTrue(contract_evidence["shadow_replays"][0]["passed"])
                self.assertTrue(contract_evidence["soak_reports"][0]["passed"])
                self.assertEqual(traffic_export["export_id"], contract_evidence["traffic_holdout_exports"][0]["export_id"])
                self.assertEqual(traffic_completeness["completeness_id"], contract_evidence["traffic_completeness_receipts"][0]["completeness_id"])
                self.assertTrue(contract_evidence["traffic_completeness_receipts"][0]["source_completeness"]["records_root_matches"])
                self.assertEqual("gen_ai.tool.call", contract_evidence["ingest_events"][0]["event_name"])
                self.assertEqual("place_shadow_order", contract_evidence["mcp_tool_calls"][0]["tool_name"])
                self.assertEqual(mcp_entries[0]["entry_id"], contract_evidence["mcp_tool_calls"][0]["entry_id"])
                self.assertEqual(mcp_proxy_entry["payload"]["capture_id"], contract_evidence["mcp_proxy_captures"][0]["capture_id"])
                self.assertEqual(mcp_proxy_capture["event_chain_root"], contract_evidence["mcp_proxy_captures"][0]["event_chain_root"])
                self.assertEqual(2, contract_evidence["mcp_proxy_captures"][0]["proxy_events_artifact"]["event_count"])
                self.assertEqual("opa", contract_evidence["policy_engine_receipts"][0]["engine_name"])
                self.assertEqual("incident-20260704-latency-drift", contract_evidence["incidents"][0]["incident_id"])
                hash_scoped = control.contract_evidence(contract_hash=contract_hash, limit=1)
                self.assertEqual(contract_hash, hash_scoped["scope"]["contract_hash"])
                self.assertLessEqual(len(hash_scoped["chain_entries"]), 1)
                with self.assertRaises(ValueError):
                    control.contract_evidence()
                agent_evidence = control.agent_evidence(
                    agent_name=contract["agent"]["name"],
                    agent_version=contract["agent"]["version"],
                )
                self.assertEqual(contract["agent"]["name"], agent_evidence["scope"]["agent_name"])
                self.assertEqual(contract["agent"]["version"], agent_evidence["scope"]["agent_version"])
                self.assertIn(contract_hash, agent_evidence["contract_hashes"])
                self.assertEqual(1, agent_evidence["counts"]["agents"])
                self.assertEqual(1, agent_evidence["counts"]["contracts"])
                self.assertGreaterEqual(agent_evidence["counts"]["chain_entries"], 4)
                self.assertEqual(1, agent_evidence["counts"]["eval_runs"])
                self.assertEqual(1, agent_evidence["counts"]["gate_decisions"])
                self.assertEqual(1, agent_evidence["counts"]["temporal_holdout_manifests"])
                self.assertEqual(1, agent_evidence["counts"]["shadow_replays"])
                self.assertEqual(1, agent_evidence["counts"]["soak_reports"])
                self.assertEqual(1, agent_evidence["counts"]["traffic_holdout_exports"])
                self.assertEqual(1, agent_evidence["counts"]["traffic_completeness_receipts"])
                self.assertEqual(1, agent_evidence["counts"]["proof_packs"])
                self.assertEqual(2, agent_evidence["counts"]["ingest_events"])
                self.assertEqual(1, agent_evidence["counts"]["mcp_tool_calls"])
                self.assertEqual(1, agent_evidence["counts"]["mcp_proxy_captures"])
                self.assertEqual(1, agent_evidence["counts"]["promotion_statuses"])
                self.assertEqual(1, agent_evidence["counts"]["runtime_attestations"])
                self.assertEqual(1, agent_evidence["counts"]["policy_decisions"])
                self.assertEqual(1, agent_evidence["counts"]["policy_engine_receipts"])
                self.assertEqual(1, agent_evidence["counts"]["incidents"])
                self.assertTrue(agent_evidence["agents"][0]["governed"])
                self.assertEqual("passed", agent_evidence["gate_decisions"][0]["outcome"])
                self.assertTrue(agent_evidence["shadow_replays"][0]["passed"])
                self.assertTrue(agent_evidence["traffic_holdout_exports"][0]["passed"])
                self.assertEqual("gen_ai.tool.call", agent_evidence["ingest_events"][0]["event_name"])
                self.assertEqual("place_shadow_order", agent_evidence["mcp_tool_calls"][0]["tool_name"])
                self.assertEqual(mcp_proxy_capture["capture_id"], agent_evidence["mcp_proxy_captures"][0]["capture_id"])
                unversioned_agent_evidence = control.agent_evidence(agent_name=contract["agent"]["name"], limit=1)
                self.assertEqual(contract["agent"]["name"], unversioned_agent_evidence["scope"]["agent_name"])
                self.assertLessEqual(len(unversioned_agent_evidence["chain_entries"]), 1)
                with self.assertRaises(ValueError):
                    control.agent_evidence(agent_name=None)
                self.assertEqual(2, len(control.agents()))
                eval_runs = control.recent_eval_runs()
                self.assertEqual(1, len(eval_runs))
                self.assertEqual("aitrade-btcusdt-canary", eval_runs[0]["contract_id"])
                gate_decisions = control.recent_gate_decisions()
                self.assertEqual(1, len(gate_decisions))
                self.assertEqual("passed", gate_decisions[0]["outcome"])
                self.assertTrue(gate_decisions[0]["passed"])
                self.assertEqual(1, len(control.recent_proof_packs()))
                ingest_events = control.recent_ingest_events()
                self.assertEqual(2, len(ingest_events))
                self.assertEqual("gen_ai.tool.call", ingest_events[0]["event_name"])
                self.assertEqual("place_shadow_order", ingest_events[0]["attributes"]["tool.name"])
                mcp_evidence = control.mcp_evidence()
                self.assertEqual("place_shadow_order", mcp_evidence["mcp_tool_calls"][0]["tool_name"])
                self.assertEqual(mcp_proxy_capture["capture_id"], mcp_evidence["mcp_proxy_captures"][0]["capture_id"])
                self.assertEqual(mcp_authority_bundle["bundle_id"], mcp_evidence["mcp_gateway_authority_evidence_bundles"][0]["bundle_id"])
                self.assertEqual(2, mcp_evidence["mcp_gateway_authority_evidence_bundles"][0]["covered_requirement_count"])
                self.assertEqual(2, mcp_evidence["mcp_gateway_authority_evidence_bundles"][0]["fresh_evidence_count"])
                self.assertEqual(0, mcp_evidence["mcp_gateway_authority_evidence_bundles"][0]["placeholder_source_uri_count"])
                self.assertEqual(1, len(control.recent_mcp_tool_calls()))
                self.assertEqual(1, len(control.recent_mcp_proxy_captures()))
                self.assertEqual(1, len(control.recent_mcp_gateway_authority_evidence_bundles()))
                statuses = control.recent_promotion_statuses()
                self.assertEqual(1, len(statuses))
                self.assertEqual("volelabs/trust_ai", statuses[0]["target_ref"]["repository"])
                self.assertTrue(statuses[0]["provider_status_success"])
                runtime_evidence = control.runtime_evidence()
                self.assertEqual("shadow-order-20260703-001", runtime_evidence["runtime_attestations"][0]["action_id"])
                self.assertEqual("trading-runtime-policy-v0", runtime_evidence["policy_decisions"][0]["policy_pack_id"])
                self.assertEqual("opa", runtime_evidence["policy_engine_receipts"][0]["engine_name"])
                self.assertEqual("incident-20260704-latency-drift", runtime_evidence["incidents"][0]["incident_id"])
                holdout_evidence = control.holdout_evidence()
                self.assertEqual(temporal_entry["payload"]["manifest_id"], holdout_evidence["temporal_holdout_manifests"][0]["manifest_id"])
                self.assertEqual(shadow_entry["entry_id"], holdout_evidence["shadow_replays"][0]["entry_id"])
                self.assertEqual(soak_entry["entry_id"], holdout_evidence["soak_reports"][0]["entry_id"])
                self.assertEqual(traffic_export["export_id"], holdout_evidence["traffic_holdout_exports"][0]["export_id"])
                self.assertEqual(traffic_completeness["completeness_id"], holdout_evidence["traffic_completeness_receipts"][0]["completeness_id"])
                self.assertEqual(3, holdout_evidence["traffic_completeness_receipts"][0]["source_completeness"]["matched_record_count"])
                self.assertEqual(shadow_authority_entry["payload"]["dossier_id"], holdout_evidence["shadow_authority_dossiers"][0]["dossier_id"])
                self.assertTrue(holdout_evidence["shadow_authority_dossiers"][0]["production_ready"])
                roadmap_evidence = control.roadmap_evidence()
                self.assertEqual(audit["audit_id"], roadmap_evidence["roadmap_audits"][0]["audit_id"])
                self.assertGreater(roadmap_evidence["roadmap_audits"][0]["deferred_external_count"], 0)
                self.assertEqual("collection-run-control-001", roadmap_evidence["external_evidence_collection_runs"][0]["run_id"])
                self.assertEqual(2, roadmap_evidence["external_evidence_collection_runs"][0]["task_count"])
                self.assertTrue(roadmap_evidence["external_evidence_collection_runs"][0]["require_live_source_uris"])
                self.assertEqual(
                    ["intake:github-main-ref", "intake:github-actions-run"],
                    roadmap_evidence["external_evidence_collection_runs"][0]["intake_ids"],
                )
                self.assertEqual(1, len(roadmap_evidence["external_evidence_manifests"]))
                self.assertEqual(1, len(roadmap_evidence["phase_scoreboards"]))
                self.assertEqual(1, len(roadmap_evidence["design_partner_dossiers"]))
                self.assertEqual(1, len(roadmap_evidence["own_compliance_dossiers"]))
                self.assertEqual(1, len(roadmap_evidence["product_scope_decisions"]))
                self.assertEqual(1, len(roadmap_evidence["vertical_packs"]))
                self.assertEqual(1, len(roadmap_evidence["reliability_reports"]))
                self.assertEqual(1, len(roadmap_evidence["holdout_evidence"]["shadow_replays"]))
                self.assertEqual(1, len(roadmap_evidence["holdout_evidence"]["traffic_completeness_receipts"]))
                self.assertEqual(1, len(roadmap_evidence["holdout_evidence"]["shadow_authority_dossiers"]))
                self.assertEqual(2, len(roadmap_evidence["authority_dossiers"]))
                self.assertEqual(1, len(roadmap_evidence["mcp_evidence"]["mcp_tool_calls"]))
                self.assertEqual(1, len(roadmap_evidence["mcp_evidence"]["mcp_proxy_captures"]))
                self.assertEqual(1, len(roadmap_evidence["mcp_evidence"]["mcp_gateway_authority_evidence_bundles"]))
                self.assertEqual(runtime_evidence, roadmap_evidence["runtime_evidence"])
                phase_scoreboards = control.recent_phase_scoreboards()
                self.assertEqual(1, len(phase_scoreboards))
                self.assertEqual("readiness", phase_scoreboards[0]["mode"])
                self.assertEqual({"external-required": 10, "passed": 2}, phase_scoreboards[0]["control_summary"])
                design_partner_dossiers = control.recent_design_partner_dossiers()
                self.assertEqual(1, len(design_partner_dossiers))
                self.assertEqual("dossier:design-partner/phase1-readiness", design_partner_dossiers[0]["dossier_ref"])
                self.assertEqual(3, design_partner_dossiers[0]["partner_count"])
                self.assertEqual({"external-required": 2, "passed": 6}, design_partner_dossiers[0]["control_summary"])
                own_compliance_dossiers = control.recent_own_compliance_dossiers()
                self.assertEqual(1, len(own_compliance_dossiers))
                self.assertEqual("dossier:trustai/own-compliance-readiness", own_compliance_dossiers[0]["dossier_ref"])
                self.assertEqual(0, own_compliance_dossiers[0]["required_certification_evidence_count"])
                self.assertEqual({"external-required": 2, "passed": 6}, own_compliance_dossiers[0]["control_summary"])
                product_scope_decisions = control.recent_product_scope_decisions()
                self.assertEqual(1, len(product_scope_decisions))
                self.assertEqual("scope:request/regulator-export", product_scope_decisions[0]["decision_ref"])
                self.assertEqual(["proof-strength", "wider-acceptance"], product_scope_decisions[0]["proof_impacts"])
                self.assertEqual({"passed": 10}, product_scope_decisions[0]["control_summary"])
                vertical_packs = control.recent_vertical_packs()
                self.assertEqual(1, len(vertical_packs))
                self.assertEqual("trading-treasury", vertical_packs[0]["vertical"])
                self.assertEqual(["SR 11-7", "ISO 42001", "NIST AI RMF", "SOC 2"], vertical_packs[0]["frameworks"])
                self.assertEqual({"external-required": 1, "passed": 7}, vertical_packs[0]["control_summary"])
                reliability_reports = control.recent_reliability_reports()
                self.assertEqual(1, len(reliability_reports))
                self.assertEqual("draft", reliability_reports[0]["mode"])
                self.assertEqual("2026-01-01T00:00:00Z", reliability_reports[0]["reporting_period"]["start"])
                self.assertEqual(1, reliability_reports[0]["incident_rate_per_100k_actions"])
                self.assertEqual({"external-required": 2, "passed": 6}, reliability_reports[0]["control_summary"])
                readiness = control.readiness()
                self.assertEqual("not_ready", readiness["status"])
                self.assertTrue(readiness["local_reference_complete"])
                self.assertTrue(readiness["collection_run_present"])
                self.assertTrue(readiness["collection_run_complete"])
                self.assertFalse(readiness["external_authority_complete"])
                self.assertGreater(readiness["external_authority_gap_summary"]["missing_authority_unit_count"], 0)
                self.assertIn("provider-api", readiness["external_authority_gap_summary"]["gap_count_by_authority_kind"])
                self.assertFalse(readiness["production_authority_ready"])
                self.assertFalse(readiness["roadmap_phase_scoreboard_ready"])
                self.assertFalse(readiness["design_partner_ready"])
                self.assertFalse(readiness["own_compliance_ready"])
                self.assertTrue(readiness["product_scope_ready"])
                self.assertFalse(readiness["vertical_pack_ready"])
                self.assertFalse(readiness["reliability_report_ready"])
                self.assertEqual("readiness", readiness["phase_scoreboard_summary"]["mode"])
                self.assertEqual(10, readiness["phase_scoreboard_summary"]["external_required_control_count"])
                self.assertEqual("readiness", readiness["design_partner_summary"]["mode"])
                self.assertEqual(2, readiness["design_partner_summary"]["external_required_control_count"])
                self.assertEqual(3, readiness["design_partner_summary"]["partner_count"])
                self.assertEqual(0, readiness["design_partner_summary"]["signed_pilot_value_usd"])
                self.assertEqual("readiness", readiness["own_compliance_summary"]["mode"])
                self.assertEqual(2, readiness["own_compliance_summary"]["external_required_control_count"])
                self.assertEqual(0, readiness["own_compliance_summary"]["required_certification_evidence_count"])
                self.assertEqual("accept", readiness["product_scope_summary"]["decision"])
                self.assertEqual(2, readiness["product_scope_summary"]["proof_impact_count"])
                self.assertEqual(0, readiness["product_scope_summary"]["failed_control_count"])
                self.assertEqual("trading-treasury", readiness["vertical_pack_summary"]["vertical"])
                self.assertEqual(1, readiness["vertical_pack_summary"]["external_required_control_count"])
                self.assertEqual("draft", readiness["reliability_report_summary"]["mode"])
                self.assertEqual(0, readiness["reliability_report_summary"]["source_product_count"])
                self.assertEqual(2, readiness["reliability_report_summary"]["external_required_control_count"])
                self.assertTrue(readiness["promotion_gate_ready"])
                self.assertTrue(readiness["proof_pack_ready"])
                self.assertTrue(readiness["runtime_policy_ready"])
                self.assertGreater(readiness["authority_dossier_summary"]["not_ready"], 0)
                self.assertTrue(
                    any("external authority evidence incomplete" in blocker for blocker in readiness["blockers"])
                )
                self.assertTrue(
                    any("roadmap phase scoreboard milestones incomplete" in blocker for blocker in readiness["blockers"])
                )
                self.assertTrue(
                    any("design-partner pilot milestones incomplete" in blocker for blocker in readiness["blockers"])
                )
                self.assertTrue(
                    any("TrustAI own-compliance certifications incomplete" in blocker for blocker in readiness["blockers"])
                )
                self.assertTrue(
                    any("vertical-pack production acceptance incomplete" in blocker for blocker in readiness["blockers"])
                )
                self.assertTrue(
                    any("State of Agent Reliability publication incomplete" in blocker for blocker in readiness["blockers"])
                )
                external_evidence = control.recent_external_evidence_manifests()
                self.assertEqual(1, len(external_evidence))
                self.assertEqual("partial", external_evidence[0]["status"])
                self.assertFalse(external_evidence[0]["require_complete"])
                self.assertGreater(external_evidence[0]["missing_requirement_count"], 0)
                self.assertGreater(external_evidence[0]["missing_authority_kind_count"], 0)
                self.assertIsInstance(external_evidence[0]["missing_requirement_ids"], list)
                self.assertIsInstance(external_evidence[0]["missing_authority_kinds_by_requirement"], dict)
                self.assertEqual(
                    external_evidence[0]["missing_authority_kind_count"],
                    external_evidence[0]["external_authority_gap_summary"]["missing_authority_unit_count"],
                )
                self.assertEqual(
                    external_evidence[0]["missing_authority_kind_count"],
                    len(external_evidence[0]["missing_authority_units"]),
                )
                first_missing_unit = external_evidence[0]["missing_authority_units"][0]
                self.assertIn("task_id", first_missing_unit)
                self.assertIn("requirement_title", first_missing_unit)
                self.assertIn("requirement_phase", first_missing_unit)
                self.assertIn("requirement_priority", first_missing_unit)
                self.assertIn("roadmap_ref", first_missing_unit)
                self.assertGreaterEqual(first_missing_unit["authority_kind_rank"], 1)
                self.assertIn(
                    first_missing_unit["collection_priority"],
                    {"deployment-operations", "external-acceptance", "other"},
                )
                self.assertIn(
                    "gap_count_by_collection_priority",
                    external_evidence[0]["external_authority_gap_summary"],
                )
                self.assertIn(
                    "gap_count_by_requirement_phase",
                    external_evidence[0]["external_authority_gap_summary"],
                )
                gap_worklist = control.external_authority_gaps(authority_kind="provider-api", limit=2)
                self.assertEqual(2, len(gap_worklist["missing_authority_units"]))
                self.assertEqual(2, gap_worklist["summary"]["returned_missing_authority_unit_count"])
                self.assertGreater(gap_worklist["summary"]["selected_missing_authority_unit_count"], 2)
                self.assertEqual(
                    {"deployment-operations": gap_worklist["summary"]["selected_missing_authority_unit_count"]},
                    gap_worklist["summary"]["gap_count_by_collection_priority"],
                )
                self.assertTrue(gap_worklist["summary"]["gap_count_by_requirement_phase"])
                self.assertTrue(
                    all(unit["authority_kind"] == "provider-api" for unit in gap_worklist["missing_authority_units"])
                )
                first_requirement = external_evidence[0]["missing_authority_units"][0]["requirement_id"]
                requirement_gaps = control.external_authority_gaps(requirement_id=first_requirement)
                self.assertTrue(
                    all(unit["requirement_id"] == first_requirement for unit in requirement_gaps["missing_authority_units"])
                )
                with self.assertRaises(ValueError):
                    control.external_authority_gaps(limit=0)
                authority_dossiers = control.recent_authority_dossiers()
                self.assertEqual(2, len(authority_dossiers))
                mcp_authority_dossier = next(
                    item for item in authority_dossiers if item["entry_type"] == "mcp.gateway_authority_recorded"
                )
                shadow_authority_dossier = next(
                    item for item in authority_dossiers if item["entry_type"] == shadow_authority_entry["entry_type"]
                )
                self.assertEqual("authority:mcp-gateway/proxy-prod", mcp_authority_dossier["authority_ref"])
                self.assertFalse(mcp_authority_dossier["production_claimed"])
                self.assertEqual(2, mcp_authority_dossier["covered_requirement_count"])
                self.assertGreater(mcp_authority_dossier["missing_requirement_count"], 0)
                self.assertEqual(2, mcp_authority_dossier["freshness_window_count"])
                self.assertIsInstance(mcp_authority_dossier["missing_requirement_ids"], list)
                self.assertEqual(2, mcp_authority_dossier["control_summary"]["deferred"])
                self.assertEqual(shadow_authority_entry["payload"]["dossier_id"], shadow_authority_dossier["dossier_id"])
                self.assertTrue(shadow_authority_dossier["production_ready"])
            finally:
                control.close()

    def test_indexes_byoc_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            store_root = tmp / "worm"
            store = WORMStore(store_root)
            receipt = store.store_json(
                {"artifact": "proof-pack", "pack_id": "pack-123"},
                "proof-pack",
                retention_until="2033-07-04T00:00:00Z",
            )
            legal_hold = store.apply_legal_hold(
                receipt,
                case_id="external-audit-2026-001",
                reason="Preserve proof pack for external audit.",
                applied_by="legal@example.com",
                applied_at="2026-07-04T01:00:00Z",
            )
            deployment = build_deployment_manifest(
                ROOT,
                environment="aitrade-byoc",
                generated_at="2026-07-04T00:00:00Z",
            )
            operator = build_byoc_operator_attestation(
                deployment,
                receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
                environment="aitrade-byoc",
                operator_ref="operator:trustai/byoc",
                operator_version="0.1.0",
                operator_image="ghcr.io/trustai/operator:0.1.0",
                operator_image_digest="sha256:trustai-byoc-operator-digest",
                namespace="trustai",
                service_account_ref="k8s:sa/trustai/operator",
                reconciler_ref="controller:trustai/byoc-operator",
                upgrade_policy_ref="policy:trustai/byoc-upgrade-v0.1",
                rollback_policy_ref="policy:trustai/byoc-rollback-v0.1",
                tenant_id="aitrade-local",
                customer_account_ref="aws:123456789012",
                data_plane_ref="k8s:cluster/aitrade-prod",
                control_plane_ref="trustai:control-plane/local",
                keyring_ref="keyring:.trustai/keyring.local.json",
                object_lock_provider="Example S3 Object Lock",
                object_lock_bucket="arn:aws:s3:::trustai-aitrade-evidence",
                object_lock_region="us-east-1",
                backup_policy_ref="backup:trustai/daily",
                backup_schedule="rate(1 day)",
                restore_test_ref="restore-test:trustai/2026-07-04",
                restore_test_at="2026-07-04T02:00:00Z",
                rpo_minutes=60,
                rto_minutes=240,
                ingress_mode="private-load-balancer",
                egress_policy_ref="egress-policy:trustai/deny-by-default",
                allowed_egress_refs=["egress:kms", "egress:tsa"],
                airgap_bundle_ref="bundle:trustai/airgap/2026-07-04",
                airgap_bundle_hash="sha256:trustai-airgap-bundle",
                audit_log_ref="audit-log:byoc/operator",
                audit_log_root="sha256:byoc-operator-audit-root",
                retention_until="2033-07-04T00:00:00Z",
                actor_ref="oidc:trustai.example/byoc-operator",
                credential_ref="env:BYOC_OPERATOR_TOKEN",
                evidence_refs=["evidence:byoc/operator"],
                attested_at="2026-07-04T03:00:00Z",
            )
            authority = build_byoc_authority_dossier(
                deployment,
                operator,
                root=ROOT,
                store=store_root,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                mode="operator-dossier",
                environment="aitrade-byoc",
                dossier_ref="dossier:byoc-authority/aitrade-byoc",
                authority_ref="authority:byoc/aitrade-byoc",
                producer_ref="oidc:trustai.example/byoc-authority-worker",
                authority_evidence=[
                    {
                        "requirement_id": "live-cloud-account-binding",
                        "authority_kind": "provider-api",
                        "evidence_ref": "aws:account/123456789012/trustai-byoc",
                        "evidence_hash": "sha256:byoc-live-cloud-account",
                        "description": "Provider account export tying the BYOC deployment to the customer-owned account.",
                        "issuer": "ExampleCloud",
                        "subject": "aitrade BYOC account",
                        "source_uri": "https://cloud.example/accounts/123456789012/trustai",
                        "issued_at": "2026-07-04T03:05:00Z",
                        "expires_at": "2026-12-31T00:00:00Z",
                    },
                    {
                        "requirement_id": "object-lock-compliance-mode",
                        "authority_kind": "cloud-object-lock",
                        "evidence_ref": "s3-object-lock:trustai-aitrade-evidence",
                        "evidence_hash": "sha256:byoc-object-lock-export",
                        "description": "Provider Object Lock export for the retained proof-pack bucket.",
                        "issuer": "ExampleCloud Object Lock",
                        "subject": "trustai-aitrade-evidence",
                        "source_uri": "https://cloud.example/s3/trustai-aitrade-evidence/object-lock",
                        "issued_at": "2026-07-04T03:06:00Z",
                        "expires_at": "2026-12-31T00:00:00Z",
                    },
                ],
                authority_artifacts=[],
                generated_at="2026-07-04T03:10:00Z",
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="byoc-control")
            operator_entry = append_byoc_operator_attestation(
                chain,
                operator,
                deployment,
                receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )
            authority_entry = append_byoc_authority_dossier(
                chain,
                authority,
                deployment_manifest=deployment,
                byoc_operator=operator,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
                authority_artifacts=[],
            )
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.byoc_evidence()
                roadmap = control.roadmap_evidence()
                generic_authority = control.recent_authority_dossiers()

                self.assertEqual(1, indexed["byoc_operator_attestations"])
                self.assertEqual(1, indexed["byoc_authority_dossiers"])
                self.assertEqual(1, indexed["authority_dossiers"])
                self.assertEqual(1, summary["counts"]["byoc_operator_attestations"])
                self.assertEqual(1, summary["counts"]["byoc_authority_dossiers"])
                self.assertEqual(operator["attestation_id"], summary["latest_byoc_operator_attestation"]["attestation_id"])
                self.assertTrue(summary["latest_byoc_operator_attestation"]["object_lock_enabled"])
                self.assertTrue(summary["latest_byoc_operator_attestation"]["legal_hold_active"])
                self.assertTrue(summary["latest_byoc_operator_attestation"]["private_endpoint"])
                self.assertEqual(authority["dossier_id"], summary["latest_byoc_authority_dossier"]["dossier_id"])
                self.assertEqual(2, summary["latest_byoc_authority_dossier"]["covered_requirement_count"])
                self.assertGreater(summary["latest_byoc_authority_dossier"]["missing_requirement_count"], 0)
                self.assertFalse(summary["latest_byoc_authority_dossier"]["production_claimed"])
                self.assertFalse(summary["latest_byoc_authority_dossier"]["production_ready"])

                self.assertEqual(operator_entry["payload"]["attestation_id"], evidence["byoc_operator_attestations"][0]["attestation_id"])
                self.assertEqual("operator:trustai/byoc", evidence["byoc_operator_attestations"][0]["operator_ref"])
                self.assertEqual(authority_entry["payload"]["dossier_id"], evidence["byoc_authority_dossiers"][0]["dossier_id"])
                self.assertEqual(operator["attestation_id"], evidence["byoc_authority_dossiers"][0]["byoc_operator_attestation_id"])
                self.assertEqual(2, evidence["byoc_authority_dossiers"][0]["fresh_evidence_count"])
                self.assertEqual(0, evidence["byoc_authority_dossiers"][0]["authority_artifact_count"])
                self.assertEqual(evidence, roadmap["byoc_evidence"])
                self.assertEqual(authority["dossier_id"], generic_authority[0]["dossier_id"])
                self.assertEqual("deployment.byoc_production_authority_recorded", generic_authority[0]["entry_type"])
            finally:
                control.close()

    def test_indexes_multi_agent_delegation_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="multi-agent-control")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            inventory_entries = append_inventory(chain, load_inventory(INVENTORY))
            delegation = load_delegation(DELEGATION)
            delegation_entry = append_delegation(chain, delegation)
            graph = build_delegation_graph(
                chain,
                contract_hash=delegation["contract_hash"],
                root_agent="aitrade-risk-agent",
                generated_at="2026-07-03T12:03:00Z",
            )
            graph_entry = append_delegation_graph(chain, graph, source_chain=chain)
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.multi_agent_evidence()
                roadmap = control.roadmap_evidence()
                contract_evidence = control.contract_evidence(contract_id=contract["id"])
                parent_evidence = control.agent_evidence(
                    agent_name="aitrade-risk-agent",
                    agent_version=delegation["parent_agent"]["version"],
                )
                child_evidence = control.agent_evidence(
                    agent_name="aitrade-news-summarizer",
                    agent_version=delegation["child_agent"]["version"],
                )

                self.assertEqual(2, len(inventory_entries))
                self.assertEqual(1, indexed["agent_delegations"])
                self.assertEqual(1, indexed["agent_delegation_graphs"])
                self.assertEqual(1, summary["counts"]["agent_delegations"])
                self.assertEqual(1, summary["counts"]["agent_delegation_graphs"])

                latest_delegation = summary["latest_agent_delegation"]
                self.assertEqual(delegation_entry["payload"]["delegation_hash"], latest_delegation["delegation_hash"])
                self.assertEqual("aitrade-risk-agent@" + delegation["parent_agent"]["version"], latest_delegation["parent_agent_ref"])
                self.assertEqual("aitrade-news-summarizer@" + delegation["child_agent"]["version"], latest_delegation["child_agent_ref"])

                latest_graph = summary["latest_agent_delegation_graph"]
                self.assertEqual(graph_entry["payload"]["delegation_graph_id"], latest_graph["delegation_graph_id"])
                self.assertEqual(2, latest_graph["node_count"])
                self.assertEqual(1, latest_graph["edge_count"])
                self.assertFalse(latest_graph["cycle_detected"])
                self.assertEqual(["aitrade-risk-agent@" + delegation["parent_agent"]["version"]], latest_graph["root_agents"])
                self.assertEqual([delegation["contract_hash"]], latest_graph["contract_hashes"])

                self.assertEqual(delegation_entry["payload"]["delegation_hash"], evidence["agent_delegations"][0]["delegation_hash"])
                self.assertEqual(delegation["scope"], evidence["agent_delegations"][0]["scope"])
                self.assertEqual(graph_entry["payload"]["delegation_graph_id"], evidence["agent_delegation_graphs"][0]["delegation_graph_id"])
                self.assertEqual(graph["summary"], evidence["agent_delegation_graphs"][0]["summary"])
                self.assertEqual(evidence, roadmap["multi_agent_evidence"])

                self.assertEqual(1, contract_evidence["counts"]["agent_delegations"])
                self.assertEqual(1, contract_evidence["counts"]["agent_delegation_graphs"])
                self.assertEqual(delegation_entry["payload"]["delegation_hash"], contract_evidence["agent_delegations"][0]["delegation_hash"])
                self.assertEqual(graph_entry["payload"]["delegation_graph_id"], contract_evidence["agent_delegation_graphs"][0]["delegation_graph_id"])

                self.assertEqual(1, parent_evidence["counts"]["agent_delegations"])
                self.assertEqual(1, parent_evidence["counts"]["agent_delegation_graphs"])
                self.assertEqual(1, child_evidence["counts"]["agent_delegations"])
                self.assertEqual(delegation_entry["payload"]["delegation_hash"], child_evidence["agent_delegations"][0]["delegation_hash"])
            finally:
                control.close()

    def test_indexes_standards_and_auditor_ecosystem_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="standards-auditor-control")
            standards_helper = standards_status_fixtures.StandardsBodyStatusTests(
                methodName="test_standards_body_status_verifies_and_appends"
            )
            standards, conformance, release, submission = standards_helper._sources()
            submission_entry = append_standards_body_submission_receipt(
                chain,
                submission,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )
            status_receipt = build_standards_body_status_receipt(
                submission,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
                new_status="acknowledged",
                docket_ref="LF-TRUSTAI-DKT-2026-001",
                status_ref="LF-TRUSTAI-DKT-2026-001:ack",
                actor_ref="oidc:standards.example/chair-1",
                actor_role="working-group-chair",
                reason="Submission accepted into the working-group intake docket.",
                evidence_refs=["mail:trustai-wg/2026-07-18"],
                decided_at="2026-07-18T00:00:00Z",
                effective_at="2026-07-18T01:00:00Z",
            )
            status_entry = append_standards_body_status_receipt(
                chain,
                status_receipt,
                submission_receipt=submission,
                standards_package=standards,
                verifier_release=release,
                conformance_report=conformance,
                root=ROOT,
            )

            auditor_helper = auditor_governance_fixtures.AuditorProgramGovernanceTests(
                methodName="test_auditor_program_governance_verifies_and_appends"
            )
            pack, disclosure, auditor_standards, kit = auditor_helper._sources(tmp)
            governance_receipt = build_auditor_program_governance_receipt(
                kit,
                standards_package=auditor_standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
                program_ref="TRUSTAI-AUDITOR-0.1",
                governance_ref="TRUSTAI-AUD-GOV-2026-001",
                governance_mode="local-reference",
                operator_ref="oidc:trustai.example/program-operator",
                issued_at="2026-07-14T00:00:00Z",
                effective_at="2026-07-14T01:00:00Z",
            )
            governance_entry = append_auditor_program_governance_receipt(
                chain,
                governance_receipt,
                certification_kit=kit,
                standards_package=auditor_standards,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                root=ROOT,
            )
            accreditation_receipt = build_auditor_accreditation_receipt(
                kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=auditor_standards,
                root=ROOT,
                auditor_name="Ada Audit",
                auditor_ref="oidc:auditor.example/ada",
                auditor_organization="Example AI Audit LLP",
                credential_id="TA-AUD-2026-001",
                status="active",
                score_percent=100,
                proctor_ref="oidc:trustai.example/proctor-1",
                evidence_refs=["exam:TA-AUD-2026-001"],
                issued_at="2026-07-15T00:00:00Z",
                expires_at="2027-07-15T00:00:00Z",
            )
            accreditation_entry = append_auditor_accreditation_receipt(
                chain,
                accreditation_receipt,
                certification_kit=kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=auditor_standards,
                root=ROOT,
            )

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.standards_auditor_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(2, indexed["standards_body_evidence"])
                self.assertEqual(2, indexed["auditor_ecosystem_evidence"])
                self.assertEqual(status_receipt["status_id"], summary["latest_standards_body_evidence"]["artifact_id"])
                self.assertEqual("standards-body-status", summary["latest_standards_body_evidence"]["artifact_kind"])
                self.assertEqual("acknowledged", summary["latest_standards_body_evidence"]["status"])
                self.assertEqual(accreditation_receipt["accreditation_id"], summary["latest_auditor_ecosystem_evidence"]["artifact_id"])
                self.assertEqual("auditor-accreditation", summary["latest_auditor_ecosystem_evidence"]["artifact_kind"])
                self.assertEqual("active", summary["latest_auditor_ecosystem_evidence"]["status"])

                standards_rows = evidence["standards_body_evidence"]
                auditor_rows = evidence["auditor_ecosystem_evidence"]
                self.assertEqual(status_entry["payload"]["status_id"], standards_rows[0]["artifact_id"])
                self.assertEqual(submission_entry["payload"]["submission_id"], standards_rows[1]["artifact_id"])
                self.assertEqual(status_entry["payload"]["source_refs"], standards_rows[0]["source_artifacts"])
                self.assertEqual(accreditation_entry["payload"]["accreditation_id"], auditor_rows[0]["artifact_id"])
                self.assertEqual(governance_entry["payload"]["program_id"], auditor_rows[1]["artifact_id"])
                self.assertEqual(accreditation_entry["payload"]["source_refs"], auditor_rows[0]["source_artifacts"])
                self.assertEqual(evidence, roadmap["standards_auditor_evidence"])
            finally:
                control.close()


    def test_indexes_trust_network_procurement_marketplace_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "trust-network-chain.json", tenant_id="trust-network-test")
            entries = [
                (
                    PROCUREMENT_CLAUSE_ENTRY_TYPE,
                    "proc-clause-001",
                    "procurement-clause",
                    "2026-07-10T00:00:00Z",
                    {
                        "receipt_id": "proc-clause-001",
                        "receipt_hash": "sha256:proc-clause",
                        "buyer": {"ref": "buyer:bank"},
                        "contract": {"contract_ref": "contract:aitrade", "status": "approved"},
                        "requirements": [{"id": "proof-pack-retention"}],
                        "source_refs": ["docs/specs/procurement-clause-v0.1.md"],
                        "controls": {"clause-bound": "passed"},
                        "issued_at": "2026-07-10T00:00:00Z",
                    },
                ),
                (
                    PROCUREMENT_INTEGRATION_ENTRY_TYPE,
                    "proc-int-001",
                    "procurement-integration",
                    "2026-07-10T01:00:00Z",
                    {
                        "integration_id": "proc-int-001",
                        "integration_hash": "sha256:proc-int",
                        "mode": "production-sync",
                        "procurement_system": {"system_ref": "procurement:coupa"},
                        "request": {"request_ref": "request:coupa/aitrade"},
                        "response": {"response_ref": "response:coupa/aitrade", "status": "accepted"},
                        "source_refs": ["docs/specs/procurement-integration-v0.1.md"],
                        "controls": {"integration-delivered": "passed"},
                        "delivered_at": "2026-07-10T01:00:00Z",
                    },
                ),
                (
                    TRUST_NETWORK_REGISTRY_ENTRY_TYPE,
                    "tn-registry-001",
                    "trust-network-registry",
                    "2026-07-10T02:00:00Z",
                    {
                        "registration_id": "tn-registry-001",
                        "registration_hash": "sha256:tn-registry",
                        "registry": {"registry_ref": "registry:trust-network"},
                        "registration": {"registration_ref": "registration:trustai", "status": "active"},
                        "vendor": {"subject_ref": "vendor:trustai", "name": "TrustAI"},
                        "trust_network": {"registry_ref": "registry:trust-network"},
                        "procurement": {"marketplace_ref": "marketplace:agent-trust"},
                        "source_refs": ["docs/specs/trust-network-v0.1.md"],
                        "controls": {"registry-published": "passed"},
                        "published_at": "2026-07-10T02:00:00Z",
                    },
                ),
                (
                    TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE,
                    "tn-status-001",
                    "trust-network-registry-status",
                    "2026-07-10T03:00:00Z",
                    {
                        "status_id": "tn-status-001",
                        "status_hash": "sha256:tn-status",
                        "target_registration": {"registration_ref": "registration:trustai"},
                        "status_update": {"status_ref": "status:registration/active", "new_status": "active"},
                        "source_refs": ["docs/specs/trust-network-status-v0.1.md"],
                        "controls": {"status-recorded": "passed"},
                        "decided_at": "2026-07-10T03:00:00Z",
                    },
                ),
                (
                    MARKETPLACE_DISTRIBUTION_ENTRY_TYPE,
                    "market-dist-001",
                    "marketplace-distribution",
                    "2026-07-10T04:00:00Z",
                    {
                        "distribution_id": "market-dist-001",
                        "distribution_hash": "sha256:market-dist",
                        "distribution_ref": "distribution:agent-trust/aitrade",
                        "mode": "subscriber-distribution",
                        "channel": {"channel_ref": "marketplace:agent-trust"},
                        "subscriber": {"subscriber_ref": "subscriber:enterprise"},
                        "catalog": {"catalog_ref": "catalog:trustai"},
                        "source_artifacts": [{"path": "artifacts/marketplace-distribution.json"}],
                        "controls": {"distribution-published": "passed"},
                        "distributed_at": "2026-07-10T04:00:00Z",
                    },
                ),
                (
                    MARKETPLACE_AUTHOR_ENTRY_TYPE,
                    "market-author-001",
                    "marketplace-author-governance",
                    "2026-07-10T05:00:00Z",
                    {
                        "governance_id": "market-author-001",
                        "governance_hash": "sha256:market-author",
                        "mode": "production-governance",
                        "catalog": {"catalog_ref": "catalog:trustai"},
                        "distribution": {"distribution_ref": "distribution:agent-trust/aitrade"},
                        "author": {"subject_ref": "author:trustai"},
                        "identity": {"subject_ref": "vendor:trustai"},
                        "source_artifacts": [{"path": "artifacts/marketplace-author.json"}],
                        "control_summary": {"author-governance": "passed"},
                        "issued_at": "2026-07-10T05:00:00Z",
                    },
                ),
                (
                    MARKETPLACE_SETTLEMENT_ENTRY_TYPE,
                    "market-settle-001",
                    "marketplace-settlement",
                    "2026-07-10T06:00:00Z",
                    {
                        "settlement_id": "market-settle-001",
                        "settlement_hash": "sha256:market-settle",
                        "mode": "billing-settlement",
                        "settlement": {"settlement_ref": "settlement:agent-trust/aitrade", "status": "closed"},
                        "invoice": {"status": "paid"},
                        "payout": {"status": "paid"},
                        "source_artifacts": [{"path": "artifacts/marketplace-settlement.json"}],
                        "control_summary": {"settlement-recorded": "passed"},
                        "issued_at": "2026-07-10T06:00:00Z",
                    },
                ),
                (
                    TRUST_NETWORK_SERVICE_ENTRY_TYPE,
                    "tn-service-001",
                    "trust-network-service-attestation",
                    "2026-07-10T07:00:00Z",
                    {
                        "attestation_id": "tn-service-001",
                        "attestation_hash": "sha256:tn-service",
                        "mode": "production-service",
                        "environment": "aitrade-prod",
                        "service": {"service_ref": "service:trust-network", "status": "attested"},
                        "registry": {"registry_ref": "registry:trust-network"},
                        "marketplace": {"marketplace_ref": "marketplace:agent-trust"},
                        "source": {"source_artifacts": [{"path": "artifacts/trust-network-service.json"}]},
                        "control_status_summary": {"service-attested": "passed"},
                        "attested_at": "2026-07-10T07:00:00Z",
                    },
                ),
                (
                    TRUST_NETWORK_WORKER_ENTRY_TYPE,
                    "tn-worker-001",
                    "trust-network-worker",
                    "2026-07-10T08:00:00Z",
                    {
                        "worker_operation_id": "tn-worker-001",
                        "worker_operation_hash": "sha256:tn-worker",
                        "mode": "registry-propagation",
                        "environment": "aitrade-prod",
                        "service": {"service_ref": "service:trust-network"},
                        "registry": {"registry_ref": "registry:trust-network"},
                        "marketplace": {"marketplace_ref": "marketplace:agent-trust"},
                        "worker": {"worker_ref": "worker:trust-network", "status": "recorded"},
                        "scheduler": {"run_ref": "run:trust-network/001"},
                        "source": {"source_refs": ["artifacts/trust-network-worker.json"]},
                        "control_status_summary": {"worker-recorded": "passed"},
                        "recorded_at": "2026-07-10T08:00:00Z",
                    },
                ),
                (
                    TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE,
                    "tn-bundle-001",
                    "trust-network-worker-bundle",
                    "2026-07-10T09:00:00Z",
                    {
                        "bundle_id": "tn-bundle-001",
                        "bundle_hash": "sha256:tn-bundle",
                        "mode": "reviewer-bundle",
                        "environment": "aitrade-prod",
                        "reviewer_ref": "reviewer:enterprise",
                        "bundle_ref": "bundle:trust-network/aitrade",
                        "source": {"source_artifacts": [{"path": "artifacts/trust-network-worker-bundle.json"}]},
                        "summary": {"status": "exported"},
                        "control_summary": {"bundle-exported": "passed"},
                        "generated_at": "2026-07-10T09:00:00Z",
                    },
                ),
                (
                    TRUST_NETWORK_AUTHORITY_ENTRY_TYPE,
                    "tn-authority-001",
                    "trust-network-authority",
                    "2026-07-10T10:00:00Z",
                    {
                        "dossier_id": "tn-authority-001",
                        "dossier_hash": "sha256:tn-authority",
                        "mode": "production-dossier",
                        "environment": "aitrade-prod",
                        "dossier_ref": "dossier:trust-network/aitrade",
                        "authority_ref": "authority:trust-network/aitrade",
                        "producer_ref": "producer:trust-network-authority",
                        "service_attestation_binding": {"service_ref": "service:trust-network"},
                        "summary": {"status": "ready"},
                        "control_summary": {"authority-ready": "passed"},
                        "authority_evidence": [{"authority_kind": "hosted-service", "status": "fresh"}],
                        "generated_at": "2026-07-10T10:00:00Z",
                    },
                ),
            ]

            for entry_type, _artifact_id, _artifact_kind, timestamp, payload in entries:
                chain.append(entry_type, payload, timestamp=timestamp)
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.trust_network_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(len(entries), indexed["trust_network_evidence"])
                self.assertEqual(len(entries), summary["counts"]["trust_network_evidence"])
                self.assertEqual("tn-authority-001", summary["latest_trust_network_evidence"]["artifact_id"])
                self.assertEqual("trust-network-authority", summary["latest_trust_network_evidence"]["artifact_kind"])

                rows = evidence["trust_network_evidence"]
                self.assertEqual(len(entries), len(rows))
                self.assertEqual("tn-authority-001", rows[0]["artifact_id"])
                self.assertEqual("proc-clause-001", rows[-1]["artifact_id"])
                self.assertEqual(
                    {artifact_kind for _entry_type, _artifact_id, artifact_kind, _timestamp, _payload in entries},
                    {row["artifact_kind"] for row in rows},
                )

                clause = next(row for row in rows if row["artifact_id"] == "proc-clause-001")
                self.assertEqual(["docs/specs/procurement-clause-v0.1.md"], clause["source_artifacts"])
                self.assertEqual(1, clause["source_artifact_count"])
                self.assertEqual(1, clause["control_count"])
                self.assertEqual("buyer:bank", clause["party_ref"])

                service = next(row for row in rows if row["artifact_id"] == "tn-service-001")
                self.assertEqual("service:trust-network", service["service_ref"])
                self.assertEqual("registry:trust-network", service["registry_ref"])
                self.assertEqual("marketplace:agent-trust", service["marketplace_ref"])
                self.assertEqual(1, service["source_artifact_count"])

                authority = rows[0]
                self.assertEqual("service:trust-network", authority["service_ref"])
                self.assertEqual("dossier:trust-network/aitrade", authority["artifact_ref"])
                self.assertEqual(evidence, roadmap["trust_network_evidence"])
            finally:
                control.close()


    def test_indexes_provider_delivery_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "provider-delivery-chain.json", tenant_id="provider-delivery-test")
            entries = [
                (
                    PROVIDER_DELIVERY_ENTRY_TYPE,
                    "delivery-001",
                    "provider-delivery",
                    "2026-07-08T05:00:00Z",
                    {
                        "delivery_id": "delivery-001",
                        "delivery_hash": "sha256:delivery",
                        "provider": "github",
                        "mode": "recorded-response",
                        "payload_hash": "sha256:payload",
                        "pack_id": "pack:aitrade",
                        "contract_id": "contract:aitrade",
                        "contract_hash": "sha256:contract",
                        "request": {"method": "POST", "path": "/repos/volelabs/trust_ai/check-runs"},
                        "target_url": "https://api.github.com/repos/volelabs/trust_ai/check-runs",
                        "response": {"status": 201, "accepted": True, "body_hash": "sha256:response"},
                        "payload_artifact": {"path": "artifacts/github-check-run-payload.json", "hash": "sha256:payload"},
                    },
                ),
                (
                    PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE,
                    "delivery-service-001",
                    "provider-delivery-service",
                    "2026-07-08T05:10:00Z",
                    {
                        "attestation_id": "delivery-service-001",
                        "attestation_hash": "sha256:delivery-service",
                        "mode": "provider-delivery-attested",
                        "environment": "aitrade-prod",
                        "attested_at": "2026-07-08T05:10:00Z",
                        "service": {"service_ref": "provider-delivery:trustai/github-prod", "provider": "github"},
                        "dispatch": {
                            "dispatch_worker_ref": "worker:provider-delivery/github",
                            "provider_endpoint_base": "https://api.github.com",
                            "source_target_url": "https://api.github.com/repos/volelabs/trust_ai/check-runs",
                        },
                        "source_artifacts": [{"path": "artifacts/provider-delivery-service-attestation.json"}],
                        "control_summary": {"service-attested": "passed"},
                    },
                ),
                (
                    PROVIDER_DELIVERY_WORKER_ENTRY_TYPE,
                    "delivery-worker-001",
                    "provider-delivery-worker",
                    "2026-07-08T05:15:01Z",
                    {
                        "worker_operation_id": "delivery-worker-001",
                        "worker_operation_hash": "sha256:delivery-worker",
                        "mode": "dispatch-worker",
                        "environment": "aitrade-prod",
                        "recorded_at": "2026-07-08T05:15:01Z",
                        "service": {"service_ref": "provider-delivery:trustai/github-prod", "provider": "github"},
                        "source_delivery": {
                            "delivery_id": "delivery-001",
                            "provider": "github",
                            "target_url": "https://api.github.com/repos/volelabs/trust_ai/check-runs",
                            "pack_id": "pack:aitrade",
                            "contract_id": "contract:aitrade",
                            "contract_hash": "sha256:contract",
                        },
                        "source": {"source_refs": ["artifacts/provider-delivery-worker.json"]},
                        "worker": {"worker_ref": "worker:provider-delivery/github", "success": True},
                        "dispatch": {
                            "destination_ref": "https://api.github.com/repos/volelabs/trust_ai/check-runs",
                            "response_status": 202,
                            "response_accepted": True,
                        },
                        "provider_response": {"status": 202, "accepted": True},
                        "control_status_summary": {"worker-recorded": "passed"},
                    },
                ),
                (
                    PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE,
                    "delivery-bundle-001",
                    "provider-delivery-worker-bundle",
                    "2026-07-08T05:17:00Z",
                    {
                        "bundle_id": "delivery-bundle-001",
                        "bundle_hash": "sha256:delivery-bundle",
                        "mode": "offline-review",
                        "environment": "aitrade-prod",
                        "generated_at": "2026-07-08T05:17:00Z",
                        "reviewer_ref": "reviewer:provider-delivery",
                        "bundle_ref": "bundle:provider-delivery/github",
                        "source": {"source_artifacts": [{"path": "artifacts/provider-delivery-worker-bundle.json"}]},
                        "summary": {"status": "exported"},
                        "control_summary": {"bundle-exported": "passed"},
                    },
                ),
                (
                    PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE,
                    "delivery-authority-001",
                    "provider-delivery-authority",
                    "2026-07-08T05:45:00Z",
                    {
                        "dossier_id": "delivery-authority-001",
                        "dossier_hash": "sha256:delivery-authority",
                        "mode": "provider-dossier",
                        "environment": "aitrade-prod",
                        "generated_at": "2026-07-08T05:45:00Z",
                        "dossier_ref": "dossier:provider-delivery/github-prod",
                        "authority_ref": "authority:provider-delivery/github-prod",
                        "producer_ref": "producer:provider-delivery-authority",
                        "service_attestation_binding": {"service_ref": "provider-delivery:trustai/github-prod"},
                        "worker_bundle_bindings": [{"bundle_ref": "bundle:provider-delivery/github"}],
                        "summary": {"status": "ready"},
                        "control_summary": {"authority-ready": "passed"},
                    },
                ),
            ]

            for entry_type, _artifact_id, _artifact_kind, timestamp, payload in entries:
                chain.append(entry_type, payload, timestamp=timestamp)
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.provider_delivery_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(len(entries), indexed["provider_delivery_evidence"])
                self.assertEqual(len(entries), summary["counts"]["provider_delivery_evidence"])
                self.assertEqual("delivery-authority-001", summary["latest_provider_delivery_evidence"]["artifact_id"])
                self.assertEqual("provider-delivery-authority", summary["latest_provider_delivery_evidence"]["artifact_kind"])

                rows = evidence["provider_delivery_evidence"]
                self.assertEqual(len(entries), len(rows))
                self.assertEqual("delivery-authority-001", rows[0]["artifact_id"])
                self.assertEqual("delivery-001", rows[-1]["artifact_id"])
                self.assertEqual(
                    {artifact_kind for _entry_type, _artifact_id, artifact_kind, _timestamp, _payload in entries},
                    {row["artifact_kind"] for row in rows},
                )

                delivery = next(row for row in rows if row["artifact_id"] == "delivery-001")
                self.assertEqual("github", delivery["provider"])
                self.assertEqual("pack:aitrade", delivery["pack_id"])
                self.assertEqual("sha256:contract", delivery["contract_hash"])
                self.assertEqual("https://api.github.com/repos/volelabs/trust_ai/check-runs", delivery["target_ref"])
                self.assertEqual(201, delivery["response_status"])
                self.assertTrue(delivery["success"])
                self.assertEqual(1, delivery["source_artifact_count"])

                service = next(row for row in rows if row["artifact_id"] == "delivery-service-001")
                self.assertEqual("provider-delivery:trustai/github-prod", service["service_ref"])
                self.assertEqual("worker:provider-delivery/github", service["worker_ref"])
                self.assertEqual("https://api.github.com", service["provider_endpoint"])
                self.assertEqual(1, service["control_count"])

                worker = next(row for row in rows if row["artifact_id"] == "delivery-worker-001")
                self.assertEqual(202, worker["response_status"])
                self.assertTrue(worker["success"])
                self.assertEqual("worker:provider-delivery/github", worker["worker_ref"])
                self.assertEqual("https://api.github.com/repos/volelabs/trust_ai/check-runs", worker["target_ref"])

                authority = rows[0]
                self.assertEqual("dossier:provider-delivery/github-prod", authority["artifact_ref"])
                self.assertEqual("authority:provider-delivery/github-prod", authority["authority_ref"])
                self.assertEqual("provider-delivery:trustai/github-prod", authority["service_ref"])
                self.assertEqual("bundle:provider-delivery/github", authority["bundle_ref"])
                self.assertEqual(evidence, roadmap["provider_delivery_evidence"])
            finally:
                control.close()

    def test_indexes_provider_operations_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "provider-operations-chain.json", tenant_id="provider-operations-test")
            entries = [
                (PROVIDER_INSTALLATION_ENTRY_TYPE, "provider-installation-001", "provider-installation", "2026-07-08T05:00:00Z", {"manifest_id": "provider-installation-001", "provider": "github", "mode": "oauth-app", "installed_at": "2026-07-08T05:00:00Z", "installation": {"installation_ref": "installation:github/trustai", "status": "installed"}, "control_summary": {"installation-registered": "passed"}}),
                (PROVIDER_INGRESS_ENTRY_TYPE, "provider-ingress-001", "provider-ingress", "2026-07-08T05:05:00Z", {"ingress_manifest_id": "provider-ingress-001", "ingress": {"ingress_ref": "ingress:github/webhooks", "provider": "github", "endpoint_ref": "https://trustai.example/webhooks/github", "status": "ready"}, "source_artifact_count": 2, "control_summary": {"tls-attested": "passed"}}),
                (PROVIDER_LIFECYCLE_ENTRY_TYPE, "provider-lifecycle-001", "provider-lifecycle", "2026-07-08T05:10:00Z", {"lifecycle_manifest_id": "provider-lifecycle-001", "generated_at": "2026-07-08T05:10:00Z", "lifecycle": {"lifecycle_ref": "lifecycle:github/app", "status": "active"}, "installation": {"installation_ref": "installation:github/trustai"}, "source_artifact_count": 1, "control_summary": {"lifecycle-active": "passed"}}),
                (PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE, "provider-lifecycle-operation-001", "provider-lifecycle-operation", "2026-07-08T05:15:00Z", {"operation_receipt_id": "provider-lifecycle-operation-001", "provider": "github", "mode": "credential-rotation", "environment": "aitrade-prod", "recorded_at": "2026-07-08T05:15:00Z", "operation": {"operation_ref": "operation:github/credential-rotation", "operation_kind": "credential_rotation", "status": "completed"}, "credential": {"credential_ref": "credential:github/app"}, "audit_log": {"audit_log_ref": "audit:github/lifecycle"}, "control_summary": {"operation-recorded": "passed"}}),
                (PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE, "provider-operations-service-001", "provider-operations-service", "2026-07-08T05:20:00Z", {"attestation_id": "provider-operations-service-001", "mode": "provider-operations-attested", "environment": "aitrade-prod", "attested_at": "2026-07-08T05:20:00Z", "source": {"source_artifacts": [{"path": "artifacts/provider-operations-service.json"}]}, "service": {"service_ref": "service:provider-operations/github", "provider": "github", "status": "ready"}, "operations": {"operation_kind": "provider_operations", "status": "ready"}, "operation_actor": {"credential": {"credential_ref": "credential:provider-operations/actor"}}, "audit_log": {"audit_log_ref": "audit:provider-operations/service"}, "control_summary": {"service-attested": "passed"}}),
                (PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE, "provider-operations-authority-001", "provider-operations-authority", "2026-07-08T05:25:00Z", {"dossier_id": "provider-operations-authority-001", "mode": "authority-dossier", "environment": "aitrade-prod", "generated_at": "2026-07-08T05:25:00Z", "dossier_ref": "dossier:provider-operations/github", "authority_ref": "authority:provider-operations/github", "service_attestation_binding": {"service_ref": "service:provider-operations/github"}, "summary": {"status": "ready"}, "control_summary": {"authority-ready": "passed"}}),
                (PROVIDER_WEBHOOK_ENTRY_TYPE, "provider-webhook-001", "provider-webhook", "2026-07-08T05:30:00Z", {"receipt_id": "provider-webhook-001", "provider": "github", "received_at": "2026-07-08T05:30:00Z", "webhook": {"webhook_ref": "webhook:github/check-run", "event_type": "check_run", "target_ref": "https://trustai.example/webhooks/github", "status": "verified"}, "payload_artifact": {"path": "artifacts/github-webhook-payload.json", "hash": "sha256:webhook"}, "verification": {"status": "passed"}}),
                (PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE, "provider-callback-storage-001", "provider-callback-storage", "2026-07-08T05:35:00Z", {"storage_manifest_id": "provider-callback-storage-001", "generated_at": "2026-07-08T05:35:00Z", "storage": {"mode": "ha-storage", "environment": "aitrade-prod", "storage_ref": "storage:provider-callbacks", "schema_ref": "schema:provider-callbacks/v1", "status": "ready"}, "source_artifact_count": 1, "control_summary": {"storage-ready": "passed"}}),
                (PROVIDER_CALLBACK_STORE_ENTRY_TYPE, "provider-callback-store-001", "provider-callback-store", "2026-07-08T05:40:00Z", {"store_manifest_id": "provider-callback-store-001", "generated_at": "2026-07-08T05:40:00Z", "database": {"engine": "sqlite", "store_ref": "store:provider-callbacks", "schema_version": "v1", "status": "ready"}, "operation_count": 3, "source_artifact_count": 1, "control_summary": {"store-ready": "passed"}}),
                (PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE, "provider-audit-correlation-001", "provider-audit-correlation", "2026-07-08T05:45:00Z", {"correlation_id": "provider-audit-correlation-001", "provider": "github", "correlated_at": "2026-07-08T05:45:00Z", "audit_log": {"audit_log_ref": "audit:github/provider"}, "audit_log_ref": "audit:github/provider", "source_receipts": ["provider-webhook-001"], "matches": [{"receipt_id": "provider-webhook-001"}]}),
                (PROVIDER_AUDIT_STREAM_ENTRY_TYPE, "provider-audit-stream-001", "provider-audit-stream", "2026-07-08T05:50:00Z", {"stream_receipt_id": "provider-audit-stream-001", "provider": "github", "mode": "audit-stream", "environment": "aitrade-prod", "recorded_at": "2026-07-08T05:50:00Z", "stream": {"stream_ref": "stream:github/audit", "status": "healthy"}, "audit_log": {"audit_log_ref": "audit:github/provider"}, "credential": {"credential_ref": "credential:github/audit"}, "control_summary": {"stream-recorded": "passed"}}),
                (PROVIDER_AUDIT_WORKER_ENTRY_TYPE, "provider-audit-worker-001", "provider-audit-worker", "2026-07-08T05:55:00Z", {"worker_operation_id": "provider-audit-worker-001", "provider": "github", "mode": "audit-worker", "environment": "aitrade-prod", "recorded_at": "2026-07-08T05:55:00Z", "worker": {"worker_ref": "worker:provider-audit/github", "status": "completed"}, "scheduler": {"run_ref": "run:provider-audit/github/001"}, "sources": {"source_refs": ["provider-audit-stream-001"], "audit_log_ref": "audit:github/provider"}, "credential": {"credential_ref": "credential:provider-audit/worker"}, "control_summary": {"worker-recorded": "passed"}}),
                (PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE, "provider-credential-custody-001", "provider-credential-custody", "2026-07-08T06:00:00Z", {"custody_id": "provider-credential-custody-001", "provider": "github", "mode": "kms-custody", "environment": "aitrade-prod", "issued_at": "2026-07-08T06:00:00Z", "credential": {"credential_ref": "credential:github/app"}, "custody": {"custody_ref": "custody:github/app", "status": "escrowed"}, "vault": {"vault_ref": "vault:kms/provider-credentials"}, "policy": {"status": "enforced"}, "source_artifacts": [{"path": "artifacts/provider-credential-custody.json"}], "control_summary": {"custody-enforced": "passed"}}),
                (PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE, "provider-approval-authority-001", "provider-approval-authority", "2026-07-08T06:05:00Z", {"dossier_id": "provider-approval-authority-001", "mode": "authority-dossier", "environment": "aitrade-prod", "generated_at": "2026-07-08T06:05:00Z", "dossier_ref": "dossier:provider-approval/github", "authority_ref": "authority:provider-approval/github", "source_binding": {"webhook_ref": "webhook:github/check-run", "provider_operations_authority_ref": "authority:provider-operations/github"}, "summary": {"status": "ready"}, "control_summary": {"approval-authority-ready": "passed"}}),
            ]

            for entry_type, _artifact_id, _artifact_kind, timestamp, payload in entries:
                chain.append(entry_type, payload, timestamp=timestamp)
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.provider_operations_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(len(entries), indexed["provider_operations_evidence"])
                self.assertEqual(len(entries), summary["counts"]["provider_operations_evidence"])
                self.assertEqual("provider-approval-authority-001", summary["latest_provider_operations_evidence"]["artifact_id"])
                self.assertEqual("provider-approval-authority", summary["latest_provider_operations_evidence"]["artifact_kind"])

                rows = evidence["provider_operations_evidence"]
                self.assertEqual(len(entries), len(rows))
                self.assertEqual("provider-approval-authority-001", rows[0]["artifact_id"])
                self.assertEqual("provider-installation-001", rows[-1]["artifact_id"])
                self.assertEqual({kind for _entry_type, _artifact_id, kind, _timestamp, _payload in entries}, {row["artifact_kind"] for row in rows})

                installation = next(row for row in rows if row["artifact_id"] == "provider-installation-001")
                self.assertEqual("github", installation["provider"])
                self.assertEqual("installation:github/trustai", installation["installation_ref"])
                self.assertEqual(1, installation["control_count"])

                ingress = next(row for row in rows if row["artifact_id"] == "provider-ingress-001")
                self.assertEqual("ingress:github/webhooks", ingress["artifact_ref"])
                self.assertEqual("https://trustai.example/webhooks/github", ingress["target_ref"])
                self.assertEqual(2, ingress["source_artifact_count"])

                operation = next(row for row in rows if row["artifact_id"] == "provider-lifecycle-operation-001")
                self.assertEqual("credential_rotation", operation["operation_kind"])
                self.assertEqual("credential:github/app", operation["credential_ref"])
                self.assertEqual("audit:github/lifecycle", operation["audit_ref"])

                service = next(row for row in rows if row["artifact_id"] == "provider-operations-service-001")
                self.assertEqual("service:provider-operations/github", service["service_ref"])
                self.assertEqual("provider_operations", service["operation_kind"])
                self.assertEqual("credential:provider-operations/actor", service["credential_ref"])
                self.assertEqual(1, service["source_artifact_count"])

                webhook = next(row for row in rows if row["artifact_id"] == "provider-webhook-001")
                self.assertEqual("check_run", webhook["operation_kind"])
                self.assertEqual("webhook:github/check-run", webhook["webhook_ref"])
                self.assertEqual("https://trustai.example/webhooks/github", webhook["target_ref"])

                callback_storage = next(row for row in rows if row["artifact_id"] == "provider-callback-storage-001")
                self.assertEqual("storage:provider-callbacks", callback_storage["callback_ref"])
                self.assertEqual("schema:provider-callbacks/v1", callback_storage["target_ref"])

                audit_worker = next(row for row in rows if row["artifact_id"] == "provider-audit-worker-001")
                self.assertEqual("worker:provider-audit/github", audit_worker["artifact_ref"])
                self.assertEqual("audit:github/provider", audit_worker["audit_ref"])
                self.assertEqual("credential:provider-audit/worker", audit_worker["credential_ref"])

                custody = next(row for row in rows if row["artifact_id"] == "provider-credential-custody-001")
                self.assertEqual("credential:github/app", custody["credential_ref"])
                self.assertEqual("custody:github/app", custody["artifact_ref"])

                approval_authority = rows[0]
                self.assertEqual("dossier:provider-approval/github", approval_authority["artifact_ref"])
                self.assertEqual("authority:provider-approval/github", approval_authority["authority_ref"])
                self.assertEqual("webhook:github/check-run", approval_authority["webhook_ref"])
                self.assertEqual(evidence, roadmap["provider_operations_evidence"])
            finally:
                control.close()

    def test_indexes_policy_backend_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "policy-backend-chain.json", tenant_id="policy-backend-test")
            entries = [
                (
                    POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE,
                    "policy-backend-enforcement-001",
                    "policy-backend-enforcement",
                    "2026-07-08T07:00:00Z",
                    {
                        "enforcement_id": "policy-backend-enforcement-001",
                        "mode": "enforced",
                        "environment": "aitrade-prod",
                        "enforced_at": "2026-07-08T07:00:00Z",
                        "backend": {"backend_ref": "backend:opa/prod", "engine": "opa", "response_status": 200},
                        "credential": {"credential_ref": "credential:policy-backend/client"},
                        "policy": {"policy_ref": "policy:trading-spend-cap"},
                        "action": {"action_ref": "action:trade/order-123"},
                        "decision": {"decision_ref": "decision:policy/local-123", "allowed": True, "outcome": "passed"},
                        "backend_decision": {"decision_ref": "decision:opa/prod-123", "allowed": True, "outcome": "allowed", "response_status": 200},
                        "policy_engine_receipt": {"receipt_id": "policy-engine-receipt-123", "policy_pack_id": "policy-pack:trading"},
                        "source_artifacts": [{"path": "artifacts/policy-backend-enforcement.json"}],
                        "control_summary": {"backend-allowed": "passed"},
                    },
                ),
                (
                    POLICY_BACKEND_SERVICE_ENTRY_TYPE,
                    "policy-backend-service-001",
                    "policy-backend-service",
                    "2026-07-08T07:05:00Z",
                    {
                        "attestation_id": "policy-backend-service-001",
                        "mode": "service-attested",
                        "environment": "aitrade-prod",
                        "attested_at": "2026-07-08T07:05:00Z",
                        "source": {"source_artifacts": [{"path": "artifacts/policy-backend-service.json"}]},
                        "enforcement": {"backend_ref": "backend:opa/prod", "action_ref": "action:trade/order-123"},
                        "service": {"service_ref": "service:policy-backend/opa", "engine": "opa", "status": "ready"},
                        "operation": {"status": "ready"},
                        "audit_log": {"audit_log_ref": "audit:policy-backend/service"},
                        "control_summary": {"service-ready": "passed"},
                    },
                ),
                (
                    POLICY_BACKEND_WORKER_ENTRY_TYPE,
                    "policy-backend-worker-001",
                    "policy-backend-worker",
                    "2026-07-08T07:10:00Z",
                    {
                        "worker_operation_id": "policy-backend-worker-001",
                        "mode": "worker-recorded",
                        "environment": "aitrade-prod",
                        "recorded_at": "2026-07-08T07:10:00Z",
                        "service": {"service_ref": "service:policy-backend/opa"},
                        "source_enforcement": {"backend_ref": "backend:opa/prod", "engine": "opa", "action_ref": "action:trade/order-123"},
                        "worker": {"worker_ref": "worker:policy-backend/opa", "status": "completed"},
                        "scheduler": {"run_ref": "run:policy-backend/worker/001"},
                        "execution": {"status": "completed"},
                        "observability": {"audit_log_ref": "audit:policy-backend/worker"},
                        "backend_credential": {"credential_ref": "credential:policy-backend/worker"},
                        "control_status_summary": {"worker-recorded": "passed"},
                    },
                ),
                (
                    POLICY_BACKEND_PROVIDER_ENTRY_TYPE,
                    "policy-backend-provider-001",
                    "policy-backend-provider-export",
                    "2026-07-08T07:15:00Z",
                    {
                        "provider_receipt_id": "policy-backend-provider-001",
                        "mode": "provider-exported",
                        "environment": "aitrade-prod",
                        "provider": {"provider_ref": "provider:github-actions", "status": "exported"},
                        "worker_operation_id": "policy-backend-worker-001",
                        "provider_export": {"provider_ref": "provider:github-actions", "export_ref": "export:policy-backend/provider/001", "status": "complete"},
                        "provider_exchange": {"response_status": 200},
                        "credential_ref": "credential:provider/policy-backend",
                        "matched_audit_record": {"audit_log_ref": "audit:policy-backend/provider"},
                        "controls_summary": {"provider-exported": "passed"},
                    },
                ),
                (
                    POLICY_BACKEND_PROVIDER_BUNDLE_ENTRY_TYPE,
                    "policy-backend-provider-bundle-001",
                    "policy-backend-provider-bundle",
                    "2026-07-08T07:20:00Z",
                    {
                        "bundle_id": "policy-backend-provider-bundle-001",
                        "mode": "review-bundle",
                        "environment": "aitrade-prod",
                        "generated_at": "2026-07-08T07:20:00Z",
                        "reviewer_ref": "auditor:internal/model-risk",
                        "bundle_ref": "bundle:policy-backend/provider/001",
                        "source": {"source_artifacts": [{"path": "artifacts/policy-backend-provider-bundle.json"}]},
                        "summary": {"status": "ready"},
                        "control_summary": {"bundle-ready": "passed"},
                    },
                ),
                (
                    POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE,
                    "policy-backend-service-bundle-001",
                    "policy-backend-service-bundle",
                    "2026-07-08T07:25:00Z",
                    {
                        "bundle_id": "policy-backend-service-bundle-001",
                        "mode": "service-review-bundle",
                        "environment": "aitrade-prod",
                        "generated_at": "2026-07-08T07:25:00Z",
                        "reviewer_ref": "auditor:internal/model-risk",
                        "bundle_ref": "bundle:policy-backend/service/001",
                        "source": {"source_artifacts": [{"path": "artifacts/policy-backend-service-bundle.json"}]},
                        "summary": {"status": "ready"},
                        "control_summary": {"service-bundle-ready": "passed"},
                    },
                ),
                (
                    POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
                    "policy-backend-authority-bundle-001",
                    "policy-backend-authority-evidence-bundle",
                    "2026-07-08T07:28:00Z",
                    {
                        "bundle_id": "policy-backend-authority-bundle-001",
                        "bundle_hash": "sha256:policy-backend-authority-bundle-hash",
                        "mode": "production-export",
                        "environment": "aitrade-prod",
                        "generated_at": "2026-07-08T07:28:00Z",
                        "bundle_ref": "bundle:policy-backend/authority/001",
                        "authority_ref": "authority:policy-backend/opa-prod",
                        "summary": {"status": "ready", "covered_requirement_count": 12},
                        "control_summary": {"passed": 5},
                    },
                ),
                (
                    POLICY_BACKEND_AUTHORITY_ENTRY_TYPE,
                    "policy-backend-authority-001",
                    "policy-backend-authority",
                    "2026-07-08T07:30:00Z",
                    {
                        "dossier_id": "policy-backend-authority-001",
                        "mode": "authority-dossier",
                        "environment": "aitrade-prod",
                        "generated_at": "2026-07-08T07:30:00Z",
                        "dossier_ref": "dossier:policy-backend/opa-prod",
                        "authority_ref": "authority:policy-backend/opa-prod",
                        "producer_ref": "oidc:trustai.example/policy-backend-authority-worker",
                        "provider_bundle_binding": {"bundle_ref": "bundle:policy-backend/provider/001", "service_ref": "service:policy-backend/opa"},
                        "summary": {"status": "ready"},
                        "authority_evidence": [{"requirement_id": "policy-backend-provider-api", "authority_kind": "provider-api", "evidence_ref": "opa:decision-log/export", "evidence_hash": "sha256:policy-backend-provider-api"}],
                        "control_summary": {"authority-ready": "passed"},
                    },
                ),
            ]

            for entry_type, _artifact_id, _artifact_kind, timestamp, payload in entries:
                chain.append(entry_type, payload, timestamp=timestamp)
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.policy_backend_evidence()
                runtime = control.runtime_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(len(entries), indexed["policy_backend_evidence"])
                self.assertEqual(len(entries), summary["counts"]["policy_backend_evidence"])
                self.assertEqual("policy-backend-authority-001", summary["latest_policy_backend_evidence"]["artifact_id"])
                self.assertEqual("policy-backend-authority", summary["latest_policy_backend_evidence"]["artifact_kind"])

                rows = evidence["policy_backend_evidence"]
                self.assertEqual(len(entries), len(rows))
                self.assertEqual("policy-backend-authority-001", rows[0]["artifact_id"])
                self.assertEqual("policy-backend-enforcement-001", rows[-1]["artifact_id"])
                self.assertEqual({kind for _entry_type, _artifact_id, kind, _timestamp, _payload in entries}, {row["artifact_kind"] for row in rows})

                enforcement = next(row for row in rows if row["artifact_id"] == "policy-backend-enforcement-001")
                self.assertEqual("backend:opa/prod", enforcement["backend_ref"])
                self.assertEqual("opa", enforcement["engine"])
                self.assertEqual("policy:trading-spend-cap", enforcement["policy_ref"])
                self.assertEqual("action:trade/order-123", enforcement["action_ref"])
                self.assertEqual("decision:opa/prod-123", enforcement["decision_ref"])
                self.assertEqual("credential:policy-backend/client", enforcement["credential_ref"])
                self.assertEqual(200, enforcement["response_status"])
                self.assertIs(enforcement["allowed"], True)
                self.assertEqual(1, enforcement["source_artifact_count"])
                self.assertEqual(1, enforcement["control_count"])

                service = next(row for row in rows if row["artifact_id"] == "policy-backend-service-001")
                self.assertEqual("service:policy-backend/opa", service["service_ref"])
                self.assertEqual("audit:policy-backend/service", service["audit_ref"])

                worker = next(row for row in rows if row["artifact_id"] == "policy-backend-worker-001")
                self.assertEqual("worker:policy-backend/opa", worker["worker_ref"])
                self.assertEqual("credential:policy-backend/worker", worker["credential_ref"])

                provider = next(row for row in rows if row["artifact_id"] == "policy-backend-provider-001")
                self.assertEqual("provider:github-actions", provider["provider_ref"])
                self.assertEqual("export:policy-backend/provider/001", provider["artifact_ref"])
                self.assertEqual("credential:provider/policy-backend", provider["credential_ref"])

                authority_bundle = next(row for row in rows if row["artifact_id"] == "policy-backend-authority-bundle-001")
                self.assertEqual("policy-backend-authority-evidence-bundle", authority_bundle["artifact_kind"])
                self.assertEqual("bundle:policy-backend/authority/001", authority_bundle["artifact_ref"])
                self.assertEqual("bundle:policy-backend/authority/001", authority_bundle["bundle_ref"])
                self.assertEqual("authority:policy-backend/opa-prod", authority_bundle["authority_ref"])
                self.assertEqual(0, authority_bundle["source_artifact_count"])
                self.assertEqual(1, authority_bundle["control_count"])

                authority = rows[0]
                self.assertEqual("dossier:policy-backend/opa-prod", authority["artifact_ref"])
                self.assertEqual("authority:policy-backend/opa-prod", authority["authority_ref"])
                self.assertEqual(1, authority["source_artifact_count"])
                self.assertEqual(evidence, roadmap["policy_backend_evidence"])
                self.assertEqual(rows, runtime["policy_backend_evidence"])
                self.assertEqual(runtime, roadmap["runtime_evidence"])
            finally:
                control.close()

    def test_indexes_compliance_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "compliance-chain.json", tenant_id="compliance-test")
            compliance_payload = {
                "dossier_id": "compliance-authority-001",
                "dossier_hash": "sha256:compliance-authority-hash",
                "mode": "provider-dossier",
                "environment": "aitrade-prod",
                "generated_at": "2026-07-09T09:10:00Z",
                "dossier_ref": "dossier:compliance/aitrade-prod",
                "authority_ref": "authority:compliance/aitrade-prod",
                "producer_ref": "oidc:trustai.example/compliance-authority-worker",
                "source_binding": {
                    "compliance_export": {"pack_id": "pack-001", "export_hash": "sha256:compliance-export"},
                    "eu_ai_act_document": {"document_id": "eu-doc-001", "document_hash": "sha256:eu-doc"},
                    "proof_pack": {"pack_id": "pack-001", "pack_hash": "sha256:pack"},
                    "regulator_disclosure": {"disclosure_id": "disclosure-001", "disclosure_hash": "sha256:disclosure"},
                    "eu_data_plane": {"attestation_id": "eu-data-plane-001", "attestation_hash": "sha256:eu-data-plane", "data_plane_ref": "k8s:cluster/aitrade-eu-central-1"},
                },
                "summary": {
                    "required_requirement_count": 11,
                    "covered_requirement_count": 2,
                    "missing_requirement_count": 9,
                    "missing_requirement_ids": ["grc-platform-export"],
                },
                "control_summary": {"passed": 7, "deferred": 3},
                "authority_evidence": [
                    {"requirement_id": "framework-control-mapping-ontology", "authority_kind": "standards-body", "evidence_ref": "evidence:framework-controls"},
                    {"requirement_id": "eu-ai-act-technical-documentation", "authority_kind": "regulator", "evidence_ref": "evidence:eu-doc"},
                ],
            }
            data_plane_payload = {
                "attestation_id": "eu-data-plane-001",
                "attestation_hash": "sha256:eu-data-plane-hash",
                "mode": "eu-data-plane-attested",
                "environment": "aitrade-eu-prod",
                "attested_at": "2026-07-09T09:05:00Z",
                "source": {
                    "deployment_manifest_id": "deployment-001",
                    "byoc_attestation_id": "byoc-operator-001",
                    "byoc_tenant_id": "aitrade-eu",
                    "byoc_data_plane_ref": "k8s:cluster/aitrade-eu-central-1",
                    "eu_ai_act_document_id": "eu-doc-001",
                },
                "deployment": {"manifest_id": "deployment-001", "name": "trustai", "environment": "aitrade-eu-prod"},
                "regions": {"primary_region": "eu-central-1", "object_lock_region": "eu-central-1"},
                "residency": {"tenant_id": "aitrade-eu", "data_plane_ref": "k8s:cluster/aitrade-eu-central-1", "control_plane_ref": "trustai:control-plane/eu"},
                "sovereignty": {"kms_key_region": "eu-central-1", "encryption_key_ref": "kms:eu-central-1:trustai/aitrade-eu/evidence"},
                "audit": {"audit_log_ref": "audit-log:eu-data-plane/service", "access_log_ref": "access-log:eu-data-plane/sessions"},
                "operation": {"actor_ref": "oidc:trustai.example/eu-data-plane-operator", "evidence_refs": ["evidence:eu-data-plane/service"]},
                "source_artifacts": [
                    {"type": "deployment-manifest", "id": "deployment-001", "hash": "sha256:deployment"},
                    {"type": "byoc-operator-attestation", "id": "byoc-operator-001", "hash": "sha256:byoc"},
                    {"type": "eu-ai-act-document", "id": "eu-doc-001", "hash": "sha256:eu-doc"},
                ],
                "control_summary": {"sovereignty-attested": "passed", "residency-attested": "passed"},
            }
            chain.append(EU_DATA_PLANE_ENTRY_TYPE, data_plane_payload, timestamp=data_plane_payload["attested_at"])
            chain.append(COMPLIANCE_AUTHORITY_ENTRY_TYPE, compliance_payload, timestamp=compliance_payload["generated_at"])
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.compliance_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(2, indexed["compliance_evidence"])
                self.assertEqual(2, summary["counts"]["compliance_evidence"])
                self.assertEqual("compliance-authority-001", summary["latest_compliance_evidence"]["artifact_id"])
                self.assertEqual("compliance-production-authority", summary["latest_compliance_evidence"]["artifact_kind"])

                rows = evidence["compliance_evidence"]
                self.assertEqual(2, len(rows))
                rows_by_kind = {row["artifact_kind"]: row for row in rows}
                authority = rows_by_kind["compliance-production-authority"]
                data_plane = rows_by_kind["eu-data-plane-attestation"]

                self.assertEqual("provider-dossier", authority["mode"])
                self.assertEqual("eu-doc-001", authority["document_id"])
                self.assertEqual("pack-001", authority["pack_id"])
                self.assertEqual("disclosure-001", authority["disclosure_id"])
                self.assertEqual("k8s:cluster/aitrade-eu-central-1", authority["data_plane_ref"])
                self.assertEqual(11, authority["required_requirement_count"])
                self.assertEqual(2, authority["covered_requirement_count"])
                self.assertEqual(9, authority["missing_requirement_count"])
                self.assertEqual(2, authority["authority_evidence_count"])
                self.assertEqual(5, authority["source_artifact_count"])
                self.assertEqual(2, authority["control_count"])
                self.assertEqual("eu-doc-001", authority["source_binding"]["eu_ai_act_document"]["document_id"])
                self.assertEqual(7, authority["controls"]["passed"])
                self.assertEqual(["grc-platform-export"], authority["summary"]["missing_requirement_ids"])

                self.assertEqual("aitrade-eu", data_plane["tenant_id"])
                self.assertEqual("eu-central-1", data_plane["primary_region"])
                self.assertEqual("eu-central-1", data_plane["kms_key_region"])
                self.assertEqual("audit-log:eu-data-plane/service", data_plane["audit_ref"])
                self.assertEqual(3, data_plane["source_artifact_count"])
                self.assertEqual(2, data_plane["control_count"])
                self.assertEqual("eu-doc-001", data_plane["source_binding"]["eu_ai_act_document_id"])
                self.assertEqual(evidence, roadmap["compliance_evidence"])
            finally:
                control.close()
    def test_indexes_identity_provider_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            helper = identity_authority_fixtures.IdentityProviderAuthorityTests(
                methodName="test_identity_provider_authority_verifies_and_appends"
            )
            sources = helper._sources(tmp)
            dossier = helper._dossier(sources)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="identity-provider-lifecycle-test")
            vendor_entry = append_vendor_identity_receipt(
                chain,
                sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            attestation_entry = append_identity_provider_attestation(
                chain,
                sources["attestation"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            session_entry = append_identity_provider_session_receipt(
                chain,
                sources["session"],
                identity_provider_attestation=sources["attestation"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            operation_entry = append_identity_provider_lifecycle_operation_receipt(
                chain,
                sources["lifecycle_operation"],
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            worker_entry = append_identity_provider_lifecycle_worker_receipt(
                chain,
                sources["worker"],
                lifecycle_operation_receipt=sources["lifecycle_operation"],
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            authority_entry = append_identity_provider_authority_dossier(
                chain,
                dossier,
                worker_receipt=sources["worker"],
                lifecycle_operation_receipt=sources["lifecycle_operation"],
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )
            inventory_entries = append_inventory(chain, load_inventory(INVENTORY))
            delegation = load_delegation(DELEGATION)
            delegation_entry = append_delegation(chain, delegation)
            delegation_graph = build_delegation_graph(
                chain,
                contract_hash=delegation["contract_hash"],
                generated_at="2026-07-03T12:03:00Z",
            )
            delegation_graph_entry = append_delegation_graph(chain, delegation_graph, source_chain=chain)

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.identity_provider_evidence()
                combined = control.agent_inventory_identity_evidence()
                roadmap = control.roadmap_evidence()

                expected_counts = {
                    "vendor_identity_receipts": 1,
                    "identity_provider_attestations": 1,
                    "identity_provider_sessions": 1,
                    "identity_provider_lifecycle_operations": 1,
                    "identity_provider_lifecycle_workers": 1,
                    "identity_provider_authority_dossiers": 1,
                }
                for table, expected in expected_counts.items():
                    self.assertEqual(expected, indexed[table], table)
                    self.assertEqual(expected, summary["counts"][table], table)

                latest_vendor = summary["latest_vendor_identity_receipt"]
                self.assertEqual(vendor_entry["payload"]["receipt_id"], latest_vendor["receipt_id"])
                self.assertEqual("aitrade", latest_vendor["vendor_name"])
                self.assertEqual("okta-agent-aitrade-risk", latest_vendor["identity_id"])

                latest_attestation = summary["latest_identity_provider_attestation"]
                self.assertEqual(attestation_entry["payload"]["attestation_id"], latest_attestation["attestation_id"])
                self.assertEqual("okta", latest_attestation["provider"])
                self.assertEqual(sources["vendor"]["receipt_id"], latest_attestation["vendor_receipt_id"])

                latest_session = summary["latest_identity_provider_session"]
                self.assertEqual(session_entry["payload"]["session_id"], latest_session["session_id"])
                self.assertEqual("token_introspection", latest_session["event_kind"])
                self.assertTrue(latest_session["success"])

                latest_operation = summary["latest_identity_provider_lifecycle_operation"]
                self.assertEqual(operation_entry["payload"]["operation_id"], latest_operation["operation_id"])
                self.assertEqual("app_assignment", latest_operation["operation_kind"])
                self.assertTrue(latest_operation["success"])

                latest_worker = summary["latest_identity_provider_lifecycle_worker"]
                self.assertEqual(worker_entry["payload"]["worker_operation_id"], latest_worker["worker_operation_id"])
                self.assertEqual("worker:identity-provider/lifecycle/okta", latest_worker["worker_ref"])
                self.assertTrue(latest_worker["worker_success"])

                latest_authority = summary["latest_identity_provider_authority_dossier"]
                self.assertEqual(authority_entry["payload"]["dossier_id"], latest_authority["dossier_id"])
                self.assertEqual(2, latest_authority["covered_requirement_count"])
                self.assertEqual(len(dossier["summary"]["missing_requirement_ids"]), latest_authority["missing_requirement_count"])
                self.assertEqual(2, latest_authority["fresh_evidence_count"])
                self.assertFalse(latest_authority["production_claimed"])
                self.assertFalse(latest_authority["production_ready"])

                self.assertEqual(vendor_entry["payload"]["receipt_id"], evidence["vendor_identity_receipts"][0]["receipt_id"])
                self.assertEqual(attestation_entry["payload"]["attestation_id"], evidence["identity_provider_attestations"][0]["attestation_id"])
                self.assertEqual(session_entry["payload"]["session_id"], evidence["identity_provider_sessions"][0]["session_id"])
                self.assertEqual(operation_entry["payload"]["operation_id"], evidence["identity_provider_lifecycle_operations"][0]["operation_id"])
                self.assertEqual(worker_entry["payload"]["worker_operation_id"], evidence["identity_provider_lifecycle_workers"][0]["worker_operation_id"])
                self.assertEqual(authority_entry["payload"]["dossier_id"], evidence["identity_provider_authority_dossiers"][0]["dossier_id"])
                self.assertEqual(dossier["summary"], evidence["identity_provider_authority_dossiers"][0]["summary"])
                self.assertEqual(evidence, roadmap["identity_provider_evidence"])
                self.assertEqual(2, indexed["agents"])
                self.assertEqual(1, indexed["agent_delegations"])
                self.assertEqual(1, indexed["agent_delegation_graphs"])
                self.assertEqual(2, len(combined["agents"]))
                self.assertEqual({entry["payload"]["agent"]["name"] for entry in inventory_entries}, {agent["name"] for agent in combined["agents"]})
                self.assertEqual(evidence, combined["identity_provider_evidence"])
                self.assertEqual(delegation_entry["payload"]["delegation_hash"], combined["multi_agent_evidence"]["agent_delegations"][0]["delegation_hash"])
                self.assertEqual(delegation_graph_entry["payload"]["delegation_graph_id"], combined["multi_agent_evidence"]["agent_delegation_graphs"][0]["delegation_graph_id"])
                self.assertEqual(combined, roadmap["agent_inventory_identity_evidence"])
            finally:
                control.close()

    def test_indexes_insurer_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            helper = insurer_authority_fixtures.InsurerPartnerAuthorityTests(
                methodName="test_insurer_partner_authority_verifies_and_appends"
            )
            sources, service, workers, dossier = helper._dossier(tmp)
            verify_kwargs = helper._verify_source_kwargs(sources)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="insurer-control")
            quote_entry = append_underwriting_quote(chain, sources["quote"])
            authority_entry = append_insurer_partner_authority_dossier(
                chain,
                dossier,
                service_attestation=service,
                worker_receipts=workers,
                **verify_kwargs,
            )

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.insurer_evidence()
                roadmap = control.roadmap_evidence()

                self.assertEqual(1, indexed["underwriting_quotes"])
                self.assertEqual(1, indexed["insurer_partner_authority_dossiers"])
                self.assertEqual(1, summary["counts"]["underwriting_quotes"])
                self.assertEqual(1, summary["counts"]["insurer_partner_authority_dossiers"])

                latest_quote = summary["latest_underwriting_quote"]
                self.assertEqual(quote_entry["payload"]["quote_id"], latest_quote["quote_id"])
                self.assertEqual(sources["quote"]["quote"]["quote_ref"], latest_quote["quote_ref"])
                self.assertEqual(sources["quote"]["quote"]["quoted_premium_usd"], latest_quote["quoted_premium_usd"])
                self.assertEqual(sources["quote"]["quote"]["discount_percent"], latest_quote["discount_percent"])
                self.assertTrue(latest_quote["consent_active"])
                self.assertEqual(sources["telemetry"]["risk_tier"], latest_quote["risk_tier"])

                latest_authority = summary["latest_insurer_partner_authority_dossier"]
                self.assertEqual(authority_entry["payload"]["dossier_id"], latest_authority["dossier_id"])
                self.assertEqual(service["attestation_id"], latest_authority["service_attestation_id"])
                self.assertEqual(sources["quote"]["quote_id"], latest_authority["quote_id"])
                self.assertEqual(1, latest_authority["worker_receipt_count"])
                self.assertEqual(1, latest_authority["worker_bundle_count"])
                self.assertEqual(2, latest_authority["covered_requirement_count"])
                self.assertEqual(len(dossier["summary"]["missing_requirement_ids"]), latest_authority["missing_requirement_count"])
                self.assertEqual(2, latest_authority["fresh_evidence_count"])
                self.assertFalse(latest_authority["production_claimed"])
                self.assertFalse(latest_authority["production_ready"])

                self.assertEqual(quote_entry["payload"]["quote_id"], evidence["underwriting_quotes"][0]["quote_id"])
                self.assertEqual(sources["quote"]["risk_evidence"], evidence["underwriting_quotes"][0]["risk_evidence"])
                self.assertEqual(authority_entry["payload"]["dossier_id"], evidence["insurer_partner_authority_dossiers"][0]["dossier_id"])
                self.assertEqual(service["attestation_id"], evidence["insurer_partner_authority_dossiers"][0]["service_attestation_id"])
                self.assertEqual(dossier["summary"], evidence["insurer_partner_authority_dossiers"][0]["summary"])
                self.assertEqual(evidence, roadmap["insurer_evidence"])
            finally:
                control.close()

    def test_indexes_framework_adapter_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="framework-adapter-control")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            matrix = build_framework_adapter_matrix(
                load_framework_adapter_matrix_source(FRAMEWORK_MATRIX),
                root=ROOT,
                issued_at="2026-07-09T00:00:00Z",
            )
            release = build_framework_hook_release(
                load_framework_hook_release_source(FRAMEWORK_HOOK_RELEASE),
                matrix,
                root=ROOT,
                released_at="2026-07-09T00:30:00Z",
            )
            trace = load_framework_trace_payload(FRAMEWORK_TRACES)
            operation = build_framework_hook_operation(
                trace,
                release,
                matrix,
                framework="langgraph",
                trace_id="lg-trace-001",
                root=ROOT,
                mode="collector-observed",
                environment="aitrade-prod",
                operation_ref="framework-hook-operation:aitrade/langgraph/lg-trace-001",
                runtime_instance_ref="runtime:aitrade/langgraph/prod-worker-1",
                runtime_process_ref="pid:4242",
                collector_service_ref="collector:trustai/otel-prod",
                collector_worker_ref="worker-run:collector/framework-hook/lg-trace-001",
                stream_message_ref="stream-message:collector/framework-hook/lg-trace-001",
                audit_log_ref="audit-log:framework-hooks/aitrade",
                audit_log_root="sha256:framework-hook-operation-audit-root",
                actor_ref="oidc:trustai.example/framework-hook-runtime",
                credential_ref="env:FRAMEWORK_HOOK_TOKEN",
                evidence_refs=["evidence:framework-hook/lg-trace-001"],
                captured_at="2026-07-09T00:40:00Z",
            )
            authority = build_framework_adapter_authority_dossier(
                matrix,
                release,
                root=ROOT,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:framework-adapter-authority/aitrade-prod",
                authority_ref="authority:framework-adapter/aitrade-prod",
                producer_ref="oidc:trustai.example/framework-adapter-authority-worker",
                authority_evidence=[
                    {
                        "requirement_id": "exact-runtime-release-matrix",
                        "authority_kind": "ci-run",
                        "evidence_ref": "ci:framework-adapter-matrix/nightly/aitrade-prod",
                        "evidence_hash": "sha256:framework-adapter-matrix-ci-run",
                        "description": "Nightly adapter matrix replay export for exact framework runtime versions.",
                        "issuer": "TrustAI CI",
                        "subject": "aitrade-prod framework adapter matrix",
                        "source_uri": "https://ci.example/trustai/framework-adapter-matrix/aitrade-prod",
                        "issued_at": "2026-07-09T00:45:00Z",
                        "expires_at": "2026-12-31T00:00:00Z",
                    },
                    {
                        "requirement_id": "native-hook-package-provenance",
                        "authority_kind": "ci-run",
                        "evidence_ref": "ci:framework-hook-release/provenance/0.1.0",
                        "evidence_hash": "sha256:framework-hook-release-provenance",
                        "description": "Hook package build provenance and source artifact attestation.",
                        "issuer": "TrustAI CI",
                        "subject": "trustai-framework-hooks 0.1.0",
                        "source_uri": "https://ci.example/trustai/framework-hook-release/0.1.0",
                        "issued_at": "2026-07-09T00:46:00Z",
                        "expires_at": "2026-12-31T00:00:00Z",
                    },
                ],
                generated_at="2026-07-09T01:05:00Z",
            )
            matrix_entry = append_framework_adapter_matrix(chain, matrix, root=ROOT)
            release_entry = append_framework_hook_release(chain, release, matrix, root=ROOT)
            operation_entry = append_framework_hook_operation(chain, operation, trace, release, matrix, root=ROOT)
            authority_entry = append_framework_adapter_authority_dossier(chain, authority, matrix=matrix, release=release, root=ROOT)
            chain.save()

            contract_hash = content_hash(contract)
            self.assertEqual(contract_hash, operation["trace"]["contract_hashes"][0])

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                evidence = control.framework_adapter_evidence()
                roadmap = control.roadmap_evidence()
                contract_evidence = control.contract_evidence(contract_id=contract["id"])
                agent_evidence = control.agent_evidence(
                    agent_name=contract["agent"]["name"],
                    agent_version=contract["agent"]["version"],
                )

                self.assertEqual(1, indexed["framework_adapter_matrices"])
                self.assertEqual(1, indexed["framework_hook_releases"])
                self.assertEqual(1, indexed["framework_hook_operations"])
                self.assertEqual(1, indexed["framework_adapter_authority_dossiers"])
                self.assertEqual(1, summary["counts"]["framework_adapter_matrices"])
                self.assertEqual(1, summary["counts"]["framework_hook_releases"])
                self.assertEqual(1, summary["counts"]["framework_hook_operations"])
                self.assertEqual(1, summary["counts"]["framework_adapter_authority_dossiers"])
                self.assertEqual(matrix["matrix_id"], summary["latest_framework_adapter_matrix"]["matrix_id"])
                self.assertEqual(release["release_id"], summary["latest_framework_hook_release"]["release_id"])
                self.assertEqual(operation["operation_id"], summary["latest_framework_hook_operation"]["operation_id"])
                self.assertEqual(authority["dossier_id"], summary["latest_framework_adapter_authority_dossier"]["dossier_id"])
                self.assertFalse(summary["latest_framework_adapter_authority_dossier"]["production_claimed"])

                self.assertEqual(matrix_entry["payload"]["matrix_id"], evidence["framework_adapter_matrices"][0]["matrix_id"])
                self.assertIn("langgraph", evidence["framework_adapter_matrices"][0]["frameworks"])
                self.assertEqual(release_entry["payload"]["release_id"], evidence["framework_hook_releases"][0]["release_id"])
                self.assertEqual(matrix["matrix_id"], evidence["framework_hook_releases"][0]["matrix_id"])
                self.assertEqual(operation_entry["payload"]["operation_id"], evidence["framework_hook_operations"][0]["operation_id"])
                self.assertEqual("langgraph", evidence["framework_hook_operations"][0]["framework"])
                self.assertEqual(2, evidence["framework_hook_operations"][0]["event_count"])
                self.assertEqual(5, evidence["framework_hook_operations"][0]["control_summary"]["passed"])
                self.assertEqual(authority_entry["payload"]["dossier_id"], evidence["framework_adapter_authority_dossiers"][0]["dossier_id"])
                self.assertEqual(2, evidence["framework_adapter_authority_dossiers"][0]["covered_requirement_count"])
                self.assertGreater(evidence["framework_adapter_authority_dossiers"][0]["missing_requirement_count"], 0)
                self.assertEqual(evidence, roadmap["framework_adapter_evidence"])

                self.assertEqual(1, contract_evidence["counts"]["framework_hook_operations"])
                self.assertEqual(operation["operation_id"], contract_evidence["framework_hook_operations"][0]["operation_id"])
                self.assertEqual(1, agent_evidence["counts"]["framework_hook_operations"])
                self.assertEqual(operation["operation_id"], agent_evidence["framework_hook_operations"][0]["operation_id"])
            finally:
                control.close()

    def test_indexes_review_portal_evidence_and_rebuilds(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            helper = service_fixtures.ReviewPortalServiceTests()
            (
                chain,
                pack,
                pack_path,
                disclosure,
                disclosure_path,
                view_path,
                frontend_bundle_path,
                frontend_bundle_hash,
                receipt,
                _,
            ) = helper._fixtures(tmp)
            document = build_eu_ai_act_document(pack, disclosure, operator="aitrade")
            acceptance = build_regulator_acceptance(
                pack,
                disclosure,
                document,
                supervised_access_receipt=receipt,
                supervised_view_path=view_path,
                regulator="Example Supervisor",
                authority_ref="EU-NCA:EXAMPLE",
                reviewer_ref="oidc:regulator.example/supervisor-123",
                examination_ref="EXAM-2026-TRUSTAI-CONTROL",
                accepted_at="2026-07-08T05:45:00Z",
                review_period_start="2026-07-08T00:00:00Z",
                review_period_end="2026-07-08T05:45:00Z",
            )
            attestation = helper._attestation(
                receipt,
                pack,
                pack_path,
                disclosure,
                disclosure_path,
                view_path,
                frontend_bundle_path,
                frontend_bundle_hash,
                regulator_acceptance=acceptance,
                eu_ai_act_document=document,
            )
            authority_evidence = [
                {
                    "requirement_id": "hosted-portal-worker-fleet",
                    "authority_kind": "hosted-service",
                    "evidence_ref": "service:review-portal/regulator-prod",
                    "evidence_hash": "sha256:review-portal-hosted-service-authority",
                    "description": "Hosted regulator review portal service export.",
                    "issuer": "TrustAI Cloud",
                    "subject": "aitrade-prod regulator review portal",
                    "source_uri": "https://ops.example/trustai/review-portal/regulator-prod",
                    "issued_at": "2026-07-08T06:10:00Z",
                    "expires_at": "2026-07-15T06:10:00Z",
                },
                {
                    "requirement_id": "production-identity-provider-sessions",
                    "authority_kind": "identity-provider",
                    "evidence_ref": "idp:review-portal/regulator-prod",
                    "evidence_hash": "sha256:review-portal-idp-session-authority",
                    "description": "Identity-provider session audit export.",
                    "issuer": "Example IdP",
                    "subject": "regulator reviewer sessions",
                    "source_uri": "https://idp.example/audit/review-portal/regulator",
                    "issued_at": "2026-07-08T06:11:00Z",
                    "expires_at": "2026-07-15T06:11:00Z",
                },
            ]
            dossier = build_review_portal_authority_dossier(
                attestation,
                supervised_access_receipt=receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                regulator_disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                frontend_bundle_path=frontend_bundle_path,
                regulator_acceptance=acceptance,
                eu_ai_act_document=document,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:review-portal-authority/control-plane",
                authority_ref="authority:review-portal/control-plane",
                producer_ref="oidc:trustai.example/review-portal-authority-worker",
                authority_evidence=authority_evidence,
                generated_at="2026-07-08T06:15:00Z",
            )
            authority_bundle = build_review_portal_authority_evidence_bundle(
                authority_evidence=authority_evidence,
                mode="authority-export",
                environment="aitrade-prod",
                bundle_ref="bundle:review-portal-authority/control-plane",
                issuer_ref="issuer:trustai-cloud/review-portal",
                subject_ref="service:review-portal/regulator-prod",
                authority_ref="authority:review-portal/control-plane",
                generated_at="2026-07-08T06:16:00Z",
            )

            receipt_entry = append_supervised_access_receipt(chain, receipt)
            acceptance_entry = append_regulator_acceptance(chain, acceptance)
            service_entry = append_review_portal_service_attestation(
                chain,
                attestation,
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                regulator_disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                frontend_bundle_path=frontend_bundle_path,
                regulator_acceptance=acceptance,
                eu_ai_act_document=document,
            )
            authority_entry = append_review_portal_authority_dossier(
                chain,
                dossier,
                service_attestation=attestation,
                supervised_access_receipt=receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                regulator_disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                frontend_bundle_path=frontend_bundle_path,
                regulator_acceptance=acceptance,
                eu_ai_act_document=document,
            )
            bundle_entry = append_review_portal_authority_evidence_bundle(chain, authority_bundle)
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                control.index_proof_pack(pack, pack_path)
                summary = control.summary()
                evidence = control.review_portal_evidence()

                for table in (
                    "supervised_access_receipts",
                    "regulator_acceptances",
                    "review_portal_service_attestations",
                    "review_portal_authority_dossiers",
                    "review_portal_authority_evidence_bundles",
                ):
                    self.assertEqual(1, indexed[table])
                    self.assertEqual(1, summary["counts"][table])

                self.assertEqual(receipt["receipt_id"], summary["latest_supervised_access_receipt"]["receipt_id"])
                self.assertEqual(acceptance["acceptance_id"], summary["latest_regulator_acceptance"]["acceptance_id"])
                self.assertTrue(summary["latest_regulator_acceptance"]["accepted"])
                self.assertEqual(attestation["attestation_id"], summary["latest_review_portal_service_attestation"]["attestation_id"])
                self.assertEqual(dossier["dossier_id"], summary["latest_review_portal_authority_dossier"]["dossier_id"])
                self.assertEqual(authority_bundle["bundle_id"], summary["latest_review_portal_authority_evidence_bundle"]["bundle_id"])
                self.assertEqual(2, summary["latest_review_portal_authority_evidence_bundle"]["live_source_uri_count"])
                self.assertFalse(summary["latest_review_portal_authority_dossier"]["production_claimed"])
                self.assertEqual(2, summary["latest_review_portal_authority_dossier"]["fresh_evidence_count"])

                self.assertEqual(receipt_entry["payload"]["receipt_id"], evidence["supervised_access_receipts"][0]["receipt_id"])
                self.assertEqual(receipt_entry["timestamp"], evidence["supervised_access_receipts"][0]["issued_at"])
                self.assertEqual(receipt_entry["payload"]["artifact_count"], len(evidence["supervised_access_receipts"][0]["artifact_refs"]))
                self.assertEqual(acceptance_entry["payload"]["acceptance_id"], evidence["regulator_acceptances"][0]["acceptance_id"])
                self.assertTrue(evidence["regulator_acceptances"][0]["accepted"])
                self.assertEqual(service_entry["payload"]["attestation_id"], evidence["review_portal_service_attestations"][0]["attestation_id"])
                self.assertEqual(attestation["source"]["source_count"], evidence["review_portal_service_attestations"][0]["source_count"])
                self.assertEqual(authority_entry["payload"]["dossier_id"], evidence["review_portal_authority_dossiers"][0]["dossier_id"])
                self.assertEqual(2, evidence["review_portal_authority_dossiers"][0]["fresh_evidence_count"])
                self.assertEqual(2, len(evidence["review_portal_authority_dossiers"][0]["authority_evidence"]))
                self.assertEqual(bundle_entry["payload"]["bundle_id"], evidence["review_portal_authority_evidence_bundles"][0]["bundle_id"])
                self.assertEqual(REVIEW_PORTAL_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE, bundle_entry["entry_type"])
                self.assertEqual(2, evidence["review_portal_authority_evidence_bundles"][0]["fresh_evidence_count"])
                self.assertEqual(2, evidence["review_portal_authority_evidence_bundles"][0]["live_source_uri_count"])
                self.assertEqual(0, evidence["review_portal_authority_evidence_bundles"][0]["placeholder_source_uri_count"])
                self.assertEqual(2, len(evidence["review_portal_authority_evidence_bundles"][0]["authority_evidence"]))
                self.assertEqual(evidence, control.roadmap_evidence()["review_portal_evidence"])

                deleted = control.clear_index()
                self.assertEqual(1, deleted["proof_packs"])
                self.assertTrue(all(count == 0 for count in control.summary()["counts"].values()))

                rebuilt = control.rebuild_from_chain(chain)
                rebuilt_summary = control.summary()
                for table in (
                    "supervised_access_receipts",
                    "regulator_acceptances",
                    "review_portal_service_attestations",
                    "review_portal_authority_dossiers",
                    "review_portal_authority_evidence_bundles",
                ):
                    self.assertEqual(1, rebuilt[table])
                    self.assertEqual(1, rebuilt_summary["counts"][table])
                self.assertEqual(0, rebuilt_summary["counts"]["proof_packs"])
            finally:
                control.close()

    def test_indexes_promotion_lifecycle_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="promotion-lifecycle")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            append_approval(chain, contract, load_approval(APPROVAL_MODEL_RISK))
            append_approval(chain, contract, load_approval(APPROVAL_TRADING_OPS))
            incident_entry = append_incident(chain, load_incident(INCIDENT))
            demotion_entry = append_demotion(
                chain,
                contract,
                reason="High-severity latency drift incident",
                triggering_entry_id=incident_entry["entry_id"],
                trigger={"entry_type": incident_entry["entry_type"], "entry_id": incident_entry["entry_id"]},
            )
            append_rollback(
                chain,
                contract,
                target_agent_version="sha256:previous-stable-agent-version",
                reason="Restore last known stable risk agent",
                triggering_entry_id=incident_entry["entry_id"],
            )
            failed_soak_entry = append_soak_report(chain, contract, load_soak_window(FAILED_SOAK))
            soak_demotion_entry = append_soak_failure_demotion(chain, contract, failed_soak_entry)
            soak_demotion_receipt = build_soak_demotion_receipt(
                contract,
                failed_soak_entry,
                soak_demotion_entry,
                attested_at="2026-07-04T01:05:00Z",
            )
            append_soak_demotion_receipt(
                chain,
                soak_demotion_receipt,
                contract=contract,
                soak_entry=failed_soak_entry,
                demotion_entry=soak_demotion_entry,
            )
            chain.save()

            control = ControlPlane(tmp / "control.sqlite")
            try:
                indexed = control.index_chain(chain)
                summary = control.summary()
                lifecycle = control.promotion_lifecycle_evidence()
                roadmap = control.roadmap_evidence()
                contract_evidence = control.contract_evidence(contract_id=contract["id"])
                agent_evidence = control.agent_evidence(
                    agent_name=contract["agent"]["name"],
                    agent_version=contract["agent"]["version"],
                )

                self.assertEqual(2, indexed["human_approvals"])
                self.assertEqual(2, indexed["promotion_demotions"])
                self.assertEqual(1, indexed["promotion_rollbacks"])
                self.assertEqual(1, indexed["soak_demotion_receipts"])
                self.assertEqual(2, summary["counts"]["human_approvals"])
                self.assertEqual(2, summary["counts"]["promotion_demotions"])
                self.assertEqual(1, summary["counts"]["promotion_rollbacks"])
                self.assertEqual(1, summary["counts"]["soak_demotion_receipts"])
                self.assertEqual("trading_ops", summary["latest_human_approval"]["role"])
                self.assertEqual("sha256:previous-stable-agent-version", summary["latest_promotion_rollback"]["target_agent_version"])
                self.assertEqual(soak_demotion_receipt["receipt_id"], summary["latest_soak_demotion_receipt"]["receipt_id"])
                self.assertTrue(summary["latest_soak_demotion_receipt"]["passed"])

                self.assertEqual(2, len(lifecycle["human_approvals"]))
                self.assertEqual(2, len(lifecycle["promotion_demotions"]))
                self.assertEqual(1, len(lifecycle["promotion_rollbacks"]))
                self.assertEqual(1, len(lifecycle["soak_demotion_receipts"]))
                self.assertTrue(any(item["role"] == "model_risk" for item in lifecycle["human_approvals"]))
                self.assertEqual(soak_demotion_entry["entry_id"], lifecycle["soak_demotion_receipts"][0]["demotion_entry_id"])
                self.assertTrue(any(item["triggering_entry_id"] == failed_soak_entry["entry_id"] for item in lifecycle["promotion_demotions"]))
                self.assertEqual(0, lifecycle["soak_demotion_receipts"][0]["violation_count"])
                self.assertIn("soak_report_verified", lifecycle["soak_demotion_receipts"][0]["source"])
                self.assertEqual(lifecycle, roadmap["promotion_lifecycle_evidence"])

                for scoped in (contract_evidence, agent_evidence):
                    self.assertEqual(2, scoped["counts"]["human_approvals"])
                    self.assertEqual(2, scoped["counts"]["promotion_demotions"])
                    self.assertEqual(1, scoped["counts"]["promotion_rollbacks"])
                    self.assertEqual(1, scoped["counts"]["soak_demotion_receipts"])
                    self.assertEqual(2, len(scoped["human_approvals"]))
                    self.assertEqual(2, len(scoped["promotion_demotions"]))
                    self.assertEqual(1, len(scoped["promotion_rollbacks"]))
                    self.assertEqual(1, len(scoped["soak_demotion_receipts"]))
                    self.assertTrue(scoped["soak_demotion_receipts"][0]["passed"])
            finally:
                control.close()

if __name__ == "__main__":
    unittest.main()
