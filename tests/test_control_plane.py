import json
import tempfile
import unittest
from pathlib import Path

from tests import test_review_portal_service as service_fixtures
from trustai.approvals import append_approval, load_approval
from trustai.byoc_authority import append_byoc_authority_dossier, build_byoc_authority_dossier
from trustai.byoc_operator import append_byoc_operator_attestation, build_byoc_operator_attestation
from trustai.control_plane import ControlPlane, _sqlite_nolock_uri
from trustai.canonical import content_hash
from trustai.chain import EvidenceChain
from trustai.cicd import append_promotion_status_receipt, build_promotion_check_payload, build_promotion_status_receipt
from trustai.delivery import build_provider_delivery
from trustai.design_partner import append_design_partner_dossier, build_design_partner_dossier
from trustai.deployment import build_deployment_manifest
from trustai.contracts import load_contract, register_contract
from trustai.external_evidence import (
    EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE,
    append_external_evidence_manifest,
    build_external_evidence_manifest,
)
from trustai.eu_ai_act import build_eu_ai_act_document
from trustai.framework_adapter_authority import (
    append_framework_adapter_authority_dossier,
    build_framework_adapter_authority_dossier,
)
from trustai.framework_adapter_matrix import append_framework_adapter_matrix, build_framework_adapter_matrix, load_framework_adapter_matrix_source
from trustai.framework_hook_operation import append_framework_hook_operation, build_framework_hook_operation, load_framework_trace_payload
from trustai.framework_hook_release import append_framework_hook_release, build_framework_hook_release, load_framework_hook_release_source
from trustai.gate import append_eval_and_gate
from trustai.ingest import append_events, load_events
from trustai.mcp_gateway import (
    append_mcp_proxy_capture,
    append_mcp_transcript,
    build_mcp_proxy_capture,
    load_mcp_proxy_events,
    load_mcp_transcript,
)
from trustai.mcp_gateway_authority import append_mcp_gateway_authority_dossier, build_mcp_gateway_authority_dossier
from trustai.phase_scoreboard import append_phase_scoreboard, build_phase_scoreboard
from trustai.product_scope import append_product_scope_decision, build_product_scope_decision
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
    append_review_portal_authority_dossier,
    build_review_portal_authority_dossier,
)
from trustai.review_portal_service import append_review_portal_service_attestation
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.policy_engine import append_policy_engine_receipt, build_policy_engine_receipt
from trustai.policy_export import export_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.registry import append_inventory, load_inventory
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
from trustai.supervised_access import append_supervised_access_receipt
from trustai.vertical_pack import append_vertical_pack, build_vertical_pack
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"
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
            mcp_authority = build_mcp_gateway_authority_dossier(
                mcp_calls,
                mode="proxy-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:mcp-gateway-authority/aitrade-prod",
                authority_ref="authority:mcp-gateway/proxy-prod",
                producer_ref="oidc:trustai.example/mcp-gateway-authority-worker",
                authority_evidence=[
                    {
                        "requirement_id": "production-mcp-proxy-worker-fleet",
                        "authority_kind": "hosted-service",
                        "evidence_ref": "mcp-proxy:fleet/aitrade-prod",
                        "evidence_hash": "sha256:mcp-proxy-worker-fleet",
                        "description": "Hosted MCP proxy worker fleet export for governed tool-call capture.",
                        "issuer": "TrustAI Hosted Ops",
                        "subject": "aitrade-prod MCP proxy fleet",
                        "source_uri": "https://mcp.example/audit/fleet/aitrade-prod",
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
                        "source_uri": "https://object-lock.example/mcp/audit/aitrade-prod",
                        "issued_at": "2026-07-12T03:11:00Z",
                        "expires_at": "2026-07-19T03:11:00Z",
                    },
                ],
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
                self.assertEqual(1, counts["mcp_tool_calls"])
                self.assertEqual(1, counts["mcp_proxy_captures"])
                self.assertEqual(1, summary["counts"]["promotion_statuses"])
                self.assertEqual(1, counts["promotion_statuses"])
                self.assertEqual(1, summary["counts"]["runtime_attestations"])
                self.assertEqual(1, summary["counts"]["policy_decisions"])
                self.assertEqual(1, summary["counts"]["policy_engine_receipts"])
                self.assertEqual(1, summary["counts"]["incidents"])
                self.assertEqual(1, summary["counts"]["roadmap_audits"])
                self.assertEqual(1, summary["counts"]["external_evidence_collection_runs"])
                self.assertEqual(1, summary["counts"]["external_evidence_manifests"])
                self.assertEqual(1, summary["counts"]["authority_dossiers"])
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
                self.assertEqual(1, counts["runtime_attestations"])
                self.assertEqual(1, counts["policy_decisions"])
                self.assertEqual(1, counts["policy_engine_receipts"])
                self.assertEqual(1, counts["incidents"])
                self.assertEqual(1, counts["roadmap_audits"])
                self.assertEqual(1, counts["external_evidence_collection_runs"])
                self.assertEqual(1, counts["external_evidence_manifests"])
                self.assertEqual(1, counts["authority_dossiers"])
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
                self.assertEqual("authority:mcp-gateway/proxy-prod", summary["latest_authority_dossier"]["authority_ref"])
                self.assertEqual("proxy-dossier", summary["latest_authority_dossier"]["mode"])
                self.assertFalse(summary["latest_authority_dossier"]["production_claimed"])
                self.assertGreater(summary["latest_authority_dossier"]["missing_requirement_count"], 0)
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
                self.assertEqual(1, len(control.recent_mcp_tool_calls()))
                self.assertEqual(1, len(control.recent_mcp_proxy_captures()))
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
                self.assertEqual(1, len(roadmap_evidence["mcp_evidence"]["mcp_tool_calls"]))
                self.assertEqual(1, len(roadmap_evidence["mcp_evidence"]["mcp_proxy_captures"]))
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
                self.assertIn("task_id", external_evidence[0]["missing_authority_units"][0])
                gap_worklist = control.external_authority_gaps(authority_kind="provider-api", limit=2)
                self.assertEqual(2, len(gap_worklist["missing_authority_units"]))
                self.assertEqual(2, gap_worklist["summary"]["returned_missing_authority_unit_count"])
                self.assertGreater(gap_worklist["summary"]["selected_missing_authority_unit_count"], 2)
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
                self.assertEqual(1, len(authority_dossiers))
                self.assertEqual("mcp.gateway_authority_recorded", authority_dossiers[0]["entry_type"])
                self.assertEqual("authority:mcp-gateway/proxy-prod", authority_dossiers[0]["authority_ref"])
                self.assertFalse(authority_dossiers[0]["production_claimed"])
                self.assertEqual(2, authority_dossiers[0]["covered_requirement_count"])
                self.assertGreater(authority_dossiers[0]["missing_requirement_count"], 0)
                self.assertEqual(2, authority_dossiers[0]["freshness_window_count"])
                self.assertIsInstance(authority_dossiers[0]["missing_requirement_ids"], list)
                self.assertEqual(2, authority_dossiers[0]["control_summary"]["deferred"])
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
                ):
                    self.assertEqual(1, indexed[table])
                    self.assertEqual(1, summary["counts"][table])

                self.assertEqual(receipt["receipt_id"], summary["latest_supervised_access_receipt"]["receipt_id"])
                self.assertEqual(acceptance["acceptance_id"], summary["latest_regulator_acceptance"]["acceptance_id"])
                self.assertTrue(summary["latest_regulator_acceptance"]["accepted"])
                self.assertEqual(attestation["attestation_id"], summary["latest_review_portal_service_attestation"]["attestation_id"])
                self.assertEqual(dossier["dossier_id"], summary["latest_review_portal_authority_dossier"]["dossier_id"])
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
