import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from trustai.anchor import append_anchor, verify_anchor
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.ingest import load_events
from trustai.object_store import WORMStore
from trustai.server import serve
from trustai.timestamping import issue_timestamp_token, verify_timestamp_token


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
EVENTS = ROOT / "examples" / "aitrade" / "otel-events.json"
OTLP = ROOT / "examples" / "aitrade" / "otlp-traces.json"


class ProductionPrimitiveTests(unittest.TestCase):
    def test_timestamp_token_rejects_message_tamper(self):
        message = {"entry_id": "abc", "payload_hash": "def"}
        token = issue_timestamp_token(message)

        self.assertTrue(verify_timestamp_token(message, token))
        self.assertFalse(verify_timestamp_token({"entry_id": "abc", "payload_hash": "tampered"}, token))

    def test_chain_entries_include_timestamp_tokens_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="test")
            register_contract(chain, load_contract(CONTRACT))
            chain.save()

            self.assertIn("timestamp_token", chain.entries[0])
            self.assertTrue(chain.verify_all().ok)

    def test_anchor_and_worm_receipt_verify(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            register_contract(chain, load_contract(CONTRACT))
            anchor_entry = append_anchor(chain)
            chain.save()

            self.assertEqual([], verify_anchor(anchor_entry["payload"]))
            store = WORMStore(tmp / "worm")
            receipt = store.store_json({"chain": chain.tree(), "anchor": anchor_entry}, "chain-anchor")
            audit = store.audit_receipt(receipt, now="2026-07-04T00:00:00Z")
            expired = store.audit_receipt(receipt, now="2034-01-01T00:00:00Z")
            tampered = {**receipt, "size_bytes": receipt["size_bytes"] + 1}
            tampered_audit = store.audit_receipt(tampered, now="2026-07-04T00:00:00Z")

            self.assertTrue(store.verify_receipt(receipt))
            self.assertTrue(audit.ok, audit.errors)
            self.assertTrue(audit.retention_active)
            self.assertTrue(expired.ok, expired.errors)
            self.assertFalse(expired.retention_active)
            self.assertIn("retention period has expired", expired.warnings)
            self.assertFalse(tampered_audit.ok)
            self.assertTrue(any("receipt_id" in error or "size" in error for error in tampered_audit.errors))

    def test_http_service_health_ingest_and_control_plane_index(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "server-chain.json"
            control_path = tmp / "control.sqlite"
            server = serve(
                "127.0.0.1",
                0,
                str(state_path),
                "server-test",
                control_db_path=str(control_path),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request("GET", "/health")
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                response.read()

                events = {"events": load_events(EVENTS)}
                conn.request(
                    "POST",
                    "/v0/ingest",
                    body=json.dumps(events),
                    headers={"Content-Type": "application/json"},
                )
                ingest_response = conn.getresponse()
                body = json.loads(ingest_response.read().decode("utf-8"))
                self.assertEqual(200, ingest_response.status)
                self.assertEqual(2, len(body["entries"]))

                conn.request(
                    "POST",
                    "/v1/traces",
                    body=OTLP.read_text(encoding="utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                otlp_response = conn.getresponse()
                otlp_body = json.loads(otlp_response.read().decode("utf-8"))
                self.assertEqual(200, otlp_response.status)
                self.assertEqual(2, len(otlp_body["entries"]))

                conn.request(
                    "POST",
                    "/v0/control/index",
                    body=json.dumps({"state_path": str(state_path)}),
                    headers={"Content-Type": "application/json"},
                )
                index_response = conn.getresponse()
                index_body = json.loads(index_response.read().decode("utf-8"))
                self.assertEqual(200, index_response.status)
                self.assertEqual(4, index_body["summary"]["counts"]["chain_entries"])
                self.assertEqual(4, index_body["summary"]["counts"]["ingest_events"])

                conn.request("GET", "/v0/control/summary")
                summary_response = conn.getresponse()
                summary_body = json.loads(summary_response.read().decode("utf-8"))
                self.assertEqual(200, summary_response.status)
                self.assertEqual(4, summary_body["counts"]["chain_entries"])
                self.assertEqual(0, summary_body["counts"]["contracts"])
                self.assertEqual(0, summary_body["counts"]["eval_runs"])
                self.assertEqual(0, summary_body["counts"]["gate_decisions"])
                self.assertEqual(0, summary_body["counts"]["human_approvals"])
                self.assertEqual(0, summary_body["counts"]["promotion_demotions"])
                self.assertEqual(0, summary_body["counts"]["promotion_rollbacks"])
                self.assertEqual(0, summary_body["counts"]["soak_demotion_receipts"])
                self.assertEqual(4, summary_body["counts"]["ingest_events"])
                self.assertEqual(0, summary_body["counts"]["mcp_tool_calls"])
                self.assertEqual(0, summary_body["counts"]["mcp_proxy_captures"])
                self.assertEqual(0, summary_body["counts"]["roadmap_audits"])
                self.assertEqual(0, summary_body["counts"]["external_evidence_collection_runs"])
                self.assertEqual(0, summary_body["counts"]["authority_dossiers"])
                self.assertEqual(0, summary_body["counts"]["design_partner_dossiers"])
                self.assertEqual(0, summary_body["counts"]["own_compliance_dossiers"])
                self.assertEqual(0, summary_body["counts"]["product_scope_decisions"])
                self.assertEqual(0, summary_body["counts"]["vertical_packs"])
                self.assertEqual(0, summary_body["counts"]["reliability_reports"])

                conn.request("GET", "/v0/contracts")
                contracts_response = conn.getresponse()
                contracts_body = json.loads(contracts_response.read().decode("utf-8"))
                self.assertEqual(200, contracts_response.status)
                self.assertEqual([], contracts_body["contracts"])

                conn.request("GET", "/v0/control/contracts")
                control_contracts_response = conn.getresponse()
                control_contracts_body = json.loads(control_contracts_response.read().decode("utf-8"))
                self.assertEqual(200, control_contracts_response.status)
                self.assertEqual([], control_contracts_body["contracts"])

                conn.request("GET", "/v0/agents")
                agents_response = conn.getresponse()
                agents_body = json.loads(agents_response.read().decode("utf-8"))
                self.assertEqual(200, agents_response.status)
                self.assertEqual([], agents_body["agents"])

                conn.request("GET", "/v0/control/agents")
                control_agents_response = conn.getresponse()
                control_agents_body = json.loads(control_agents_response.read().decode("utf-8"))
                self.assertEqual(200, control_agents_response.status)
                self.assertEqual([], control_agents_body["agents"])

                conn.request("GET", "/v0/control/contract-evidence")
                missing_scope_response = conn.getresponse()
                missing_scope_body = json.loads(missing_scope_response.read().decode("utf-8"))
                self.assertEqual(422, missing_scope_response.status)
                self.assertIn("contract_id or contract_hash", missing_scope_body["error"])

                conn.request("GET", "/v0/control/contract-evidence?contract_id=unknown")
                contract_evidence_response = conn.getresponse()
                contract_evidence_body = json.loads(contract_evidence_response.read().decode("utf-8"))
                self.assertEqual(200, contract_evidence_response.status)
                self.assertEqual("unknown", contract_evidence_body["scope"]["contract_id"])
                self.assertEqual(0, contract_evidence_body["counts"]["contracts"])
                self.assertEqual(0, contract_evidence_body["counts"]["eval_runs"])

                conn.request("GET", "/v0/control/agent-evidence")
                missing_agent_response = conn.getresponse()
                missing_agent_body = json.loads(missing_agent_response.read().decode("utf-8"))
                self.assertEqual(422, missing_agent_response.status)
                self.assertIn("agent_name", missing_agent_body["error"])

                conn.request("GET", "/v0/control/agent-evidence?agent_name=aitrade-risk-agent")
                agent_evidence_response = conn.getresponse()
                agent_evidence_body = json.loads(agent_evidence_response.read().decode("utf-8"))
                self.assertEqual(200, agent_evidence_response.status)
                self.assertEqual("aitrade-risk-agent", agent_evidence_body["scope"]["agent_name"])
                self.assertEqual(0, agent_evidence_body["counts"]["agents"])
                self.assertEqual(0, agent_evidence_body["counts"]["contracts"])
                self.assertEqual(4, agent_evidence_body["counts"]["chain_entries"])
                self.assertEqual(4, agent_evidence_body["counts"]["ingest_events"])
                self.assertEqual("gen_ai.tool.call", agent_evidence_body["ingest_events"][0]["event_name"])

                conn.request("GET", "/v0/eval-runs")
                eval_runs_response = conn.getresponse()
                eval_runs_body = json.loads(eval_runs_response.read().decode("utf-8"))
                self.assertEqual(200, eval_runs_response.status)
                self.assertEqual([], eval_runs_body["eval_runs"])

                conn.request("GET", "/v0/control/eval-runs")
                control_eval_runs_response = conn.getresponse()
                control_eval_runs_body = json.loads(control_eval_runs_response.read().decode("utf-8"))
                self.assertEqual(200, control_eval_runs_response.status)
                self.assertEqual([], control_eval_runs_body["eval_runs"])

                conn.request("GET", "/v0/gate-decisions")
                gate_decisions_response = conn.getresponse()
                gate_decisions_body = json.loads(gate_decisions_response.read().decode("utf-8"))
                self.assertEqual(200, gate_decisions_response.status)
                self.assertEqual([], gate_decisions_body["gate_decisions"])

                conn.request("GET", "/v0/control/gate-decisions")
                control_gate_decisions_response = conn.getresponse()
                control_gate_decisions_body = json.loads(control_gate_decisions_response.read().decode("utf-8"))
                self.assertEqual(200, control_gate_decisions_response.status)
                self.assertEqual([], control_gate_decisions_body["gate_decisions"])

                conn.request("GET", "/v0/proof-packs")
                proof_packs_response = conn.getresponse()
                proof_packs_body = json.loads(proof_packs_response.read().decode("utf-8"))
                self.assertEqual(200, proof_packs_response.status)
                self.assertEqual([], proof_packs_body["proof_packs"])

                conn.request("GET", "/v0/control/proof-packs")
                control_proof_packs_response = conn.getresponse()
                control_proof_packs_body = json.loads(control_proof_packs_response.read().decode("utf-8"))
                self.assertEqual(200, control_proof_packs_response.status)
                self.assertEqual([], control_proof_packs_body["proof_packs"])

                conn.request("GET", "/v0/promotion-statuses")
                promotion_statuses_response = conn.getresponse()
                promotion_statuses_body = json.loads(promotion_statuses_response.read().decode("utf-8"))
                self.assertEqual(200, promotion_statuses_response.status)
                self.assertEqual([], promotion_statuses_body["promotion_statuses"])

                conn.request("GET", "/v0/control/promotion-statuses")
                control_promotion_statuses_response = conn.getresponse()
                control_promotion_statuses_body = json.loads(control_promotion_statuses_response.read().decode("utf-8"))
                self.assertEqual(200, control_promotion_statuses_response.status)
                self.assertEqual([], control_promotion_statuses_body["promotion_statuses"])

                conn.request("GET", "/v0/ingest-events")
                ingest_events_response = conn.getresponse()
                ingest_events_body = json.loads(ingest_events_response.read().decode("utf-8"))
                self.assertEqual(200, ingest_events_response.status)
                self.assertEqual(4, len(ingest_events_body["ingest_events"]))
                self.assertEqual("gen_ai.tool.call", ingest_events_body["ingest_events"][0]["event_name"])

                conn.request("GET", "/v0/control/ingest-events")
                control_ingest_events_response = conn.getresponse()
                control_ingest_events_body = json.loads(control_ingest_events_response.read().decode("utf-8"))
                self.assertEqual(200, control_ingest_events_response.status)
                self.assertEqual(4, len(control_ingest_events_body["ingest_events"]))

                conn.request("GET", "/v0/runtime-evidence")
                runtime_response = conn.getresponse()
                runtime_body = json.loads(runtime_response.read().decode("utf-8"))
                self.assertEqual(200, runtime_response.status)
                self.assertEqual([], runtime_body["runtime_attestations"])
                self.assertEqual([], runtime_body["policy_decisions"])
                self.assertEqual([], runtime_body["policy_engine_receipts"])
                self.assertEqual([], runtime_body["incidents"])

                conn.request("GET", "/v0/control/runtime-evidence")
                control_runtime_response = conn.getresponse()
                control_runtime_body = json.loads(control_runtime_response.read().decode("utf-8"))
                self.assertEqual(200, control_runtime_response.status)
                self.assertEqual([], control_runtime_body["runtime_attestations"])
                self.assertEqual([], control_runtime_body["policy_decisions"])

                conn.request("GET", "/v0/holdout-evidence")
                holdout_response = conn.getresponse()
                holdout_body = json.loads(holdout_response.read().decode("utf-8"))
                self.assertEqual(200, holdout_response.status)
                self.assertEqual([], holdout_body["temporal_holdout_manifests"])
                self.assertEqual([], holdout_body["shadow_replays"])
                self.assertEqual([], holdout_body["soak_reports"])
                self.assertEqual([], holdout_body["traffic_holdout_exports"])
                self.assertEqual([], holdout_body["traffic_completeness_receipts"])

                conn.request("GET", "/v0/control/holdout-evidence")
                control_holdout_response = conn.getresponse()
                control_holdout_body = json.loads(control_holdout_response.read().decode("utf-8"))
                self.assertEqual(200, control_holdout_response.status)
                self.assertEqual([], control_holdout_body["shadow_replays"])

                conn.request("GET", "/v0/mcp-evidence")
                mcp_response = conn.getresponse()
                mcp_body = json.loads(mcp_response.read().decode("utf-8"))
                self.assertEqual(200, mcp_response.status)
                self.assertEqual([], mcp_body["mcp_tool_calls"])
                self.assertEqual([], mcp_body["mcp_proxy_captures"])

                conn.request("GET", "/v0/control/mcp-evidence")
                control_mcp_response = conn.getresponse()
                control_mcp_body = json.loads(control_mcp_response.read().decode("utf-8"))
                self.assertEqual(200, control_mcp_response.status)
                self.assertEqual([], control_mcp_body["mcp_tool_calls"])

                conn.request("GET", "/v0/onboarding-evidence")
                onboarding_response = conn.getresponse()
                onboarding_body = json.loads(onboarding_response.read().decode("utf-8"))
                self.assertEqual(200, onboarding_response.status)
                self.assertEqual([], onboarding_body["self_serve_onboarding_receipts"])

                conn.request("GET", "/v0/control/onboarding-evidence")
                control_onboarding_response = conn.getresponse()
                control_onboarding_body = json.loads(control_onboarding_response.read().decode("utf-8"))
                self.assertEqual(200, control_onboarding_response.status)
                self.assertEqual([], control_onboarding_body["self_serve_onboarding_receipts"])

                conn.request("GET", "/v0/promotion-lifecycle-evidence")
                lifecycle_response = conn.getresponse()
                lifecycle_body = json.loads(lifecycle_response.read().decode("utf-8"))
                self.assertEqual(200, lifecycle_response.status)
                self.assertEqual([], lifecycle_body["human_approvals"])
                self.assertEqual([], lifecycle_body["promotion_demotions"])
                self.assertEqual([], lifecycle_body["promotion_rollbacks"])
                self.assertEqual([], lifecycle_body["soak_demotion_receipts"])

                conn.request("GET", "/v0/control/promotion-lifecycle-evidence")
                control_lifecycle_response = conn.getresponse()
                control_lifecycle_body = json.loads(control_lifecycle_response.read().decode("utf-8"))
                self.assertEqual(200, control_lifecycle_response.status)
                self.assertEqual([], control_lifecycle_body["human_approvals"])

                conn.request("GET", "/v0/framework-adapter-evidence")
                framework_response = conn.getresponse()
                framework_body = json.loads(framework_response.read().decode("utf-8"))
                self.assertEqual(200, framework_response.status)
                self.assertEqual([], framework_body["framework_adapter_matrices"])
                self.assertEqual([], framework_body["framework_hook_releases"])
                self.assertEqual([], framework_body["framework_hook_operations"])
                self.assertEqual([], framework_body["framework_adapter_authority_dossiers"])

                conn.request("GET", "/v0/control/framework-adapter-evidence")
                control_framework_response = conn.getresponse()
                control_framework_body = json.loads(control_framework_response.read().decode("utf-8"))
                self.assertEqual(200, control_framework_response.status)
                self.assertEqual([], control_framework_body["framework_hook_operations"])

                conn.request("GET", "/v0/standards-auditor-evidence")
                standards_auditor_response = conn.getresponse()
                standards_auditor_body = json.loads(standards_auditor_response.read().decode("utf-8"))
                self.assertEqual(200, standards_auditor_response.status)
                self.assertEqual([], standards_auditor_body["standards_body_evidence"])
                self.assertEqual([], standards_auditor_body["auditor_ecosystem_evidence"])

                conn.request("GET", "/v0/control/standards-auditor-evidence")
                control_standards_auditor_response = conn.getresponse()
                control_standards_auditor_body = json.loads(control_standards_auditor_response.read().decode("utf-8"))
                self.assertEqual(200, control_standards_auditor_response.status)
                self.assertEqual([], control_standards_auditor_body["auditor_ecosystem_evidence"])


                conn.request("GET", "/v0/trust-network-evidence")
                trust_network_response = conn.getresponse()
                trust_network_body = json.loads(trust_network_response.read().decode("utf-8"))
                self.assertEqual(200, trust_network_response.status)
                self.assertEqual([], trust_network_body["trust_network_evidence"])

                conn.request("GET", "/v0/control/trust-network-evidence")
                control_trust_network_response = conn.getresponse()
                control_trust_network_body = json.loads(control_trust_network_response.read().decode("utf-8"))
                self.assertEqual(200, control_trust_network_response.status)
                self.assertEqual([], control_trust_network_body["trust_network_evidence"])

                conn.request("GET", "/v0/provider-delivery-evidence")
                provider_delivery_response = conn.getresponse()
                provider_delivery_body = json.loads(provider_delivery_response.read().decode("utf-8"))
                self.assertEqual(200, provider_delivery_response.status)
                self.assertEqual([], provider_delivery_body["provider_delivery_evidence"])

                conn.request("GET", "/v0/control/provider-delivery-evidence")
                control_provider_delivery_response = conn.getresponse()
                control_provider_delivery_body = json.loads(control_provider_delivery_response.read().decode("utf-8"))
                self.assertEqual(200, control_provider_delivery_response.status)
                self.assertEqual([], control_provider_delivery_body["provider_delivery_evidence"])

                conn.request("GET", "/v0/provider-operations-evidence")
                provider_operations_response = conn.getresponse()
                provider_operations_body = json.loads(provider_operations_response.read().decode("utf-8"))
                self.assertEqual(200, provider_operations_response.status)
                self.assertEqual([], provider_operations_body["provider_operations_evidence"])

                conn.request("GET", "/v0/control/provider-operations-evidence")
                control_provider_operations_response = conn.getresponse()
                control_provider_operations_body = json.loads(control_provider_operations_response.read().decode("utf-8"))
                self.assertEqual(200, control_provider_operations_response.status)
                self.assertEqual([], control_provider_operations_body["provider_operations_evidence"])

                conn.request("GET", "/v0/policy-backend-evidence")
                policy_backend_response = conn.getresponse()
                policy_backend_body = json.loads(policy_backend_response.read().decode("utf-8"))
                self.assertEqual(200, policy_backend_response.status)
                self.assertEqual([], policy_backend_body["policy_backend_evidence"])

                conn.request("GET", "/v0/control/policy-backend-evidence")
                control_policy_backend_response = conn.getresponse()
                control_policy_backend_body = json.loads(control_policy_backend_response.read().decode("utf-8"))
                self.assertEqual(200, control_policy_backend_response.status)
                self.assertEqual([], control_policy_backend_body["policy_backend_evidence"])

                conn.request("GET", "/v0/compliance-evidence")
                compliance_response = conn.getresponse()
                compliance_body = json.loads(compliance_response.read().decode("utf-8"))
                self.assertEqual(200, compliance_response.status)
                self.assertEqual([], compliance_body["compliance_evidence"])

                conn.request("GET", "/v0/control/compliance-evidence")
                control_compliance_response = conn.getresponse()
                control_compliance_body = json.loads(control_compliance_response.read().decode("utf-8"))
                self.assertEqual(200, control_compliance_response.status)
                self.assertEqual([], control_compliance_body["compliance_evidence"])

                conn.request("GET", "/v0/insurer-evidence")
                insurer_response = conn.getresponse()
                insurer_body = json.loads(insurer_response.read().decode("utf-8"))
                self.assertEqual(200, insurer_response.status)
                self.assertEqual([], insurer_body["underwriting_quotes"])
                self.assertEqual([], insurer_body["insurer_partner_authority_dossiers"])

                conn.request("GET", "/v0/control/insurer-evidence")
                control_insurer_response = conn.getresponse()
                control_insurer_body = json.loads(control_insurer_response.read().decode("utf-8"))
                self.assertEqual(200, control_insurer_response.status)
                self.assertEqual([], control_insurer_body["underwriting_quotes"])

                conn.request("GET", "/v0/multi-agent-evidence")
                multi_agent_response = conn.getresponse()
                multi_agent_body = json.loads(multi_agent_response.read().decode("utf-8"))
                self.assertEqual(200, multi_agent_response.status)
                self.assertEqual([], multi_agent_body["agent_delegations"])
                self.assertEqual([], multi_agent_body["agent_delegation_graphs"])

                conn.request("GET", "/v0/control/multi-agent-evidence")
                control_multi_agent_response = conn.getresponse()
                control_multi_agent_body = json.loads(control_multi_agent_response.read().decode("utf-8"))
                self.assertEqual(200, control_multi_agent_response.status)
                self.assertEqual([], control_multi_agent_body["agent_delegations"])

                conn.request("GET", "/v0/byoc-evidence")
                byoc_response = conn.getresponse()
                byoc_body = json.loads(byoc_response.read().decode("utf-8"))
                self.assertEqual(200, byoc_response.status)
                self.assertEqual([], byoc_body["byoc_operator_attestations"])
                self.assertEqual([], byoc_body["byoc_authority_dossiers"])

                conn.request("GET", "/v0/control/byoc-evidence")
                control_byoc_response = conn.getresponse()
                control_byoc_body = json.loads(control_byoc_response.read().decode("utf-8"))
                self.assertEqual(200, control_byoc_response.status)
                self.assertEqual([], control_byoc_body["byoc_operator_attestations"])

                conn.request("GET", "/v0/identity-provider-evidence")
                identity_response = conn.getresponse()
                identity_body = json.loads(identity_response.read().decode("utf-8"))
                self.assertEqual(200, identity_response.status)
                self.assertEqual([], identity_body["vendor_identity_receipts"])
                self.assertEqual([], identity_body["identity_provider_attestations"])
                self.assertEqual([], identity_body["identity_provider_authority_dossiers"])

                conn.request("GET", "/v0/control/identity-provider-evidence")
                control_identity_response = conn.getresponse()
                control_identity_body = json.loads(control_identity_response.read().decode("utf-8"))
                self.assertEqual(200, control_identity_response.status)
                self.assertEqual([], control_identity_body["vendor_identity_receipts"])

                conn.request("GET", "/v0/roadmap-evidence")
                roadmap_response = conn.getresponse()
                roadmap_body = json.loads(roadmap_response.read().decode("utf-8"))
                self.assertEqual(200, roadmap_response.status)
                self.assertEqual([], roadmap_body["roadmap_audits"])
                self.assertEqual([], roadmap_body["external_evidence_collection_runs"])
                self.assertEqual([], roadmap_body["external_evidence_manifests"])
                self.assertEqual([], roadmap_body["phase_scoreboards"])
                self.assertEqual([], roadmap_body["design_partner_dossiers"])
                self.assertEqual([], roadmap_body["own_compliance_dossiers"])
                self.assertEqual([], roadmap_body["product_scope_decisions"])
                self.assertEqual([], roadmap_body["vertical_packs"])
                self.assertEqual([], roadmap_body["reliability_reports"])
                self.assertEqual([], roadmap_body["holdout_evidence"]["shadow_replays"])
                self.assertEqual([], roadmap_body["mcp_evidence"]["mcp_tool_calls"])
                self.assertEqual([], roadmap_body["onboarding_evidence"]["self_serve_onboarding_receipts"])
                self.assertEqual([], roadmap_body["promotion_lifecycle_evidence"]["human_approvals"])
                self.assertEqual([], roadmap_body["framework_adapter_evidence"]["framework_hook_operations"])
                self.assertEqual([], roadmap_body["compliance_evidence"]["compliance_evidence"])
                self.assertEqual([], roadmap_body["insurer_evidence"]["underwriting_quotes"])
                self.assertEqual([], roadmap_body["multi_agent_evidence"]["agent_delegations"])
                self.assertEqual([], roadmap_body["byoc_evidence"]["byoc_operator_attestations"])
                self.assertEqual([], roadmap_body["identity_provider_evidence"]["vendor_identity_receipts"])

                conn.request("GET", "/v0/control/roadmap-evidence")
                control_roadmap_response = conn.getresponse()
                control_roadmap_body = json.loads(control_roadmap_response.read().decode("utf-8"))
                self.assertEqual(200, control_roadmap_response.status)
                self.assertEqual([], control_roadmap_body["roadmap_audits"])
                self.assertEqual([], control_roadmap_body["external_evidence_manifests"])

                conn.request("GET", "/v0/phase-scoreboards")
                phase_scoreboards_response = conn.getresponse()
                phase_scoreboards_body = json.loads(phase_scoreboards_response.read().decode("utf-8"))
                self.assertEqual(200, phase_scoreboards_response.status)
                self.assertEqual([], phase_scoreboards_body["phase_scoreboards"])

                conn.request("GET", "/v0/design-partner-dossiers")
                design_partner_response = conn.getresponse()
                design_partner_body = json.loads(design_partner_response.read().decode("utf-8"))
                self.assertEqual(200, design_partner_response.status)
                self.assertEqual([], design_partner_body["design_partner_dossiers"])

                conn.request("GET", "/v0/own-compliance-dossiers")
                own_compliance_response = conn.getresponse()
                own_compliance_body = json.loads(own_compliance_response.read().decode("utf-8"))
                self.assertEqual(200, own_compliance_response.status)
                self.assertEqual([], own_compliance_body["own_compliance_dossiers"])

                conn.request("GET", "/v0/product-scope-decisions")
                product_scope_response = conn.getresponse()
                product_scope_body = json.loads(product_scope_response.read().decode("utf-8"))
                self.assertEqual(200, product_scope_response.status)
                self.assertEqual([], product_scope_body["product_scope_decisions"])

                conn.request("GET", "/v0/vertical-packs")
                vertical_pack_response = conn.getresponse()
                vertical_pack_body = json.loads(vertical_pack_response.read().decode("utf-8"))
                self.assertEqual(200, vertical_pack_response.status)
                self.assertEqual([], vertical_pack_body["vertical_packs"])

                conn.request("GET", "/v0/reliability-reports")
                reliability_report_response = conn.getresponse()
                reliability_report_body = json.loads(reliability_report_response.read().decode("utf-8"))
                self.assertEqual(200, reliability_report_response.status)
                self.assertEqual([], reliability_report_body["reliability_reports"])

                conn.request("GET", "/v0/readiness")
                readiness_response = conn.getresponse()
                readiness_body = json.loads(readiness_response.read().decode("utf-8"))
                self.assertEqual(200, readiness_response.status)
                self.assertEqual("not_ready", readiness_body["status"])
                self.assertFalse(readiness_body["local_reference_complete"])
                self.assertFalse(readiness_body["external_authority_complete"])
                self.assertFalse(readiness_body["collection_run_present"])
                self.assertFalse(readiness_body["roadmap_phase_scoreboard_ready"])
                self.assertFalse(readiness_body["design_partner_ready"])
                self.assertFalse(readiness_body["own_compliance_ready"])
                self.assertFalse(readiness_body["product_scope_ready"])
                self.assertFalse(readiness_body["vertical_pack_ready"])
                self.assertFalse(readiness_body["reliability_report_ready"])
                self.assertFalse(readiness_body["phase_scoreboard_summary"]["present"])
                self.assertFalse(readiness_body["design_partner_summary"]["present"])
                self.assertFalse(readiness_body["own_compliance_summary"]["present"])
                self.assertFalse(readiness_body["product_scope_summary"]["present"])
                self.assertFalse(readiness_body["vertical_pack_summary"]["present"])
                self.assertFalse(readiness_body["reliability_report_summary"]["present"])
                self.assertEqual(0, readiness_body["external_authority_gap_summary"]["missing_authority_unit_count"])
                self.assertIn("no roadmap audit indexed", readiness_body["blockers"])
                self.assertIn("no design-partner pilot dossier indexed", readiness_body["blockers"])
                self.assertIn("no TrustAI own-compliance dossier indexed", readiness_body["blockers"])
                self.assertIn("no product-scope decision indexed", readiness_body["blockers"])
                self.assertIn("no vertical pack indexed", readiness_body["blockers"])
                self.assertIn("no State of Agent Reliability report indexed", readiness_body["blockers"])

                conn.request("GET", "/v0/external-evidence")
                external_evidence_response = conn.getresponse()
                external_evidence_body = json.loads(external_evidence_response.read().decode("utf-8"))
                self.assertEqual(200, external_evidence_response.status)
                self.assertEqual([], external_evidence_body["external_evidence_manifests"])

                conn.request("GET", "/v0/control/external-evidence")
                control_external_evidence_response = conn.getresponse()
                control_external_evidence_body = json.loads(control_external_evidence_response.read().decode("utf-8"))
                self.assertEqual(200, control_external_evidence_response.status)
                self.assertEqual([], control_external_evidence_body["external_evidence_manifests"])

                conn.request("GET", "/v0/external-authority-gaps?authority_kind=provider-api&limit=2")
                authority_gaps_response = conn.getresponse()
                authority_gaps_body = json.loads(authority_gaps_response.read().decode("utf-8"))
                self.assertEqual(200, authority_gaps_response.status)
                self.assertEqual(0, authority_gaps_body["summary"]["total_missing_authority_unit_count"])
                self.assertEqual({}, authority_gaps_body["summary"]["gap_count_by_collection_priority"])
                self.assertEqual({}, authority_gaps_body["summary"]["gap_count_by_requirement_phase"])
                self.assertEqual([], authority_gaps_body["missing_authority_units"])

                conn.request("GET", "/v0/external-authority-gaps?limit=0")
                invalid_gaps_response = conn.getresponse()
                invalid_gaps_body = json.loads(invalid_gaps_response.read().decode("utf-8"))
                self.assertEqual(422, invalid_gaps_response.status)
                self.assertEqual("limit must be a positive integer", invalid_gaps_body["error"])

                conn.request("GET", "/v0/authority-dossiers")
                authority_response = conn.getresponse()
                authority_body = json.loads(authority_response.read().decode("utf-8"))
                self.assertEqual(200, authority_response.status)
                self.assertEqual([], authority_body["authority_dossiers"])

                conn.request("GET", "/v0/control/authority-dossiers")
                control_authority_response = conn.getresponse()
                control_authority_body = json.loads(control_authority_response.read().decode("utf-8"))
                self.assertEqual(200, control_authority_response.status)
                self.assertEqual([], control_authority_body["authority_dossiers"])
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
