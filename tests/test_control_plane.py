import json
import tempfile
import unittest
from pathlib import Path

from trustai.control_plane import ControlPlane
from trustai.canonical import content_hash
from trustai.chain import EvidenceChain
from trustai.cicd import append_promotion_status_receipt, build_promotion_check_payload, build_promotion_status_receipt
from trustai.delivery import build_provider_delivery
from trustai.contracts import load_contract, register_contract
from trustai.external_evidence import (
    EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE,
    append_external_evidence_manifest,
    build_external_evidence_manifest,
)
from trustai.gate import append_eval_and_gate
from trustai.ingest import append_events, load_events
from trustai.mcp_gateway import load_mcp_transcript
from trustai.mcp_gateway_authority import append_mcp_gateway_authority_dossier, build_mcp_gateway_authority_dossier
from trustai.lifecycle import append_incident, load_incident
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.policy_engine import append_policy_engine_receipt, build_policy_engine_receipt
from trustai.policy_export import export_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.registry import append_inventory, load_inventory
from trustai.roadmap_audit import append_roadmap_audit, build_roadmap_audit
from trustai.anchor import append_anchor
from trustai.runtime import append_runtime_attestation, load_action
from trustai.verifier import verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"
INVENTORY = ROOT / "examples" / "aitrade" / "agent-inventory.json"
EVENTS = ROOT / "examples" / "aitrade" / "otel-events.json"
MCP = ROOT / "examples" / "aitrade" / "mcp-transcript.json"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class ControlPlaneTests(unittest.TestCase):
    def test_indexes_chain_and_proof_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
            contract = load_contract(CONTRACT)
            register_contract(chain, contract)
            append_inventory(chain, load_inventory(INVENTORY))
            append_events(chain, load_events(EVENTS))
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
            mcp_calls = load_mcp_transcript(MCP)
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
                self.assertEqual(1, counts["runtime_attestations"])
                self.assertEqual(1, counts["policy_decisions"])
                self.assertEqual(1, counts["policy_engine_receipts"])
                self.assertEqual(1, counts["incidents"])
                self.assertEqual(1, counts["roadmap_audits"])
                self.assertEqual(1, counts["external_evidence_collection_runs"])
                self.assertEqual(1, counts["external_evidence_manifests"])
                self.assertEqual(1, counts["authority_dossiers"])
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
                self.assertEqual("passed", summary["latest_proof_pack"]["outcome"])
                self.assertEqual("aitrade-btcusdt-canary", summary["latest_eval_run"]["contract_id"])
                self.assertEqual("passed", summary["latest_gate_decision"]["outcome"])
                self.assertTrue(summary["latest_gate_decision"]["passed"])
                self.assertTrue(summary["latest_gate_decision"]["holdout_passed"])
                self.assertTrue(summary["latest_gate_decision"]["approvals_passed"])
                self.assertEqual("gen_ai.tool.call", summary["latest_ingest_event"]["event_name"])
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
                self.assertEqual(1, contract_evidence["counts"]["proof_packs"])
                self.assertEqual(2, contract_evidence["counts"]["ingest_events"])
                self.assertEqual(1, contract_evidence["counts"]["promotion_statuses"])
                self.assertEqual(1, contract_evidence["counts"]["runtime_attestations"])
                self.assertEqual(1, contract_evidence["counts"]["policy_decisions"])
                self.assertEqual(1, contract_evidence["counts"]["policy_engine_receipts"])
                self.assertEqual(1, contract_evidence["counts"]["incidents"])
                self.assertEqual("passed", contract_evidence["gate_decisions"][0]["outcome"])
                self.assertTrue(contract_evidence["gate_decisions"][0]["passed"])
                self.assertEqual("gen_ai.tool.call", contract_evidence["ingest_events"][0]["event_name"])
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
                self.assertEqual(1, agent_evidence["counts"]["proof_packs"])
                self.assertEqual(2, agent_evidence["counts"]["ingest_events"])
                self.assertEqual(1, agent_evidence["counts"]["promotion_statuses"])
                self.assertEqual(1, agent_evidence["counts"]["runtime_attestations"])
                self.assertEqual(1, agent_evidence["counts"]["policy_decisions"])
                self.assertEqual(1, agent_evidence["counts"]["policy_engine_receipts"])
                self.assertEqual(1, agent_evidence["counts"]["incidents"])
                self.assertTrue(agent_evidence["agents"][0]["governed"])
                self.assertEqual("passed", agent_evidence["gate_decisions"][0]["outcome"])
                self.assertEqual("gen_ai.tool.call", agent_evidence["ingest_events"][0]["event_name"])
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
                statuses = control.recent_promotion_statuses()
                self.assertEqual(1, len(statuses))
                self.assertEqual("volelabs/trust_ai", statuses[0]["target_ref"]["repository"])
                self.assertTrue(statuses[0]["provider_status_success"])
                runtime_evidence = control.runtime_evidence()
                self.assertEqual("shadow-order-20260703-001", runtime_evidence["runtime_attestations"][0]["action_id"])
                self.assertEqual("trading-runtime-policy-v0", runtime_evidence["policy_decisions"][0]["policy_pack_id"])
                self.assertEqual("opa", runtime_evidence["policy_engine_receipts"][0]["engine_name"])
                self.assertEqual("incident-20260704-latency-drift", runtime_evidence["incidents"][0]["incident_id"])
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
                external_evidence = control.recent_external_evidence_manifests()
                self.assertEqual(1, len(external_evidence))
                self.assertEqual("partial", external_evidence[0]["status"])
                self.assertFalse(external_evidence[0]["require_complete"])
                self.assertGreater(external_evidence[0]["missing_requirement_count"], 0)
                self.assertGreater(external_evidence[0]["missing_authority_kind_count"], 0)
                self.assertIsInstance(external_evidence[0]["missing_requirement_ids"], list)
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


if __name__ == "__main__":
    unittest.main()
