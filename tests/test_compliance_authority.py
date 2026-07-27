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
from trustai.compliance import build_compliance_export
from trustai.compliance_authority import (
    COMPLIANCE_AUTHORITY_ENTRY_TYPE,
    append_compliance_authority_dossier,
    build_compliance_authority_dossier,
    verify_compliance_authority_dossier,
)
from trustai.contracts import load_contract, register_contract
from trustai.crypto import sign_value
from trustai.eu_ai_act import build_eu_ai_act_document
from trustai.gate import append_eval_and_gate
from trustai.lifecycle import append_demotion, append_incident, append_rollback, load_incident
from trustai.policy import append_policy_decision, load_policy_pack
from trustai.proofpack import compile_proof_pack
from trustai.regulator import build_regulator_disclosure
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
POLICY = ROOT / "examples" / "aitrade" / "policy-pack.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class ComplianceAuthorityTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="compliance-authority-test")
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
        append_policy_decision(
            chain,
            load_policy_pack(POLICY),
            load_action(ACTION),
            proof_pack=pack,
            now="2026-07-04T02:00:00Z",
        )
        incident_entry = append_incident(chain, load_incident(INCIDENT))
        append_demotion(chain, contract, "High-severity latency drift incident", incident_entry["entry_id"])
        append_rollback(
            chain,
            contract,
            "sha256:previous-stable-agent-version",
            "Restore last known stable risk agent",
            incident_entry["entry_id"],
        )
        disclosure = build_regulator_disclosure(chain, pack)
        compliance_export = build_compliance_export(pack)
        document = build_eu_ai_act_document(pack, disclosure, operator="aitrade")
        return chain, pack, disclosure, compliance_export, document

    def _evidence(self, requirement_id: str, authority_kind: str = "customer", evidence_ref: str | None = None) -> dict:
        ref = evidence_ref or f"evidence:{requirement_id}"
        return {
            "requirement_id": requirement_id,
            "authority_kind": authority_kind,
            "evidence_ref": ref,
            "evidence_hash": f"sha256:{content_hash({'ref': ref, 'requirement_id': requirement_id})}",
            "description": f"Recorded authority evidence for {requirement_id}",
            "issuer": "TrustAI compliance test",
            "subject": "aitrade compliance authority",
            "source_uri": f"https://example.test/{requirement_id}",
            "issued_at": "2026-07-04T03:00:00Z",
            "expires_at": "2026-12-31T00:00:00Z",
        }

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "compliance_authority": body})]

    def test_provider_dossier_binds_compliance_export_eu_document_and_authority_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, compliance_export, document = self._sources(Path(tmp_dir))
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
                authority_evidence=[
                    self._evidence("framework-control-mapping-ontology", "standards-body"),
                    self._evidence("eu-ai-act-technical-documentation", "regulator"),
                ],
                generated_at="2026-07-04T03:05:00Z",
            )
            result = verify_compliance_authority_dossier(
                dossier,
                compliance_export=compliance_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                now="2026-07-05T00:00:00Z",
            )
            control_summary = {}
            for control in dossier["controls"]:
                control_summary[control["status"]] = control_summary.get(control["status"], 0) + 1

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(2, result.covered_count)
            self.assertEqual(11, result.required_count)
            self.assertEqual({"deferred": 3, "passed": 7}, control_summary)
            self.assertEqual(pack["pack_id"], dossier["source_binding"]["compliance_export"]["pack_id"])
            self.assertEqual(document["document_id"], dossier["source_binding"]["eu_ai_act_document"]["document_id"])
            self.assertEqual(dossier["source_binding"]["compliance_export"]["export_hash"], dossier["authority_evidence"][0]["source_context"]["compliance_export_hash"])

    def test_verification_detects_compliance_export_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, compliance_export, document = self._sources(Path(tmp_dir))
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
            )
            tampered_export = copy.deepcopy(compliance_export)
            tampered_export["mappings"][0]["controls"][0]["evidence"] = "changed"

            result = verify_compliance_authority_dossier(
                dossier,
                compliance_export=tampered_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
            )

            self.assertFalse(result.ok)
            self.assertIn("compliance export does not match supplied proof pack", result.errors)
            self.assertIn("compliance authority source_binding does not match supplied source artifacts", result.errors)

    def test_verification_requires_complete_source_binding_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, compliance_export, document = self._sources(Path(tmp_dir))
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
            )
            tampered = copy.deepcopy(dossier)
            tampered["source_binding"]["compliance_export"].pop("export_hash")
            body = without_keys(tampered, "dossier_id", "signatures")
            dossier_id = content_hash(body)
            tampered["dossier_id"] = dossier_id
            tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "compliance_authority": body})]

            result = verify_compliance_authority_dossier(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("compliance_export.export_hash is required" in error for error in result.errors), result.errors)

    def test_rejects_resigned_authority_source_context_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, compliance_export, document = self._sources(Path(tmp_dir))
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
                authority_evidence=[self._evidence("framework-control-mapping-ontology", "standards-body")],
            )
            tampered = copy.deepcopy(dossier)
            item = tampered["authority_evidence"][0]
            item["source_context"]["compliance_export_hash"] = "sha256:tampered-compliance-export"
            item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
            self._resign_dossier(tampered)

            result = verify_compliance_authority_dossier(
                tampered,
                compliance_export=compliance_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("dossier_id does not match canonical compliance authority body", result.errors)
            self.assertNotIn("compliance authority signature verification failed", result.errors)
            self.assertNotIn("compliance authority evidence_id does not match evidence body: framework-control-mapping-ontology", result.errors)
            self.assertIn("compliance authority source_context does not match source binding: framework-control-mapping-ontology", result.errors)

    def test_compliance_authority_normalizes_uppercase_evidence_hash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, compliance_export, document = self._sources(Path(tmp_dir))
            expected_hash = self._evidence("framework-control-mapping-ontology", "standards-body")["evidence_hash"]
            evidence = self._evidence("framework-control-mapping-ontology", "standards-body")
            evidence["evidence_hash"] = "sha256:" + expected_hash.removeprefix("sha256:").upper()
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
                authority_evidence=[evidence],
            )

            result = verify_compliance_authority_dossier(
                dossier,
                compliance_export=compliance_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(expected_hash, dossier["authority_evidence"][0]["evidence_hash"])

    def test_compliance_authority_rejects_resigned_malformed_evidence_hash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, compliance_export, document = self._sources(Path(tmp_dir))
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
                authority_evidence=[self._evidence("framework-control-mapping-ontology", "standards-body")],
            )
            tampered = copy.deepcopy(dossier)
            item = tampered["authority_evidence"][0]
            item["evidence_hash"] = "sha256:not-a-real-digest"
            item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
            self._resign_dossier(tampered)

            result = verify_compliance_authority_dossier(
                tampered,
                compliance_export=compliance_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
            )

            self.assertFalse(result.ok)
            self.assertIn(
                "invalid compliance authority evidence: compliance authority evidence_hash must contain a 64-character sha256 digest",
                result.errors,
            )
            self.assertNotIn("dossier_id does not match canonical compliance authority body", result.errors)
            self.assertNotIn("compliance authority signature verification failed", result.errors)
            self.assertNotIn("compliance authority evidence_id does not match evidence body: framework-control-mapping-ontology", result.errors)

    def test_append_payload_includes_authority_source_context(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain, pack, disclosure, compliance_export, document = self._sources(tmp)
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
                authority_evidence=[self._evidence("framework-control-mapping-ontology", "standards-body")],
                generated_at="2026-07-04T03:05:00Z",
            )

            entry = append_compliance_authority_dossier(
                chain,
                dossier,
                compliance_export=compliance_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
            )

            self.assertEqual(dossier["authority_evidence"][0]["source_context"], entry["payload"]["authority_evidence"][0]["source_context"])

    def test_require_fresh_rejects_missing_freshness_windows(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, compliance_export, document = self._sources(Path(tmp_dir))
            evidence = self._evidence("framework-control-mapping-ontology", "standards-body")
            evidence.pop("issued_at")
            evidence.pop("expires_at")
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
                authority_evidence=[evidence],
            )

            result = verify_compliance_authority_dossier(
                dossier,
                compliance_export=compliance_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                require_fresh=True,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors))

    def test_production_mode_rejects_incomplete_live_authority_claim(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, pack, disclosure, compliance_export, document = self._sources(Path(tmp_dir))
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="production-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
                authority_evidence=[self._evidence("framework-control-mapping-ontology", "standards-body")],
            )

            result = verify_compliance_authority_dossier(
                dossier,
                compliance_export=compliance_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                now="2026-07-05T00:00:00Z",
            )

            self.assertFalse(result.ok)
            self.assertIn("production-dossier mode requires every compliance authority requirement to be covered", result.errors)
            self.assertIn(
                "production-dossier mode requires compliance export, EU AI Act document, proof-pack, regulator disclosure, and EU data-plane bindings",
                result.errors,
            )

    def test_append_and_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain, pack, disclosure, compliance_export, document = self._sources(tmp)
            dossier = build_compliance_authority_dossier(
                compliance_export,
                document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                mode="provider-dossier",
                environment="aitrade-prod",
                dossier_ref="dossier:compliance-authority/aitrade-prod",
                authority_ref="authority:compliance/aitrade-prod",
                producer_ref="oidc:trustai.example/compliance-authority-worker",
                authority_evidence=[self._evidence("framework-control-mapping-ontology", "standards-body")],
                generated_at="2026-07-04T03:05:00Z",
            )
            entry = append_compliance_authority_dossier(
                chain,
                dossier,
                compliance_export=compliance_export,
                eu_ai_act_document=document,
                proof_pack=pack,
                regulator_disclosure=disclosure,
            )

            self.assertEqual(COMPLIANCE_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])

            pack_path = tmp / "pack.json"
            disclosure_path = tmp / "disclosure.json"
            export_path = tmp / "compliance-export.json"
            document_path = tmp / "eu-ai-act.json"
            dossier_path = tmp / "cli-compliance-authority.json"
            for path, value in (
                (pack_path, pack),
                (disclosure_path, disclosure),
                (export_path, compliance_export),
                (document_path, document),
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            evidence_ref = "standards:ontology/2026"
            evidence_hash = f"sha256:{content_hash({'ref': evidence_ref, 'requirement_id': 'framework-control-mapping-ontology'})}"
            evidence_arg = (
                f"framework-control-mapping-ontology,standards-body,{evidence_ref},"
                f"{evidence_hash},Recorded compliance ontology evidence;"
                "issuer=TrustAI CI;subject=aitrade compliance authority;"
                "source_uri=https://example.test/compliance;issued_at=2026-07-04T03:00:00Z;expires_at=2026-12-31T00:00:00Z"
            )

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "compliance-authority",
                    str(export_path),
                    str(document_path),
                    "--pack",
                    str(pack_path),
                    "--regulator-disclosure",
                    str(disclosure_path),
                    "--mode",
                    "provider-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:compliance-authority/aitrade-prod",
                    "--authority-ref",
                    "authority:compliance/aitrade-prod",
                    "--producer-ref",
                    "oidc:trustai.example/compliance-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-04T03:05:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "compliance-authority-verify",
                    str(dossier_path),
                    "--compliance-export",
                    str(export_path),
                    "--eu-ai-act-document",
                    str(document_path),
                    "--pack",
                    str(pack_path),
                    "--regulator-disclosure",
                    str(disclosure_path),
                    "--now",
                    "2026-07-05T00:00:00Z",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)


if __name__ == "__main__":
    unittest.main()
