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
from trustai.mcp_gateway import load_mcp_transcript
from trustai.mcp_gateway_authority import (
    MCP_GATEWAY_AUTHORITY_ENTRY_TYPE,
    MCP_GATEWAY_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
    MCP_GATEWAY_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA,
    MCP_GATEWAY_AUTHORITY_SCHEMA,
    PRODUCTION_AUTHORITY_REQUIREMENTS,
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    append_mcp_gateway_authority_dossier,
    append_mcp_gateway_authority_evidence_bundle,
    build_mcp_gateway_authority_dossier,
    build_mcp_gateway_authority_evidence_bundle,
    mcp_gateway_authority_evidence_from_bundle,
    verify_mcp_gateway_authority_dossier,
    verify_mcp_gateway_authority_evidence_bundle,
    write_mcp_gateway_authority_dossier,
)

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "examples" / "aitrade" / "mcp-transcript.json"


class McpGatewayAuthorityTests(unittest.TestCase):
    def _calls(self) -> list[dict]:
        return load_mcp_transcript(MCP)

    def _authority_evidence(self) -> list[dict]:
        return [
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
        ]

    def _complete_authority_evidence(self) -> list[dict]:
        evidence = []
        for requirement in PRODUCTION_AUTHORITY_REQUIREMENTS:
            requirement_id = requirement["id"]
            authority_kind = requirement["authority_kinds"][0]
            evidence.append(
                {
                    "requirement_id": requirement_id,
                    "authority_kind": authority_kind,
                    "evidence_ref": f"authority:mcp-gateway/proxy-prod/{requirement_id}",
                    "evidence_hash": "sha256:" + content_hash({"mcp_gateway_authority": requirement_id, "authority_kind": authority_kind}),
                    "description": f"Production authority export for {requirement_id}.",
                    "issuer": "TrustAI MCP Gateway Authority",
                    "subject": "aitrade-prod MCP gateway authority",
                    "source_uri": f"https://authority.trustai.ai/mcp-gateway/proxy-prod/{requirement_id}/{authority_kind}",
                    "issued_at": "2026-07-12T03:10:00Z",
                    "expires_at": "2026-07-19T03:10:00Z",
                }
            )
        return evidence

    def _evidence_cli_arg(self, item: dict) -> str:
        return (
            f"{item['requirement_id']},{item['authority_kind']},{item['evidence_ref']},{item['evidence_hash']},{item['description']}"
            f";issuer={item['issuer']};subject={item['subject']};source_uri={item['source_uri']}"
            f";issued_at={item['issued_at']};expires_at={item['expires_at']}"
        )

    def _dossier(self, calls: list[dict], *, mode: str = "proxy-dossier", authority_evidence: list[dict] | None = None) -> dict:
        return build_mcp_gateway_authority_dossier(
            calls,
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:mcp-gateway-authority/aitrade-prod",
            authority_ref="authority:mcp-gateway/proxy-prod",
            producer_ref="oidc:trustai.example/mcp-gateway-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-12T03:12:00Z",
        )

    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "mcp_gateway_authority": body})]

    def test_mcp_gateway_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            calls = self._calls()
            dossier = self._dossier(calls)
            result = verify_mcp_gateway_authority_dossier(dossier, transcript_calls=calls)
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="mcp-gateway-authority-test")
            entry = append_mcp_gateway_authority_dossier(chain, dossier, transcript_calls=calls)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(MCP_GATEWAY_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertEqual(2, result.fresh_evidence_count)
            self.assertTrue(any("evidence missing for" in warning for warning in result.warnings), result.warnings)
            self.assertEqual(MCP_GATEWAY_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(dossier["transcript_binding"]["transcript_hash"], entry["payload"]["transcript_binding"]["transcript_hash"])
            self.assertEqual(dossier["authority_evidence"][0]["source_context"], entry["payload"]["authority_evidence"][0]["source_context"])
            self.assertEqual({"deferred": 2, "passed": 3}, entry["payload"]["control_summary"])


    def test_mcp_gateway_authority_evidence_bundle_drives_complete_proxy_dossier(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            calls = self._calls()
            bundle = build_mcp_gateway_authority_evidence_bundle(
                authority_evidence=self._complete_authority_evidence(),
                mode="production-export",
                environment="aitrade-prod",
                bundle_ref="bundle:mcp-gateway-authority/proxy-prod/2026-07-12",
                issuer_ref="authority:trustai-mcp-gateway-authority",
                subject_ref="mcp-gateway:aitrade-prod/proxy",
                authority_ref="authority:mcp-gateway/proxy-prod",
                generated_at="2026-07-12T03:12:00Z",
            )
            bundle_result = verify_mcp_gateway_authority_evidence_bundle(
                bundle,
                require_complete=True,
                require_fresh=True,
                now="2026-07-15T00:00:00Z",
            )
            dossier = self._dossier(
                calls,
                mode="proxy-dossier",
                authority_evidence=mcp_gateway_authority_evidence_from_bundle(
                    bundle,
                    require_complete=True,
                    require_fresh=True,
                    now="2026-07-15T00:00:00Z",
                ),
            )
            result = verify_mcp_gateway_authority_dossier(
                dossier,
                transcript_calls=calls,
                require_complete=True,
                require_fresh=True,
                now="2026-07-15T00:00:00Z",
            )
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="mcp-gateway-authority-bundle-test")
            bundle_entry = append_mcp_gateway_authority_evidence_bundle(
                chain,
                bundle,
                require_complete=True,
                require_fresh=True,
                now="2026-07-15T00:00:00Z",
            )
            dossier_entry = append_mcp_gateway_authority_dossier(
                chain,
                dossier,
                transcript_calls=calls,
                require_complete=True,
                require_fresh=True,
                now="2026-07-15T00:00:00Z",
            )

            self.assertTrue(bundle_result.ok, bundle_result.errors)
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(MCP_GATEWAY_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA, bundle["schema"])
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), bundle_result.covered_count)
            self.assertEqual(0, bundle["summary"]["missing_requirement_count"])
            self.assertEqual(0, bundle["summary"]["placeholder_source_uri_count"])
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.fresh_evidence_count)
            self.assertEqual({"passed": 5}, bundle_entry["payload"]["control_summary"])
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), len(bundle_entry["payload"]["authority_evidence"]))
            self.assertEqual(bundle["authority_evidence"][0]["evidence_id"], bundle_entry["payload"]["authority_evidence"][0]["evidence_id"])
            self.assertEqual({"deferred": 1, "passed": 4}, dossier_entry["payload"]["control_summary"])
            self.assertEqual(MCP_GATEWAY_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE, bundle_entry["entry_type"])
            self.assertTrue(chain.verify_all().ok)

    def test_mcp_gateway_authority_evidence_bundle_detects_placeholder_source_uri(self):
        bundle = build_mcp_gateway_authority_evidence_bundle(
            authority_evidence=self._complete_authority_evidence(),
            mode="production-export",
            environment="aitrade-prod",
            bundle_ref="bundle:mcp-gateway-authority/proxy-prod/2026-07-12",
            issuer_ref="authority:trustai-mcp-gateway-authority",
            subject_ref="mcp-gateway:aitrade-prod/proxy",
            authority_ref="authority:mcp-gateway/proxy-prod",
            generated_at="2026-07-12T03:12:00Z",
        )
        tampered = copy.deepcopy(bundle)
        tampered["authority_evidence"][0]["source_uri"] = "TODO://authority/mcp-gateway"

        result = verify_mcp_gateway_authority_evidence_bundle(
            tampered,
            require_complete=True,
            require_fresh=True,
            now="2026-07-15T00:00:00Z",
        )

        self.assertFalse(result.ok)
        self.assertIn("bundle_id does not match canonical MCP gateway authority evidence bundle body", result.errors)
        self.assertTrue(any("source_uri is placeholder" in error for error in result.errors), result.errors)

    def test_mcp_gateway_authority_rejects_empty_transcript(self):
        with self.assertRaisesRegex(ValueError, "at least one tool call"):
            self._dossier([])

    def test_mcp_gateway_authority_detects_transcript_tamper(self):
        calls = self._calls()
        dossier = self._dossier(calls)
        tampered = copy.deepcopy(calls)
        tampered[0]["response"]["status"] = "tampered"

        result = verify_mcp_gateway_authority_dossier(dossier, transcript_calls=tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("transcript_binding does not match" in error for error in result.errors), result.errors)

    def test_mcp_gateway_authority_requires_complete_transcript_binding_without_source(self):
        calls = self._calls()
        dossier = self._dossier(calls)
        tampered = copy.deepcopy(dossier)
        tampered["transcript_binding"]["tool_call_records"][0].pop("response_hash")
        body = without_keys(tampered, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        tampered["dossier_id"] = dossier_id
        tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "mcp_gateway_authority": body})]

        result = verify_mcp_gateway_authority_dossier(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("tool_call_records[0].response_hash is required" in error for error in result.errors), result.errors)

    def test_mcp_gateway_authority_rejects_resigned_authority_source_context_mismatch(self):
        calls = self._calls()
        dossier = self._dossier(calls)
        tampered = copy.deepcopy(dossier)
        item = tampered["authority_evidence"][0]
        item["source_context"]["transcript_hash"] = "tampered-transcript-hash"
        item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
        self._resign_dossier(tampered)

        result = verify_mcp_gateway_authority_dossier(tampered, transcript_calls=calls)

        self.assertFalse(result.ok)
        self.assertNotIn("dossier_id does not match canonical MCP gateway authority body", result.errors)
        self.assertNotIn("MCP gateway authority signature verification failed", result.errors)
        self.assertNotIn("MCP gateway authority evidence_id does not match evidence body: production-mcp-proxy-worker-fleet", result.errors)
        self.assertIn("MCP gateway authority source_context does not match transcript binding: production-mcp-proxy-worker-fleet", result.errors)

    def test_mcp_gateway_authority_rejects_resigned_control_tamper(self):
        calls = self._calls()
        dossier = self._dossier(calls)
        tampered = copy.deepcopy(dossier)
        tampered["controls"][0]["status"] = "deferred"
        self._resign_dossier(tampered)

        result = verify_mcp_gateway_authority_dossier(tampered, transcript_calls=calls)

        self.assertFalse(result.ok)
        self.assertNotIn("dossier_id does not match canonical MCP gateway authority body", result.errors)
        self.assertNotIn("MCP gateway authority signature verification failed", result.errors)
        self.assertIn("MCP gateway authority controls do not match dossier body", result.errors)

    def test_mcp_gateway_authority_requires_freshness_when_strict(self):
        calls = self._calls()
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0].pop("issued_at")
        evidence[0].pop("expires_at")
        dossier = self._dossier(calls, authority_evidence=evidence)

        result = verify_mcp_gateway_authority_dossier(dossier, transcript_calls=calls, require_fresh=True)

        self.assertFalse(result.ok)
        self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_mcp_gateway_authority_rejects_incomplete_production_claim(self):
        calls = self._calls()
        dossier = self._dossier(calls, mode="production-dossier")

        result = verify_mcp_gateway_authority_dossier(dossier, transcript_calls=calls)

        self.assertFalse(result.ok)
        self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)


    def test_cli_mcp_gateway_authority_evidence_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            paths = {
                "transcript": tmp / "mcp-transcript.json",
                "bundle": tmp / "mcp-gateway-authority-evidence-bundle.json",
                "bundle_entry": tmp / "mcp-gateway-authority-evidence-bundle-entry.json",
                "dossier": tmp / "mcp-gateway-authority.json",
                "chain": tmp / "mcp-gateway-authority-evidence-bundle-chain.json",
            }
            paths["transcript"].write_text(MCP.read_text(encoding="utf-8"), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            evidence_args = []
            for item in self._complete_authority_evidence():
                evidence_args.extend(["--authority-evidence", self._evidence_cli_arg(item)])

            subprocess.run(
                base
                + [
                    "mcp-gateway-authority-evidence-bundle",
                    "--mode",
                    "production-export",
                    "--environment",
                    "aitrade-prod",
                    "--bundle-ref",
                    "bundle:mcp-gateway-authority/proxy-prod/2026-07-12",
                    "--issuer-ref",
                    "authority:trustai-mcp-gateway-authority",
                    "--subject-ref",
                    "mcp-gateway:aitrade-prod/proxy",
                    "--authority-ref",
                    "authority:mcp-gateway/proxy-prod",
                    *evidence_args,
                    "--generated-at",
                    "2026-07-12T03:12:00Z",
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-15T00:00:00Z",
                    "--out",
                    str(paths["bundle"]),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["mcp-gateway-authority-evidence-bundle-verify", str(paths["bundle"]), "--require-complete", "--require-fresh", "--now", "2026-07-15T00:00:00Z"],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "mcp-gateway-authority-evidence-bundle-append",
                    str(paths["bundle"]),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-15T00:00:00Z",
                    "--state",
                    str(paths["chain"]),
                    "--tenant",
                    "mcp-gateway-authority-evidence-bundle-local",
                    "--out",
                    str(paths["bundle_entry"]),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "mcp-gateway-authority",
                    str(paths["transcript"]),
                    "--mode",
                    "proxy-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:mcp-gateway-authority/aitrade-prod",
                    "--authority-ref",
                    "authority:mcp-gateway/proxy-prod",
                    "--producer-ref",
                    "oidc:trustai.example/mcp-gateway-authority-worker",
                    "--authority-evidence-bundle",
                    str(paths["bundle"]),
                    "--generated-at",
                    "2026-07-12T03:12:00Z",
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2026-07-15T00:00:00Z",
                    "--out",
                    str(paths["dossier"]),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            bundle = json.loads(paths["bundle"].read_text(encoding="utf-8"))
            bundle_entry = json.loads(paths["bundle_entry"].read_text(encoding="utf-8"))
            dossier = json.loads(paths["dossier"].read_text(encoding="utf-8"))

            self.assertEqual(MCP_GATEWAY_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA, bundle["schema"])
            self.assertEqual(MCP_GATEWAY_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE, bundle_entry["entry_type"])
            self.assertEqual(0, dossier["summary"]["missing_requirement_count"])
            self.assertEqual("proxy-dossier", dossier["mode"])

    def test_cli_mcp_gateway_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            paths = {
                "transcript": tmp / "mcp-transcript.json",
                "dossier": tmp / "mcp-gateway-authority.json",
                "entry": tmp / "mcp-gateway-authority-entry.json",
                "chain": tmp / "mcp-gateway-authority-chain.json",
            }
            paths["transcript"].write_text(MCP.read_text(encoding="utf-8"), encoding="utf-8")
            evidence_arg = (
                "production-mcp-proxy-worker-fleet,hosted-service,mcp-proxy:fleet/aitrade-prod,"
                "sha256:mcp-proxy-worker-fleet,Hosted MCP proxy worker fleet export for governed tool-call capture;"
                "issuer=TrustAI Hosted Ops;subject=aitrade-prod MCP proxy fleet;"
                "source_uri=https://mcp.example/audit/fleet/aitrade-prod;"
                "issued_at=2026-07-12T03:10:00Z;expires_at=2026-07-19T03:10:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "mcp-gateway-authority",
                    str(paths["transcript"]),
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:mcp-gateway-authority/aitrade-prod",
                    "--authority-ref",
                    "authority:mcp-gateway/proxy-prod",
                    "--producer-ref",
                    "oidc:trustai.example/mcp-gateway-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-12T03:12:00Z",
                    "--out",
                    str(paths["dossier"]),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "mcp-gateway-authority-verify", str(paths["dossier"]), str(paths["transcript"])],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "mcp-gateway-authority-append",
                    str(paths["dossier"]),
                    str(paths["transcript"]),
                    "--state",
                    str(paths["chain"]),
                    "--tenant",
                    "mcp-gateway-authority-local",
                    "--out",
                    str(paths["entry"]),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(paths["dossier"].exists())
            self.assertTrue(paths["entry"].exists())
            dossier = json.loads(paths["dossier"].read_text(encoding="utf-8"))
            entry = json.loads(paths["entry"].read_text(encoding="utf-8"))
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(1, entry["payload"]["summary"]["covered_requirement_count"])


if __name__ == "__main__":
    unittest.main()