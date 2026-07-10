import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import tests.test_trust_network_worker as worker_test_helpers
from trustai.chain import EvidenceChain
from trustai.identity_provider_attestation import write_identity_provider_attestation
from trustai.marketplace import write_marketplace_catalog, write_marketplace_distribution
from trustai.marketplace_author import write_marketplace_author_governance
from trustai.marketplace_settlement import write_marketplace_settlement
from trustai.procurement_clause import write_procurement_clause_receipt
from trustai.procurement_integration import write_procurement_integration_receipt
from trustai.trust_network import write_trust_network_manifest
from trustai.trust_network_registry import write_trust_network_registry_receipt
from trustai.trust_network_registry_status import write_trust_network_registry_status_receipt
from trustai.trust_network_service import write_trust_network_service_attestation
from trustai.trust_network_worker import write_trust_network_worker_receipt
from trustai.trust_network_worker_bundle import (
    TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE,
    TRUST_NETWORK_WORKER_BUNDLE_SCHEMA,
    append_trust_network_worker_bundle,
    build_trust_network_worker_bundle,
    extract_trust_network_worker_bundle_sources,
    render_trust_network_worker_bundle_markdown,
    verify_trust_network_worker_bundle,
    write_trust_network_worker_bundle,
    write_trust_network_worker_bundle_markdown,
)
from trustai.vendor_identity import write_vendor_identity_receipt


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class TrustNetworkWorkerBundleTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = worker_test_helpers.TrustNetworkWorkerTests(methodName="test_trust_network_worker_verifies_and_appends")
        sources = helper._sources(tmp)
        receipt = helper._receipt(sources)
        paths = {
            "worker_receipt": tmp / "trust-network-worker.json",
            "service_attestation": tmp / "trust-network-service.json",
            "registry_receipt": tmp / "trust-network-registry.json",
            "trust_network_manifest": tmp / "trust-network-manifest.json",
            "vendor_identity_receipt": tmp / "vendor-identity.json",
            "identity_provider_attestation": tmp / "identity-provider-attestation.json",
            "identity_payload": tmp / "identity-payload.json",
            "procurement_receipt": tmp / "procurement.json",
            "procurement_integration_receipt": tmp / "procurement-integration.json",
            "proof_packs": [tmp / "proof-pack.json"],
            "registry_status_receipt": tmp / "registry-status.json",
            "marketplace_catalog": tmp / "marketplace-catalog.json",
            "marketplace_distribution": tmp / "marketplace-distribution.json",
            "marketplace_author_governance": tmp / "marketplace-author-governance.json",
            "marketplace_settlement": tmp / "marketplace-settlement.json",
        }
        write_trust_network_worker_receipt(paths["worker_receipt"], receipt)
        write_trust_network_service_attestation(paths["service_attestation"], sources["service"])
        write_trust_network_registry_receipt(paths["registry_receipt"], sources["registry"])
        write_trust_network_manifest(paths["trust_network_manifest"], sources["manifest"])
        write_vendor_identity_receipt(paths["vendor_identity_receipt"], sources["vendor"])
        write_identity_provider_attestation(paths["identity_provider_attestation"], sources["identity_attestation"])
        _write_json(paths["identity_payload"], sources["identity_payload"])
        write_procurement_clause_receipt(paths["procurement_receipt"], sources["procurement"])
        write_procurement_integration_receipt(paths["procurement_integration_receipt"], sources["integration"])
        _write_json(paths["proof_packs"][0], sources["pack"])
        write_trust_network_registry_status_receipt(paths["registry_status_receipt"], sources["status"])
        write_marketplace_catalog(paths["marketplace_catalog"], sources["catalog"])
        write_marketplace_distribution(paths["marketplace_distribution"], sources["distribution"])
        write_marketplace_author_governance(paths["marketplace_author_governance"], sources["author"])
        write_marketplace_settlement(paths["marketplace_settlement"], sources["settlement"])
        bundle = build_trust_network_worker_bundle(
            receipt,
            sources["service"],
            sources["registry"],
            trust_network_manifest=sources["manifest"],
            vendor_identity_receipt=sources["vendor"],
            identity_provider_attestation=sources["identity_attestation"],
            identity_payload=sources["identity_payload"],
            procurement_receipt=sources["procurement"],
            procurement_integration_receipt=sources["integration"],
            proof_packs=[sources["pack"]],
            registry_status_receipt=sources["status"],
            marketplace_catalog=sources["catalog"],
            marketplace_distribution=sources["distribution"],
            frontend_bundle_path=sources["frontend_bundle_path"],
            marketplace_author_governance=sources["author"],
            marketplace_settlement=sources["settlement"],
            artifact_paths=paths,
            root=ROOT,
            mode="procurement-review",
            environment="aitrade-prod",
            reviewer_ref="oidc:buyer.example/procurement-reviewer",
            generated_at="2026-07-12T04:00:00Z",
        )
        return bundle, receipt, sources, paths

    def test_trust_network_worker_bundle_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, receipt, _, _ = self._sources(tmp)
            result = verify_trust_network_worker_bundle(bundle)
            chain = EvidenceChain.load(tmp / "bundle-chain.json", tenant_id="trust-network-worker-bundle-test")
            entry = append_trust_network_worker_bundle(chain, bundle)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(TRUST_NETWORK_WORKER_BUNDLE_SCHEMA, bundle["schema"])
            self.assertEqual(receipt["worker_operation_id"], bundle["source"]["worker_operation_id"])
            self.assertEqual(18, bundle["summary"]["source_artifact_count"])
            self.assertEqual(2, bundle["summary"]["marketplace_asset_count"])
            self.assertTrue(bundle["summary"]["frontend_bundle_replayed"])
            self.assertEqual(TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
            self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_trust_network_worker_bundle_renders_and_extracts_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, _, sources, _ = self._sources(tmp)
            bundle_path = tmp / "trust-network-worker-bundle.json"
            markdown_path = tmp / "trust-network-worker-bundle.md"
            out_dir = tmp / "extracted"
            write_trust_network_worker_bundle(bundle_path, bundle)
            write_trust_network_worker_bundle_markdown(markdown_path, bundle)
            extracted = extract_trust_network_worker_bundle_sources(bundle, out_dir)
            names = {record["name"] for record in extracted}
            asset_path = sources["catalog"]["assets"][0]["path"]

            self.assertIn("TrustAI Trust Network Worker Bundle", render_trust_network_worker_bundle_markdown(bundle))
            self.assertTrue(markdown_path.exists())
            self.assertIn("frontend_bundle", names)
            self.assertIn("marketplace_asset_0", names)
            self.assertEqual(sources["frontend_bundle_path"].read_bytes(), (out_dir / "frontend_bundle.js").read_bytes())
            self.assertEqual((ROOT / asset_path).read_bytes(), (out_dir / asset_path).read_bytes())

    def test_trust_network_worker_bundle_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle, _, _, _ = self._sources(Path(tmp_dir))
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["marketplace_settlement"]["invoice"]["status"] = "void"
            result = verify_trust_network_worker_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertIn("trust-network worker bundle source artifact does not match embedded source: marketplace_settlement", result.errors)

    def test_trust_network_worker_bundle_detects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle, _, _, _ = self._sources(Path(tmp_dir))
            tampered = copy.deepcopy(bundle)
            for artifact in tampered["source_artifacts"]:
                if artifact["name"] == "marketplace_distribution":
                    artifact["content_b64"] = base64.b64encode(b'{"tampered": true}').decode("ascii")
                    break
            result = verify_trust_network_worker_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertIn("trust-network worker bundle source artifact sha256 mismatch: marketplace_distribution", result.errors)

    def test_trust_network_worker_bundle_rejects_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle, _, _, _ = self._sources(Path(tmp_dir))
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["worker_receipt"]["credential"]["token"] = "raw-secret"
            result = verify_trust_network_worker_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("secret-like field must be redacted reference: sources.worker_receipt.credential.token" in error for error in result.errors))

    def test_cli_trust_network_worker_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, _, sources, paths = self._sources(tmp)
            bundle_path = tmp / "cli-trust-network-worker-bundle.json"
            markdown_path = tmp / "cli-trust-network-worker-bundle.md"
            render_path = tmp / "cli-rendered.md"
            extract_dir = tmp / "cli-extracted"
            entry_path = tmp / "cli-trust-network-worker-bundle-entry.json"
            state_path = tmp / "cli-trust-network-worker-bundle-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
                str(paths["worker_receipt"]),
                "--service-attestation",
                str(paths["service_attestation"]),
                str(paths["registry_receipt"]),
                "--manifest",
                str(paths["trust_network_manifest"]),
                "--vendor-identity",
                str(paths["vendor_identity_receipt"]),
                "--identity-attestation",
                str(paths["identity_provider_attestation"]),
                "--identity-payload",
                str(paths["identity_payload"]),
                "--procurement-receipt",
                str(paths["procurement_receipt"]),
                "--procurement-integration",
                str(paths["procurement_integration_receipt"]),
                "--pack",
                str(paths["proof_packs"][0]),
                "--registry-status",
                str(paths["registry_status_receipt"]),
                "--marketplace-catalog",
                str(paths["marketplace_catalog"]),
                "--marketplace-distribution",
                str(paths["marketplace_distribution"]),
                "--frontend-bundle",
                str(sources["frontend_bundle_path"]),
                "--marketplace-author-governance",
                str(paths["marketplace_author_governance"]),
                "--marketplace-settlement",
                str(paths["marketplace_settlement"]),
                "--root",
                str(ROOT),
            ]
            commands = [
                base
                + [
                    "trust-network-worker-bundle",
                    *source_args,
                    "--mode",
                    "procurement-review",
                    "--environment",
                    "aitrade-prod",
                    "--reviewer-ref",
                    "oidc:buyer.example/procurement-reviewer",
                    "--generated-at",
                    "2026-07-12T04:00:00Z",
                    "--out",
                    str(bundle_path),
                    "--markdown",
                    str(markdown_path),
                ],
                base + ["trust-network-worker-bundle-verify", str(bundle_path)],
                base + ["trust-network-worker-bundle-render", str(bundle_path), "--out", str(render_path)],
                base + ["trust-network-worker-bundle-extract", str(bundle_path), "--out-dir", str(extract_dir)],
                base
                + [
                    "trust-network-worker-bundle-append",
                    str(bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "trust-network-worker-bundle-local",
                    "--out",
                    str(entry_path),
                ],
            ]
            for command in commands:
                completed = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(0, completed.returncode, completed.stderr)

            created = json.loads(bundle_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            self.assertEqual(bundle["source"]["worker_operation_id"], created["source"]["worker_operation_id"])
            self.assertEqual(created["bundle_id"], entry["payload"]["bundle_id"])
            self.assertTrue(markdown_path.exists())
            self.assertTrue(render_path.exists())
            self.assertTrue((extract_dir / "frontend_bundle.js").exists())
            self.assertTrue((extract_dir / sources["catalog"]["assets"][0]["path"]).exists())


if __name__ == "__main__":
    unittest.main()
