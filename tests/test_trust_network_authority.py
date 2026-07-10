import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.trust_network_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    PRODUCTION_AUTHORITY_REQUIREMENTS,
    TRUST_NETWORK_AUTHORITY_ENTRY_TYPE,
    TRUST_NETWORK_AUTHORITY_SCHEMA,
    append_trust_network_authority_dossier,
    build_trust_network_authority_dossier,
    verify_trust_network_authority_dossier,
    write_trust_network_authority_dossier,
)
from trustai.trust_network_service import write_trust_network_service_attestation
from trustai.trust_network_worker import write_trust_network_worker_receipt

import tests.test_trust_network_worker as worker_test_helpers


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class TrustNetworkAuthorityTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = worker_test_helpers.TrustNetworkWorkerTests()
        sources = helper._sources(tmp)
        sources["worker"] = helper._receipt(sources)
        return sources

    def _source_kwargs(self, sources: dict) -> dict:
        return {
            "registry_receipt": sources["registry"],
            "trust_network_manifest": sources["manifest"],
            "vendor_identity_receipt": sources["vendor"],
            "identity_provider_attestation": sources["identity_attestation"],
            "identity_payload": sources["identity_payload"],
            "procurement_receipt": sources["procurement"],
            "procurement_integration_receipt": sources["integration"],
            "proof_packs": [sources["pack"]],
            "registry_status_receipt": sources["status"],
            "marketplace_catalog": sources["catalog"],
            "marketplace_distribution": sources["distribution"],
            "frontend_bundle_path": sources["frontend_bundle_path"],
            "marketplace_author_governance": sources["author"],
            "marketplace_settlement": sources["settlement"],
            "root": ROOT,
        }

    def _evidence(self, requirement_id: str = "hosted-registry-marketplace-worker-fleet") -> dict:
        return {
            "requirement_id": requirement_id,
            "authority_kind": "hosted-service",
            "evidence_ref": f"trust-network:authority/{requirement_id}",
            "evidence_hash": f"sha256:trust-network-authority-{requirement_id}",
            "description": f"Fresh authority evidence for {requirement_id}",
            "issuer": "TrustAI Hosted Ops",
            "subject": "aitrade-prod trust-network",
            "source_uri": f"https://trust-network.example/audit/{requirement_id}",
            "issued_at": "2026-07-14T06:10:00Z",
            "expires_at": "2026-07-21T06:10:00Z",
        }

    def _dossier(self, sources: dict, **overrides):
        values = {
            "service_attestation": sources["service"],
            "worker_receipts": [sources["worker"]],
            **self._source_kwargs(sources),
            "mode": "network-dossier",
            "environment": "aitrade-prod",
            "dossier_ref": "dossier:trust-network-authority/registry-marketplace-prod",
            "authority_ref": "authority:trust-network/registry-marketplace-prod",
            "producer_ref": "oidc:trustai.example/trust-network-authority-worker",
            "authority_evidence": [self._evidence(), self._evidence("production-scheduler-lease-storage")],
            "generated_at": "2026-07-14T06:15:00Z",
        }
        values.update(overrides)
        return build_trust_network_authority_dossier(**values)

    def test_trust_network_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources)
            result = verify_trust_network_authority_dossier(
                dossier,
                service_attestation=sources["service"],
                worker_receipts=[sources["worker"]],
                **self._source_kwargs(sources),
            )
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(dossier["schema"], TRUST_NETWORK_AUTHORITY_SCHEMA)
            self.assertEqual(result.covered_count, 2)
            self.assertEqual(result.required_count, len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS))
            self.assertEqual(result.fresh_evidence_count, 2)
            self.assertIn("live production trust-network authority is not claimed", "\n".join(result.warnings))

            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="trust-network-authority-test")
            entry = append_trust_network_authority_dossier(
                chain,
                dossier,
                service_attestation=sources["service"],
                worker_receipts=[sources["worker"]],
                **self._source_kwargs(sources),
            )
            self.assertEqual(entry["entry_type"], TRUST_NETWORK_AUTHORITY_ENTRY_TYPE)
            self.assertEqual(entry["payload"]["dossier_id"], dossier["dossier_id"])
            self.assertEqual(entry["payload"]["control_summary"], {"deferred": 1, "passed": 5})
            self.assertEqual(entry["payload"]["service_attestation_binding"]["attestation_id"], sources["service"]["attestation_id"])
            self.assertEqual(entry["payload"]["worker_receipt_bindings"][0]["worker_operation_id"], sources["worker"]["worker_operation_id"])

    def test_trust_network_authority_detects_worker_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources)
            tampered_worker = copy.deepcopy(sources["worker"])
            tampered_worker["worker"]["worker_ref"] = "worker:trust-network/tampered"
            result = verify_trust_network_authority_dossier(
                dossier,
                service_attestation=sources["service"],
                worker_receipts=[tampered_worker],
                **self._source_kwargs(sources),
            )
            self.assertFalse(result.ok)
            self.assertTrue(any("worker receipt binding" in error for error in result.errors))

    def test_trust_network_authority_strict_freshness_rejects_missing_window(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            evidence = self._evidence()
            evidence.pop("issued_at")
            evidence.pop("expires_at")
            dossier = self._dossier(sources, authority_evidence=[evidence])
            result = verify_trust_network_authority_dossier(
                dossier,
                service_attestation=sources["service"],
                worker_receipts=[sources["worker"]],
                require_fresh=True,
                **self._source_kwargs(sources),
            )
            self.assertFalse(result.ok)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors))

    def test_trust_network_authority_production_mode_requires_complete_coverage(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources, mode="production-dossier", authority_evidence=[self._evidence()])
            result = verify_trust_network_authority_dossier(
                dossier,
                service_attestation=sources["service"],
                worker_receipts=[sources["worker"]],
                **self._source_kwargs(sources),
            )
            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires every trust-network authority requirement" in error for error in result.errors))
    def test_trust_network_authority_production_mode_requires_fresh_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            evidence = []
            for requirement in PRODUCTION_AUTHORITY_REQUIREMENTS:
                item = self._evidence(requirement["id"])
                item["authority_kind"] = requirement["authority_kinds"][0]
                item["issued_at"] = "2026-07-01T00:00:00Z"
                item["expires_at"] = "2026-07-02T00:00:00Z"
                evidence.append(item)
            dossier = self._dossier(sources, mode="production-dossier", authority_evidence=evidence)
            result = verify_trust_network_authority_dossier(
                dossier,
                service_attestation=sources["service"],
                worker_receipts=[sources["worker"]],
                **self._source_kwargs(sources),
            )
            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires every trust-network authority evidence item to be fresh" in error for error in result.errors))

    def test_trust_network_authority_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            paths = {
                "pack": tmp / "proof-pack.json",
                "manifest": tmp / "trust-network-manifest.json",
                "vendor": tmp / "vendor-identity.json",
                "identity_payload": tmp / "identity-payload.json",
                "identity_attestation": tmp / "identity-attestation.json",
                "procurement": tmp / "procurement.json",
                "integration": tmp / "procurement-integration.json",
                "registry": tmp / "registry.json",
                "status": tmp / "registry-status.json",
                "catalog": tmp / "catalog.json",
                "distribution": tmp / "distribution.json",
                "service": tmp / "service.json",
                "author": tmp / "author-governance.json",
                "settlement": tmp / "settlement.json",
                "worker": tmp / "worker.json",
                "dossier": tmp / "authority.json",
                "entry": tmp / "authority-entry.json",
                "chain": tmp / "chain.json",
            }
            for key in ("pack", "manifest", "vendor", "identity_payload", "identity_attestation", "procurement", "integration", "registry", "status", "catalog", "distribution", "author", "settlement"):
                _write_json(paths[key], sources[key])
            write_trust_network_service_attestation(paths["service"], sources["service"])
            write_trust_network_worker_receipt(paths["worker"], sources["worker"])

            evidence = "hosted-registry-marketplace-worker-fleet,hosted-service,trust-network:hosted/workers,sha256:trust-network-hosted-worker-fleet,Hosted trust-network worker fleet export;issuer=TrustAI Hosted Ops;subject=aitrade-prod trust-network;source_uri=https://trust-network.example/audit/workers;issued_at=2026-07-14T06:10:00Z;expires_at=2026-07-21T06:10:00Z"
            source_args = [
                str(paths["registry"]),
                "--service-attestation", str(paths["service"]),
                "--worker", str(paths["worker"]),
                "--manifest", str(paths["manifest"]),
                "--vendor-identity", str(paths["vendor"]),
                "--identity-attestation", str(paths["identity_attestation"]),
                "--identity-payload", str(paths["identity_payload"]),
                "--procurement-receipt", str(paths["procurement"]),
                "--procurement-integration", str(paths["integration"]),
                "--pack", str(paths["pack"]),
                "--registry-status", str(paths["status"]),
                "--marketplace-catalog", str(paths["catalog"]),
                "--marketplace-distribution", str(paths["distribution"]),
                "--marketplace-author-governance", str(paths["author"]),
                "--marketplace-settlement", str(paths["settlement"]),
                "--frontend-bundle", str(sources["frontend_bundle_path"]),
                "--root", str(ROOT),
            ]
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            subprocess.check_call([
                sys.executable, "-m", "trustai", "trust-network-authority",
                *source_args,
                "--environment", "aitrade-prod",
                "--dossier-ref", "dossier:trust-network-authority/registry-marketplace-prod",
                "--authority-ref", "authority:trust-network/registry-marketplace-prod",
                "--producer-ref", "oidc:trustai.example/trust-network-authority-worker",
                "--authority-evidence", evidence,
                "--generated-at", "2026-07-14T06:15:00Z",
                "--out", str(paths["dossier"]),
            ], cwd=ROOT, env=env)
            subprocess.check_call([
                sys.executable, "-m", "trustai", "trust-network-authority-verify",
                str(paths["dossier"]),
                *source_args,
            ], cwd=ROOT, env=env)
            subprocess.check_call([
                sys.executable, "-m", "trustai", "trust-network-authority-append",
                str(paths["dossier"]),
                *source_args,
                "--state", str(paths["chain"]),
                "--tenant", "trust-network-authority-cli",
                "--out", str(paths["entry"]),
            ], cwd=ROOT, env=env)
            self.assertTrue(paths["entry"].exists())


if __name__ == "__main__":
    unittest.main()
