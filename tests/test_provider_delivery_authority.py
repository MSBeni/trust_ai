import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.provider_delivery_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE,
    PROVIDER_DELIVERY_AUTHORITY_SCHEMA,
    append_provider_delivery_authority_dossier,
    build_provider_delivery_authority_dossier,
    verify_provider_delivery_authority_dossier,
)

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class ProviderDeliveryAuthorityTests(unittest.TestCase):
    def _sources(self):
        service = json.loads((ROOT / "artifacts" / "provider-delivery-service-attestation.json").read_text(encoding="utf-8"))
        worker = json.loads((ROOT / "artifacts" / "provider-delivery-worker.json").read_text(encoding="utf-8"))
        return {}, service, [worker]

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "hosted-dispatch-worker-fleet",
                "authority_kind": "hosted-service",
                "evidence_ref": "service:provider-delivery/github-prod",
                "evidence_hash": "sha256:provider-delivery-hosted-fleet-authority",
                "description": "Hosted provider delivery dispatch worker fleet export.",
                "issuer": "TrustAI Cloud",
                "subject": "aitrade-prod provider delivery dispatch fleet",
                "source_uri": "https://ops.example/trustai/provider-delivery/github-prod",
                "issued_at": "2026-07-08T05:40:00Z",
                "expires_at": "2026-07-15T05:40:00Z",
            },
            {
                "requirement_id": "production-provider-credentials",
                "authority_kind": "kms-hsm",
                "evidence_ref": "kms:provider-delivery/github-token",
                "evidence_hash": "sha256:provider-delivery-credential-authority",
                "description": "Provider delivery token KMS custody and rotation audit export.",
                "issuer": "Example KMS",
                "subject": "github provider delivery token custody",
                "source_uri": "https://kms.example/audit/provider-delivery/github",
                "issued_at": "2026-07-08T05:41:00Z",
                "expires_at": "2026-07-15T05:41:00Z",
            },
        ]

    def _dossier(self, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None):
        sources, service, workers = self._sources()
        dossier = build_provider_delivery_authority_dossier(
            service,
            worker_receipts=workers,
            **sources,
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:provider-delivery-authority/github-prod",
            authority_ref="authority:provider-delivery/github-prod",
            producer_ref="oidc:trustai.example/provider-delivery-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-08T05:45:00Z",
        )
        return sources, service, workers, dossier

    def test_provider_delivery_authority_verifies_and_appends(self):
        sources, service, workers, dossier = self._dossier()

        result = verify_provider_delivery_authority_dossier(dossier, service_attestation=service, worker_receipts=workers, **sources)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-delivery-authority-test")
            entry = append_provider_delivery_authority_dossier(chain, dossier, service_attestation=service, worker_receipts=workers, **sources)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_DELIVERY_AUTHORITY_SCHEMA, dossier["schema"])
        self.assertEqual(2, result.covered_count)
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
        self.assertEqual(2, result.fresh_evidence_count)
        self.assertTrue(any("missing for" in warning for warning in result.warnings), result.warnings)
        self.assertEqual(PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
        self.assertEqual(service["attestation_id"], entry["payload"]["service_attestation_binding"]["attestation_id"])
        self.assertEqual(workers[0]["worker_operation_id"], entry["payload"]["worker_receipt_bindings"][0]["worker_operation_id"])
        self.assertEqual({"deferred": 1, "passed": 5}, entry["payload"]["control_summary"])

    def test_provider_delivery_authority_detects_worker_tamper(self):
        sources, service, workers, dossier = self._dossier()
        tampered = copy.deepcopy(workers[0])
        tampered["worker"]["worker_ref"] = "worker:provider-delivery/tampered"

        result = verify_provider_delivery_authority_dossier(dossier, service_attestation=service, worker_receipts=[tampered], **sources)

        self.assertFalse(result.ok)
        self.assertTrue(any("worker_receipt_bindings do not match" in error for error in result.errors), result.errors)

    def test_provider_delivery_authority_requires_freshness_when_strict(self):
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0].pop("issued_at")
        evidence[0].pop("expires_at")
        sources, service, workers, dossier = self._dossier(authority_evidence=evidence)

        result = verify_provider_delivery_authority_dossier(dossier, service_attestation=service, worker_receipts=workers, **sources, require_fresh=True)

        self.assertFalse(result.ok)
        self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_provider_delivery_authority_rejects_incomplete_production_claim(self):
        sources, service, workers, dossier = self._dossier(mode="production-dossier")

        result = verify_provider_delivery_authority_dossier(dossier, service_attestation=service, worker_receipts=workers, **sources)

        self.assertFalse(result.ok)
        self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_cli_provider_delivery_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources, service, workers, _ = self._dossier()
            service_path = tmp / "provider-delivery-service-attestation.json"
            worker_path = tmp / "provider-delivery-worker.json"
            dossier_path = tmp / "provider-delivery-authority.json"
            entry_path = tmp / "provider-delivery-authority-entry.json"
            state_path = tmp / "provider-delivery-authority-chain.json"
            _write_json(service_path, service)
            _write_json(worker_path, workers[0])

            evidence_arg = (
                "hosted-dispatch-worker-fleet,hosted-service,service:provider-delivery/github-prod,"
                "sha256:provider-delivery-hosted-fleet-authority,Hosted provider delivery dispatch worker fleet export;"
                "issuer=TrustAI Cloud;subject=aitrade-prod provider delivery dispatch fleet;"
                "source_uri=https://ops.example/trustai/provider-delivery/github-prod;"
                "issued_at=2026-07-08T05:40:00Z;expires_at=2026-07-15T05:40:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-delivery-authority",
                    str(service_path),
                    "--worker",
                    str(worker_path),
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:provider-delivery-authority/github-prod",
                    "--authority-ref",
                    "authority:provider-delivery/github-prod",
                    "--producer-ref",
                    "oidc:trustai.example/provider-delivery-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-08T05:45:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-delivery-authority-verify", str(dossier_path), str(service_path), "--worker", str(worker_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-delivery-authority-append",
                    str(dossier_path),
                    str(service_path),
                    "--worker",
                    str(worker_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-delivery-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(dossier_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
