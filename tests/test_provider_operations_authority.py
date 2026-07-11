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
from trustai.provider_operations_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE,
    PROVIDER_OPERATIONS_AUTHORITY_SCHEMA,
    append_provider_operations_authority_dossier,
    build_provider_operations_authority_dossier,
    verify_provider_operations_authority_dossier,
)

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class ProviderOperationsAuthorityTests(unittest.TestCase):
    def _service(self):
        attestation = json.loads((ROOT / "artifacts" / "provider-operations-service-attestation.json").read_text(encoding="utf-8"))
        return {}, attestation

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "hosted-callback-worker-fleet",
                "authority_kind": "hosted-service",
                "evidence_ref": "service:provider-ops/github-prod",
                "evidence_hash": "sha256:provider-ops-hosted-fleet-authority",
                "description": "Hosted provider operations callback and audit worker fleet export.",
                "issuer": "TrustAI Cloud",
                "subject": "aitrade-prod provider operations worker fleet",
                "source_uri": "https://ops.example/trustai/provider-ops/github-prod",
                "issued_at": "2026-07-08T05:30:00Z",
                "expires_at": "2026-07-15T05:30:00Z",
            },
            {
                "requirement_id": "provider-owned-vault-kms",
                "authority_kind": "kms-hsm",
                "evidence_ref": "kms:provider-ops/github-audit-token",
                "evidence_hash": "sha256:provider-ops-vault-kms-authority",
                "description": "Provider-owned KMS/vault audit export for credential custody.",
                "issuer": "Example KMS",
                "subject": "github provider audit token custody",
                "source_uri": "https://kms.example/audit/provider-ops/github",
                "issued_at": "2026-07-08T05:31:00Z",
                "expires_at": "2026-07-15T05:31:00Z",
            },
        ]

    def _dossier(self, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None):
        sources, attestation = self._service()
        dossier = build_provider_operations_authority_dossier(
            attestation,
            **sources,
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:provider-operations-authority/github-prod",
            authority_ref="authority:provider-operations/github-prod",
            producer_ref="oidc:trustai.example/provider-operations-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-08T05:35:00Z",
        )
        return sources, attestation, dossier

    def test_provider_operations_authority_verifies_and_appends(self):
        sources, attestation, dossier = self._dossier()

        result = verify_provider_operations_authority_dossier(dossier, service_attestation=attestation, **sources)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="provider-operations-authority-test")
            entry = append_provider_operations_authority_dossier(chain, dossier, service_attestation=attestation, **sources)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_OPERATIONS_AUTHORITY_SCHEMA, dossier["schema"])
        self.assertEqual(2, result.covered_count)
        self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
        self.assertEqual(2, result.fresh_evidence_count)
        self.assertTrue(any("missing for" in warning for warning in result.warnings), result.warnings)
        self.assertEqual(PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
        self.assertEqual(attestation["attestation_id"], entry["payload"]["service_attestation_binding"]["attestation_id"])
        self.assertEqual({"deferred": 1, "passed": 5}, entry["payload"]["control_summary"])

    def test_provider_operations_authority_detects_service_tamper(self):
        sources, attestation, dossier = self._dossier()
        tampered = copy.deepcopy(attestation)
        tampered["service"]["provider"] = "gitlab"

        result = verify_provider_operations_authority_dossier(dossier, service_attestation=tampered, **sources)

        self.assertFalse(result.ok)
        self.assertTrue(any("service_attestation_binding does not match" in error for error in result.errors), result.errors)

    def test_provider_operations_authority_requires_complete_binding_without_source(self):
        _, _, dossier = self._dossier()
        tampered = copy.deepcopy(dossier)
        tampered["service_attestation_binding"].pop("source_schemas")
        body = without_keys(tampered, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        tampered["dossier_id"] = dossier_id
        tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "provider_operations_authority": body})]

        result = verify_provider_operations_authority_dossier(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(
            any("service_attestation_binding.source_schemas is required" in error for error in result.errors),
            result.errors,
        )

    def test_provider_operations_authority_requires_freshness_when_strict(self):
        evidence = [dict(self._authority_evidence()[0])]
        evidence[0].pop("issued_at")
        evidence[0].pop("expires_at")
        sources, attestation, dossier = self._dossier(authority_evidence=evidence)

        result = verify_provider_operations_authority_dossier(dossier, service_attestation=attestation, **sources, require_fresh=True)

        self.assertFalse(result.ok)
        self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_provider_operations_authority_rejects_incomplete_production_claim(self):
        sources, attestation, dossier = self._dossier(mode="production-dossier")

        result = verify_provider_operations_authority_dossier(dossier, service_attestation=attestation, **sources)

        self.assertFalse(result.ok)
        self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_cli_provider_operations_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources, attestation, _ = self._dossier()
            attestation_path = tmp / "provider-operations-service-attestation.json"
            dossier_path = tmp / "provider-operations-authority.json"
            entry_path = tmp / "provider-operations-authority-entry.json"
            state_path = tmp / "provider-operations-authority-chain.json"
            _write_json(attestation_path, attestation)

            source_args: list[str] = []
            evidence_arg = (
                "hosted-callback-worker-fleet,hosted-service,service:provider-ops/github-prod,"
                "sha256:provider-ops-hosted-fleet-authority,Hosted provider operations callback and audit worker fleet export;"
                "issuer=TrustAI Cloud;subject=aitrade-prod provider operations worker fleet;"
                "source_uri=https://ops.example/trustai/provider-ops/github-prod;"
                "issued_at=2026-07-08T05:30:00Z;expires_at=2026-07-15T05:30:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-operations-authority",
                    str(attestation_path),
                    *source_args,
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:provider-operations-authority/github-prod",
                    "--authority-ref",
                    "authority:provider-operations/github-prod",
                    "--producer-ref",
                    "oidc:trustai.example/provider-operations-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-08T05:35:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-operations-authority-verify", str(dossier_path), str(attestation_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-operations-authority-append",
                    str(dossier_path),
                    str(attestation_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-operations-authority-local",
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
