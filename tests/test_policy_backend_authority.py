import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.policy_backend_authority import (
    POLICY_BACKEND_AUTHORITY_ENTRY_TYPE,
    POLICY_BACKEND_AUTHORITY_SCHEMA,
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    append_policy_backend_authority_dossier,
    build_policy_backend_authority_dossier,
    verify_policy_backend_authority_dossier,
)

from tests import test_policy_backend_provider_bundle as bundle_fixtures


ROOT = bundle_fixtures.ROOT


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class PolicyBackendAuthorityTests(unittest.TestCase):
    def _bundle(self, tmp: Path):
        helper = bundle_fixtures.PolicyBackendProviderBundleTests()
        return helper._bundle(tmp)

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "opa-cedar-backend-fleet",
                "authority_kind": "hosted-service",
                "evidence_ref": "service:policy-backend-fleet/aitrade-prod",
                "evidence_hash": "sha256:policy-backend-fleet-authority",
                "description": "Hosted OPA/Cedar backend fleet deployment export.",
                "issuer": "TrustAI Cloud",
                "subject": "aitrade-prod policy backend fleet",
                "source_uri": "https://ops.example/trustai/policy-backend/aitrade-prod",
                "issued_at": "2026-07-04T00:00:00Z",
                "expires_at": "2026-07-11T00:00:00Z",
            },
            {
                "requirement_id": "scheduler-queue-lease",
                "authority_kind": "provider-api",
                "evidence_ref": "provider:redpanda-postgres/policy-backend/scheduler-queue-lease",
                "evidence_hash": "sha256:policy-backend-scheduler-authority",
                "description": "Provider scheduler, queue, lease, checkpoint, and cursor export.",
                "issuer": "Example Provider",
                "subject": "aitrade-prod policy backend scheduler",
                "source_uri": "https://provider.example/exports/policy-backend/scheduler",
                "issued_at": "2026-07-04T00:10:00Z",
                "expires_at": "2026-07-11T00:10:00Z",
            },
        ]

    def _dossier(self, tmp: Path, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None):
        sources, bundle, paths = self._bundle(tmp)
        dossier = build_policy_backend_authority_dossier(
            bundle,
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:policy-backend-authority/lg-trace-001",
            authority_ref="authority:policy-backend/aitrade-prod",
            producer_ref="oidc:trustai.example/policy-backend-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-04T05:20:00Z",
        )
        return sources, bundle, paths, dossier

    def test_policy_backend_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources, bundle, _, dossier = self._dossier(tmp)

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=bundle)
            chain = EvidenceChain.load(tmp / "policy-backend-authority-chain.json", tenant_id="policy-backend-authority-test")
            entry = append_policy_backend_authority_dossier(chain, dossier, provider_bundle=bundle)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_BACKEND_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertEqual(2, result.fresh_evidence_count)
            self.assertTrue(any("missing for" in warning for warning in result.warnings), result.warnings)
            self.assertEqual(POLICY_BACKEND_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(bundle["bundle_id"], entry["payload"]["provider_bundle_binding"]["bundle_id"])
            self.assertEqual({"deferred": 1, "passed": 5}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)
            self.assertTrue(sources["chain"].verify_all().ok)

    def test_policy_backend_authority_detects_bundle_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, _, dossier = self._dossier(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["source"]["provider"] = "other-provider"

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("provider_bundle_binding does not match" in error for error in result.errors), result.errors)

    def test_policy_backend_authority_requires_freshness_when_strict(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence = [dict(self._authority_evidence()[0])]
            evidence[0].pop("issued_at")
            evidence[0].pop("expires_at")
            _, bundle, _, dossier = self._dossier(tmp, authority_evidence=evidence)

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=bundle, require_fresh=True)

            self.assertFalse(result.ok)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_policy_backend_authority_rejects_incomplete_production_claim(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, _, dossier = self._dossier(tmp, mode="production-dossier")

            result = verify_policy_backend_authority_dossier(dossier, provider_bundle=bundle)

            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_cli_policy_backend_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, _, _ = self._dossier(tmp)
            bundle_path = tmp / "policy-backend-provider-export-bundle.json"
            dossier_path = tmp / "policy-backend-authority.json"
            entry_path = tmp / "policy-backend-authority-entry.json"
            state_path = tmp / "policy-backend-authority-chain.json"
            _write_json(bundle_path, bundle)

            evidence_arg = (
                "opa-cedar-backend-fleet,hosted-service,service:policy-backend-fleet/aitrade-prod,"
                "sha256:policy-backend-fleet-authority,Hosted OPA/Cedar backend fleet deployment export;"
                "issuer=TrustAI Cloud;subject=aitrade-prod policy backend fleet;"
                "source_uri=https://ops.example/trustai/policy-backend/aitrade-prod;"
                "issued_at=2026-07-04T00:00:00Z;expires_at=2026-07-11T00:00:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-authority",
                    str(bundle_path),
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:policy-backend-authority/lg-trace-001",
                    "--authority-ref",
                    "authority:policy-backend/aitrade-prod",
                    "--producer-ref",
                    "oidc:trustai.example/policy-backend-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-04T05:20:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-authority-verify",
                    str(dossier_path),
                    "--provider-bundle",
                    str(bundle_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-authority-append",
                    str(dossier_path),
                    "--provider-bundle",
                    str(bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-authority-local",
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
