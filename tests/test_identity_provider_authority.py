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
from trustai.identity_provider_attestation import write_identity_provider_attestation
from trustai.identity_provider_authority import (
    IDENTITY_PROVIDER_AUTHORITY_ENTRY_TYPE,
    IDENTITY_PROVIDER_AUTHORITY_SCHEMA,
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    append_identity_provider_authority_dossier,
    build_identity_provider_authority_dossier,
    verify_identity_provider_authority_dossier,
)
from trustai.identity_provider_lifecycle_operation import write_identity_provider_lifecycle_operation_receipt
from trustai.identity_provider_lifecycle_worker import write_identity_provider_lifecycle_worker_receipt
from trustai.identity_provider_session import write_identity_provider_session_receipt
from trustai.trust_network import write_trust_network_manifest
from trustai.vendor_identity import write_vendor_identity_receipt

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class IdentityProviderAuthorityTests(unittest.TestCase):
    def _sources(self, tmp: Path) -> dict:
        from tests.test_identity_provider_lifecycle_worker import IdentityProviderLifecycleWorkerTests

        helper = IdentityProviderLifecycleWorkerTests()
        sources = helper._sources(tmp)
        sources["worker"] = helper._receipt(sources)
        return sources

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "live-identity-provider-event-streams",
                "authority_kind": "identity-provider",
                "evidence_ref": "okta:system-log/query/aitrade-agent-events",
                "evidence_hash": "sha256:identity-provider-live-event-streams",
                "description": "Okta system-log export for governed agent lifecycle events.",
                "issuer": "Okta",
                "subject": "aitrade-prod governed agent identity events",
                "source_uri": "https://okta.example/system-log/aitrade-agent-events",
                "issued_at": "2026-07-12T02:10:00Z",
                "expires_at": "2026-07-19T02:10:00Z",
            },
            {
                "requirement_id": "credential-custody-and-kms",
                "authority_kind": "kms-hsm",
                "evidence_ref": "kms:identity-provider/lifecycle-worker-token",
                "evidence_hash": "sha256:identity-provider-kms-custody",
                "description": "KMS/HSM custody export for the identity lifecycle worker credential.",
                "issuer": "Example KMS",
                "subject": "identity lifecycle worker credential custody",
                "source_uri": "https://kms.example/audit/identity-provider/lifecycle-worker",
                "issued_at": "2026-07-12T02:11:00Z",
                "expires_at": "2026-07-19T02:11:00Z",
            },
        ]

    def _dossier(self, sources: dict, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None) -> dict:
        return build_identity_provider_authority_dossier(
            sources["worker"],
            lifecycle_operation_receipt=sources["lifecycle_operation"],
            identity_provider_attestation=sources["attestation"],
            identity_provider_session_receipt=sources["session"],
            identity_payload=sources["identity_payload"],
            identity_payload_path=sources["identity_payload_path"],
            vendor_identity_receipt=sources["vendor"],
            proof_packs=[sources["pack"]],
            trust_network_manifest=sources["manifest"],
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:identity-provider-authority/okta-prod",
            authority_ref="authority:identity-provider/okta-prod",
            producer_ref="oidc:trustai.example/identity-provider-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-12T02:12:00Z",
        )

    def _verify(self, dossier: dict, sources: dict, **kwargs):
        return verify_identity_provider_authority_dossier(
            dossier,
            worker_receipt=sources["worker"],
            lifecycle_operation_receipt=sources["lifecycle_operation"],
            identity_provider_attestation=sources["attestation"],
            identity_provider_session_receipt=sources["session"],
            identity_payload=sources["identity_payload"],
            identity_payload_path=sources["identity_payload_path"],
            vendor_identity_receipt=sources["vendor"],
            proof_packs=[sources["pack"]],
            trust_network_manifest=sources["manifest"],
            **kwargs,
        )

    def test_identity_provider_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources)
            result = self._verify(dossier, sources)
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="identity-provider-authority-test")
            entry = append_identity_provider_authority_dossier(
                chain,
                dossier,
                worker_receipt=sources["worker"],
                lifecycle_operation_receipt=sources["lifecycle_operation"],
                identity_provider_attestation=sources["attestation"],
                identity_provider_session_receipt=sources["session"],
                identity_payload=sources["identity_payload"],
                identity_payload_path=sources["identity_payload_path"],
                vendor_identity_receipt=sources["vendor"],
                proof_packs=[sources["pack"]],
                trust_network_manifest=sources["manifest"],
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(IDENTITY_PROVIDER_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertEqual(2, result.fresh_evidence_count)
            self.assertTrue(any("evidence missing for" in warning for warning in result.warnings), result.warnings)
            self.assertEqual(IDENTITY_PROVIDER_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(sources["worker"]["worker_operation_id"], entry["payload"]["worker_binding"]["worker_operation_id"])
            self.assertEqual({"deferred": 1, "passed": 5}, entry["payload"]["control_summary"])

    def test_identity_provider_authority_detects_worker_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources)
            tampered_sources = copy.deepcopy(sources)
            tampered_sources["worker"]["worker"]["run_ref"] = "worker-run:identity-provider/lifecycle/tampered"

            result = self._verify(dossier, tampered_sources)

            self.assertFalse(result.ok)
            self.assertTrue(any("worker_binding does not match" in error for error in result.errors), result.errors)

    def test_identity_provider_authority_requires_complete_binding_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources)
            cases = [
                ("worker_schema", "worker_binding.worker_schema is required"),
                ("metrics_ref", "worker_binding.metrics_ref is required"),
                ("session_revocation_log_root", "worker_binding.session_revocation_log_root is required"),
                ("control_summary", "worker_binding.control_summary is required"),
            ]
            for field, expected_error in cases:
                with self.subTest(field=field):
                    tampered = copy.deepcopy(dossier)
                    tampered["worker_binding"].pop(field)
                    body = without_keys(tampered, "dossier_id", "signatures")
                    dossier_id = content_hash(body)
                    tampered["dossier_id"] = dossier_id
                    tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "identity_provider_authority": body})]

                    result = verify_identity_provider_authority_dossier(tampered)

                    self.assertFalse(result.ok)
                    self.assertTrue(any(expected_error in error for error in result.errors), result.errors)
    def test_identity_provider_authority_requires_freshness_when_strict(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            evidence = [dict(self._authority_evidence()[0])]
            evidence[0].pop("issued_at")
            evidence[0].pop("expires_at")
            dossier = self._dossier(sources, authority_evidence=evidence)

            result = self._verify(dossier, sources, require_fresh=True)

            self.assertFalse(result.ok)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_identity_provider_authority_rejects_incomplete_production_claim(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            dossier = self._dossier(sources, mode="production-dossier")

            result = self._verify(dossier, sources)

            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_cli_identity_provider_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            paths = {
                "pack": tmp / "pack.json",
                "manifest": tmp / "manifest.json",
                "vendor": tmp / "vendor.json",
                "identity_payload": tmp / "identity-payload.json",
                "attestation": tmp / "identity-attestation.json",
                "session": tmp / "identity-session.json",
                "lifecycle": tmp / "identity-lifecycle-operation.json",
                "worker": tmp / "identity-lifecycle-worker.json",
                "dossier": tmp / "identity-provider-authority.json",
                "entry": tmp / "identity-provider-authority-entry.json",
                "chain": tmp / "identity-provider-authority-chain.json",
            }
            _write_json(paths["pack"], sources["pack"])
            write_trust_network_manifest(paths["manifest"], sources["manifest"])
            write_vendor_identity_receipt(paths["vendor"], sources["vendor"])
            paths["identity_payload"].write_text(sources["identity_payload_path"].read_text(encoding="utf-8"), encoding="utf-8")
            write_identity_provider_attestation(paths["attestation"], sources["attestation"])
            write_identity_provider_session_receipt(paths["session"], sources["session"])
            write_identity_provider_lifecycle_operation_receipt(paths["lifecycle"], sources["lifecycle_operation"])
            write_identity_provider_lifecycle_worker_receipt(paths["worker"], sources["worker"])
            source_args = [
                str(paths["worker"]),
                str(paths["lifecycle"]),
                str(paths["attestation"]),
                "--identity-payload",
                str(paths["identity_payload"]),
                "--vendor-identity",
                str(paths["vendor"]),
                "--manifest",
                str(paths["manifest"]),
                "--pack",
                str(paths["pack"]),
                "--identity-session",
                str(paths["session"]),
            ]
            evidence_arg = (
                "live-identity-provider-event-streams,identity-provider,okta:system-log/query/aitrade-agent-events,"
                "sha256:identity-provider-live-event-streams,Okta system-log export for governed agent lifecycle events;"
                "issuer=Okta;subject=aitrade-prod governed agent identity events;"
                "source_uri=https://okta.example/system-log/aitrade-agent-events;"
                "issued_at=2026-07-12T02:10:00Z;expires_at=2026-07-19T02:10:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "identity-provider-authority",
                    *source_args,
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:identity-provider-authority/okta-prod",
                    "--authority-ref",
                    "authority:identity-provider/okta-prod",
                    "--producer-ref",
                    "oidc:trustai.example/identity-provider-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-12T02:12:00Z",
                    "--out",
                    str(paths["dossier"]),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "identity-provider-authority-verify", str(paths["dossier"]), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "identity-provider-authority-append",
                    str(paths["dossier"]),
                    *source_args,
                    "--state",
                    str(paths["chain"]),
                    "--tenant",
                    "identity-provider-authority-local",
                    "--out",
                    str(paths["entry"]),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(paths["dossier"].exists())
            self.assertTrue(paths["entry"].exists())


if __name__ == "__main__":
    unittest.main()
