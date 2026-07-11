import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import tests.test_insurer_partner_worker as worker_test_helpers
from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.crypto import sign_value
from trustai.insurer_partner_authority import (
    INSURER_PARTNER_AUTHORITY_ENTRY_TYPE,
    INSURER_PARTNER_AUTHORITY_SCHEMA,
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    append_insurer_partner_authority_dossier,
    build_insurer_partner_authority_dossier,
    verify_insurer_partner_authority_dossier,
)
from trustai.insurer_partner_worker_bundle import build_insurer_partner_worker_bundle

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class InsurerPartnerAuthorityTests(unittest.TestCase):
    def _sources(self, tmp: Path) -> dict:
        helper = worker_test_helpers.InsurerPartnerWorkerTests(methodName="test_insurer_partner_worker_verifies_and_appends")
        sources = helper._sources(tmp)
        worker = helper._receipt(sources)
        paths = {
            "worker_receipt": tmp / "insurer-partner-worker.json",
            "service_attestation": tmp / "insurer-partner-service-attestation.json",
            "telemetry": tmp / "insurer-risk-telemetry.json",
            "underwriting_quote": tmp / "underwriting-quote.json",
            "actuarial_product": tmp / "actuarial-product.json",
            "actuarial_corpora": [tmp / "actuarial-corpus.json"],
            "frontend_bundle": sources["frontend_bundle_path"],
        }
        _write_json(paths["worker_receipt"], worker)
        _write_json(paths["service_attestation"], sources["service"])
        _write_json(paths["telemetry"], sources["telemetry"])
        _write_json(paths["underwriting_quote"], sources["quote"])
        _write_json(paths["actuarial_product"], sources["product"])
        _write_json(paths["actuarial_corpora"][0], sources["corpus"])
        worker_bundle = build_insurer_partner_worker_bundle(
            worker,
            sources["service"],
            sources["telemetry"],
            sources["quote"],
            actuarial_product=sources["product"],
            actuarial_corpora=[sources["corpus"]],
            frontend_bundle_path=sources["frontend_bundle_path"],
            artifact_paths=paths,
            mode="underwriter-review",
            environment="aitrade-prod",
            reviewer_ref="oidc:underwriter.example/trustai-reviewer",
            generated_at="2026-07-09T00:00:00Z",
            now="2026-07-09T00:00:00Z",
        )
        return {**sources, "worker": worker, "worker_bundle": worker_bundle, "artifact_paths": paths}

    def _build_source_kwargs(self, sources: dict) -> dict:
        return {
            "worker_bundles": [sources["worker_bundle"]],
            "telemetry": sources["telemetry"],
            "underwriting_quote": sources["quote"],
            "actuarial_product": sources["product"],
            "actuarial_corpora": [sources["corpus"]],
            "frontend_bundle_path": sources["frontend_bundle_path"],
            "now": "2026-07-09T00:00:00Z",
        }

    def _verify_source_kwargs(self, sources: dict) -> dict:
        return {
            "worker_bundles": [sources["worker_bundle"]],
            "telemetry": sources["telemetry"],
            "underwriting_quote": sources["quote"],
            "actuarial_product": sources["product"],
            "actuarial_corpora": [sources["corpus"]],
            "frontend_bundle_path": sources["frontend_bundle_path"],
            "source_now": "2026-07-09T00:00:00Z",
        }

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "credentialed-partner-api-calls",
                "authority_kind": "insurer",
                "evidence_ref": "insurer:underwriter/api/aitrade",
                "evidence_hash": "sha256:insurer-partner-live-api-authority",
                "description": "Live underwriter API authority export.",
                "issuer": "Example AI Liability Underwriter",
                "subject": "aitrade-prod insurer partner API",
                "source_uri": "https://underwriter.example/audit/trustai/aitrade",
                "issued_at": "2026-07-08T06:20:00Z",
                "expires_at": "2026-07-15T06:20:00Z",
            },
            {
                "requirement_id": "partner-owned-authentication-events",
                "authority_kind": "identity-provider",
                "evidence_ref": "idp:underwriter/trustai/aitrade",
                "evidence_hash": "sha256:insurer-partner-idp-authority",
                "description": "Partner-owned authentication event export for insurer API sessions.",
                "issuer": "Example Underwriter IdP",
                "subject": "trustai insurer partner API sessions",
                "source_uri": "https://idp.underwriter.example/audit/trustai/aitrade",
                "issued_at": "2026-07-08T06:21:00Z",
                "expires_at": "2026-07-15T06:21:00Z",
            },
        ]

    def _dossier(self, tmp: Path, *, mode: str = "partner-dossier", authority_evidence: list[dict] | None = None):
        sources = self._sources(tmp)
        service = sources["service"]
        workers = [sources["worker"]]
        dossier = build_insurer_partner_authority_dossier(
            service,
            worker_receipts=workers,
            **self._build_source_kwargs(sources),
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:insurer-partner-authority/underwriter-prod",
            authority_ref="authority:insurer-partner/underwriter-prod",
            producer_ref="oidc:trustai.example/insurer-partner-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-08T06:25:00Z",
        )
        return sources, service, workers, dossier

    def test_insurer_partner_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources, service, workers, dossier = self._dossier(Path(tmp_dir))
            verify_kwargs = self._verify_source_kwargs(sources)

            result = verify_insurer_partner_authority_dossier(dossier, service_attestation=service, worker_receipts=workers, **verify_kwargs)
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="insurer-partner-authority-test")
            entry = append_insurer_partner_authority_dossier(chain, dossier, service_attestation=service, worker_receipts=workers, **verify_kwargs)

            self.assertTrue(chain.verify_all().ok)
            self.assertTrue(result.ok, result.errors)
            self.assertEqual(INSURER_PARTNER_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertEqual(2, result.fresh_evidence_count)
            self.assertTrue(any("missing for" in warning for warning in result.warnings), result.warnings)
            self.assertEqual(INSURER_PARTNER_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(service["attestation_id"], entry["payload"]["service_attestation_binding"]["attestation_id"])
            self.assertEqual(workers[0]["worker_operation_id"], entry["payload"]["worker_receipt_bindings"][0]["worker_operation_id"])
            self.assertEqual(sources["worker_bundle"]["bundle_id"], entry["payload"]["worker_bundle_bindings"][0]["bundle_id"])
            self.assertTrue(entry["payload"]["worker_bundle_bindings"][0]["frontend_bundle_replayed"])
            self.assertEqual({"deferred": 1, "passed": 6}, entry["payload"]["control_summary"])

    def test_insurer_partner_authority_detects_worker_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources, service, workers, dossier = self._dossier(Path(tmp_dir))
            tampered = copy.deepcopy(workers[0])
            tampered["worker"]["worker_ref"] = "worker:insurer-partner/tampered"

            result = verify_insurer_partner_authority_dossier(dossier, service_attestation=service, worker_receipts=[tampered], **self._verify_source_kwargs(sources))

            self.assertFalse(result.ok)
            self.assertTrue(any("worker_receipt_bindings do not match" in error for error in result.errors), result.errors)

    def test_insurer_partner_authority_detects_worker_bundle_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources, service, workers, dossier = self._dossier(Path(tmp_dir))
            tampered_sources = dict(sources)
            tampered_bundle = copy.deepcopy(sources["worker_bundle"])
            tampered_bundle["source"]["worker_operation_id"] = "tampered-worker-operation"
            tampered_sources["worker_bundle"] = tampered_bundle

            result = verify_insurer_partner_authority_dossier(dossier, service_attestation=service, worker_receipts=workers, **self._verify_source_kwargs(tampered_sources))

            self.assertFalse(result.ok)
            self.assertTrue(any("worker_bundle_bindings" in error or "worker bundle source" in error for error in result.errors), result.errors)

    def test_insurer_partner_authority_requires_complete_bindings_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, _, _, dossier = self._dossier(Path(tmp_dir))
            tampered = copy.deepcopy(dossier)
            tampered["worker_bundle_bindings"][0].pop("frontend_bundle_replayed")
            body = without_keys(tampered, "dossier_id", "signatures")
            dossier_id = content_hash(body)
            tampered["dossier_id"] = dossier_id
            tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "insurer_partner_authority": body})]

            result = verify_insurer_partner_authority_dossier(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(
                any("worker_bundle_binding.frontend_bundle_replayed is required" in error for error in result.errors),
                result.errors,
            )

    def test_insurer_partner_authority_requires_freshness_when_strict(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence = [dict(self._authority_evidence()[0])]
            evidence[0].pop("issued_at")
            evidence[0].pop("expires_at")
            sources, service, workers, dossier = self._dossier(Path(tmp_dir), authority_evidence=evidence)

            result = verify_insurer_partner_authority_dossier(dossier, service_attestation=service, worker_receipts=workers, **self._verify_source_kwargs(sources), require_fresh=True)

            self.assertFalse(result.ok)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_insurer_partner_authority_rejects_incomplete_production_claim(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources, service, workers, dossier = self._dossier(Path(tmp_dir), mode="production-dossier")

            result = verify_insurer_partner_authority_dossier(dossier, service_attestation=service, worker_receipts=workers, **self._verify_source_kwargs(sources))

            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_cli_insurer_partner_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources, service, workers, _ = self._dossier(tmp)
            service_path = tmp / "insurer-partner-service-attestation.json"
            worker_path = tmp / "insurer-partner-worker.json"
            worker_bundle_path = tmp / "insurer-partner-worker-bundle.json"
            telemetry_path = tmp / "insurer-risk-telemetry.json"
            quote_path = tmp / "underwriting-quote.json"
            product_path = tmp / "actuarial-product.json"
            corpus_path = tmp / "actuarial-corpus.json"
            dossier_path = tmp / "insurer-partner-authority.json"
            entry_path = tmp / "insurer-partner-authority-entry.json"
            state_path = tmp / "insurer-partner-authority-chain.json"
            _write_json(service_path, service)
            _write_json(worker_path, workers[0])
            _write_json(worker_bundle_path, sources["worker_bundle"])
            _write_json(telemetry_path, sources["telemetry"])
            _write_json(quote_path, sources["quote"])
            _write_json(product_path, sources["product"])
            _write_json(corpus_path, sources["corpus"])

            evidence_arg = (
                "credentialed-partner-api-calls,insurer,insurer:underwriter/api/aitrade,"
                "sha256:insurer-partner-live-api-authority,Live underwriter API authority export;"
                "issuer=Example AI Liability Underwriter;subject=aitrade-prod insurer partner API;"
                "source_uri=https://underwriter.example/audit/trustai/aitrade;"
                "issued_at=2026-07-08T06:20:00Z;expires_at=2026-07-15T06:20:00Z"
            )
            source_args = [
                str(service_path),
                "--worker", str(worker_path),
                "--worker-bundle", str(worker_bundle_path),
                "--telemetry", str(telemetry_path),
                "--quote", str(quote_path),
                "--actuarial-product", str(product_path),
                "--actuarial-corpus", str(corpus_path),
                "--frontend-bundle", str(sources["frontend_bundle_path"]),
                "--source-now", "2026-07-09T00:00:00Z",
            ]
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "insurer-partner-authority",
                    *source_args,
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:insurer-partner-authority/underwriter-prod",
                    "--authority-ref",
                    "authority:insurer-partner/underwriter-prod",
                    "--producer-ref",
                    "oidc:trustai.example/insurer-partner-authority-worker",
                    "--authority-evidence",
                    evidence_arg,
                    "--generated-at",
                    "2026-07-08T06:25:00Z",
                    "--out",
                    str(dossier_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "insurer-partner-authority-verify", str(dossier_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "insurer-partner-authority-append",
                    str(dossier_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "insurer-partner-authority-local",
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