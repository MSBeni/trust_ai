
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_insurer_partner_service import InsurerPartnerServiceTests
from trustai.actuarial import write_actuarial_corpus, write_actuarial_product
from trustai.chain import EvidenceChain
from trustai.insurer import write_insurer_telemetry
from trustai.insurer_partner_service import write_insurer_partner_service_attestation
from trustai.insurer_partner_worker import (
    INSURER_PARTNER_WORKER_ENTRY_TYPE,
    INSURER_PARTNER_WORKER_SCHEMA,
    append_insurer_partner_worker_receipt,
    build_insurer_partner_worker_receipt,
    verify_insurer_partner_worker_receipt,
    write_insurer_partner_worker_receipt,
)
from trustai.underwriting_quote import write_underwriting_quote


ROOT = Path(__file__).resolve().parents[1]


class InsurerPartnerWorkerTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = InsurerPartnerServiceTests()
        chain, telemetry, quote, corpus, product, frontend_bundle_path, frontend_bundle_hash = helper._fixtures(tmp)
        service = helper._attestation(telemetry, quote, corpus, product, frontend_bundle_path)
        return {
            "chain": chain,
            "telemetry": telemetry,
            "quote": quote,
            "corpus": corpus,
            "product": product,
            "service": service,
            "frontend_bundle_path": frontend_bundle_path,
            "frontend_bundle_hash": frontend_bundle_hash,
        }

    def _receipt(self, sources):
        return build_insurer_partner_worker_receipt(
            sources["service"],
            telemetry=sources["telemetry"],
            underwriting_quote=sources["quote"],
            actuarial_product=sources["product"],
            actuarial_corpora=[sources["corpus"]],
            frontend_bundle_path=sources["frontend_bundle_path"],
            mode="partner-api-worker",
            environment="aitrade-prod",
            worker_ref="worker:insurer-partner/underwriting",
            run_ref="worker-run:insurer-partner/underwriting/2026-07-08T06:05:00Z",
            operation_kind="underwriting_quote_delivery",
            actor_ref="oidc:trustai.example/insurer-partner-worker",
            schedule_ref="schedule:insurer-partner/underwriting/5m",
            cadence_seconds=300,
            lease_ref="lease:insurer-partner/underwriting/2026-07-08T06:05:00Z",
            checkpoint_ref="checkpoint:insurer-partner/underwriting",
            checkpoint_hash="sha256:insurer-partner-worker-checkpoint",
            previous_cursor_ref="underwriter:quotes/cursor/before",
            next_cursor_ref="underwriter:quotes/cursor/after",
            queue_ref="queue:insurer-partner/delivery",
            queue_message_ref="queue-message:insurer-partner/underwriting/aitrade",
            destination_ref="underwriter:example/api/v1/quotes",
            delivery_log_ref="delivery-log:insurer-partner/underwriter",
            delivery_log_root="sha256:insurer-partner-worker-delivery-root",
            partner_event_log_ref="underwriter:event-log/quote-bindings",
            partner_event_log_root="sha256:insurer-partner-worker-partner-event-root",
            policy_system_ref="policy-system:underwriter/bindings",
            policy_workflow_ref="policy-workflow:underwriter/bindings/aitrade",
            policy_workflow_hash="sha256:insurer-partner-worker-policy-workflow",
            policy_binding_ref="policy-binding:underwriter/aitrade",
            policy_binding_hash="sha256:insurer-partner-worker-policy-binding",
            workflow_status="bound",
            request_hash="sha256:insurer-partner-worker-request",
            response_status=201,
            response_hash="sha256:insurer-partner-worker-response",
            metrics_ref="metrics:insurer-partner/workers",
            audit_log_ref="audit-log:insurer-partner/workers",
            audit_log_root="sha256:insurer-partner-worker-audit-root",
            access_log_ref="access-log:insurer-partner/workers",
            access_log_root="sha256:insurer-partner-worker-access-root",
            credential_ref="env:INSURER_PARTNER_WORKER_TOKEN",
            partner_credential_ref="env:UNDERWRITER_WORKER_TOKEN",
            retention_until="2033-07-08T00:00:00Z",
            evidence_refs=["evidence:insurer-partner/worker"],
            started_at="2026-07-08T06:05:00Z",
            completed_at="2026-07-08T06:06:00Z",
            next_run_at="2026-07-08T06:10:00Z",
            now="2026-07-09T00:00:00Z",
        )

    def test_insurer_partner_worker_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            result = verify_insurer_partner_worker_receipt(
                receipt,
                service_attestation=sources["service"],
                telemetry=sources["telemetry"],
                underwriting_quote=sources["quote"],
                actuarial_product=sources["product"],
                actuarial_corpora=[sources["corpus"]],
                frontend_bundle_path=sources["frontend_bundle_path"],
                now="2026-07-09T00:00:00Z",
            )
            entry = append_insurer_partner_worker_receipt(
                sources["chain"],
                receipt,
                service_attestation=sources["service"],
                telemetry=sources["telemetry"],
                underwriting_quote=sources["quote"],
                actuarial_product=sources["product"],
                actuarial_corpora=[sources["corpus"]],
                frontend_bundle_path=sources["frontend_bundle_path"],
                now="2026-07-09T00:00:00Z",
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(INSURER_PARTNER_WORKER_SCHEMA, receipt["schema"])
            self.assertEqual("partner-api-worker", receipt["mode"])
            self.assertEqual(sources["service"]["attestation_id"], receipt["service"]["attestation_id"])
            self.assertEqual(INSURER_PARTNER_WORKER_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])
            self.assertTrue(sources["chain"].verify_all().ok)

    def test_insurer_partner_worker_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sources = self._sources(Path(tmp_dir))
            receipt = self._receipt(sources)
            tampered = copy.deepcopy(sources["telemetry"])
            tampered["risk_score"] = 1

            result = verify_insurer_partner_worker_receipt(
                receipt,
                service_attestation=sources["service"],
                telemetry=tampered,
                underwriting_quote=sources["quote"],
                actuarial_product=sources["product"],
                actuarial_corpora=[sources["corpus"]],
                frontend_bundle_path=sources["frontend_bundle_path"],
                now="2026-07-09T00:00:00Z",
            )

            self.assertFalse(result.ok)
            self.assertIn("insurer partner worker source artifact hash mismatch: insurer-risk-telemetry", result.errors)
            self.assertIn("insurer partner worker service source: insurer partner service source_artifacts do not match supplied source artifacts", result.errors)

    def test_cli_insurer_partner_worker_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            service_path = tmp / "insurer-partner-service-attestation.json"
            telemetry_path = tmp / "insurer-risk-telemetry.json"
            quote_path = tmp / "underwriting-quote.json"
            corpus_path = tmp / "actuarial-corpus.json"
            product_path = tmp / "actuarial-product.json"
            worker_path = tmp / "insurer-partner-worker.json"
            entry_path = tmp / "insurer-partner-worker-entry.json"
            state_path = tmp / "insurer-partner-worker-chain.json"
            write_insurer_partner_service_attestation(service_path, sources["service"])
            write_insurer_telemetry(telemetry_path, sources["telemetry"])
            write_underwriting_quote(quote_path, sources["quote"])
            write_actuarial_corpus(corpus_path, sources["corpus"])
            write_actuarial_product(product_path, sources["product"])

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(service_path),
                str(telemetry_path),
                str(quote_path),
                "--actuarial-product",
                str(product_path),
                "--actuarial-corpus",
                str(corpus_path),
                "--frontend-bundle",
                str(sources["frontend_bundle_path"]),
                "--now",
                "2026-07-09T00:00:00Z",
            ]
            worker_args = [
                "--mode", "partner-api-worker",
                "--environment", "aitrade-prod",
                "--worker-ref", "worker:insurer-partner/underwriting",
                "--run-ref", "worker-run:insurer-partner/underwriting/2026-07-08T06:05:00Z",
                "--operation-kind", "underwriting_quote_delivery",
                "--actor-ref", "oidc:trustai.example/insurer-partner-worker",
                "--schedule-ref", "schedule:insurer-partner/underwriting/5m",
                "--cadence-seconds", "300",
                "--lease-ref", "lease:insurer-partner/underwriting/2026-07-08T06:05:00Z",
                "--checkpoint-ref", "checkpoint:insurer-partner/underwriting",
                "--checkpoint-hash", "sha256:insurer-partner-worker-checkpoint",
                "--previous-cursor-ref", "underwriter:quotes/cursor/before",
                "--next-cursor-ref", "underwriter:quotes/cursor/after",
                "--queue-ref", "queue:insurer-partner/delivery",
                "--queue-message-ref", "queue-message:insurer-partner/underwriting/aitrade",
                "--destination-ref", "underwriter:example/api/v1/quotes",
                "--delivery-log-ref", "delivery-log:insurer-partner/underwriter",
                "--delivery-log-root", "sha256:insurer-partner-worker-delivery-root",
                "--partner-event-log-ref", "underwriter:event-log/quote-bindings",
                "--partner-event-log-root", "sha256:insurer-partner-worker-partner-event-root",
                "--policy-system-ref", "policy-system:underwriter/bindings",
                "--policy-workflow-ref", "policy-workflow:underwriter/bindings/aitrade",
                "--policy-workflow-hash", "sha256:insurer-partner-worker-policy-workflow",
                "--policy-binding-ref", "policy-binding:underwriter/aitrade",
                "--policy-binding-hash", "sha256:insurer-partner-worker-policy-binding",
                "--workflow-status", "bound",
                "--request-hash", "sha256:insurer-partner-worker-request",
                "--response-status", "201",
                "--response-hash", "sha256:insurer-partner-worker-response",
                "--metrics-ref", "metrics:insurer-partner/workers",
                "--audit-log-ref", "audit-log:insurer-partner/workers",
                "--audit-log-root", "sha256:insurer-partner-worker-audit-root",
                "--access-log-ref", "access-log:insurer-partner/workers",
                "--access-log-root", "sha256:insurer-partner-worker-access-root",
                "--credential-ref", "env:INSURER_PARTNER_WORKER_TOKEN",
                "--partner-credential-ref", "env:UNDERWRITER_WORKER_TOKEN",
                "--retention-until", "2033-07-08T00:00:00Z",
                "--evidence-ref", "evidence:insurer-partner/worker",
                "--started-at", "2026-07-08T06:05:00Z",
                "--completed-at", "2026-07-08T06:06:00Z",
                "--next-run-at", "2026-07-08T06:10:00Z",
                "--out", str(worker_path),
            ]
            commands = [
                [sys.executable, "-m", "trustai", "insurer-partner-worker", *source_args, *worker_args],
                [sys.executable, "-m", "trustai", "insurer-partner-worker-verify", str(worker_path), *source_args],
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "insurer-partner-worker-append",
                    str(worker_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "insurer-partner-worker-local",
                    "--out",
                    str(entry_path),
                ],
            ]
            for command in commands:
                completed = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(0, completed.returncode, completed.stderr)

            receipt = json.loads(worker_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            self.assertEqual("partner-api-worker", receipt["mode"])
            self.assertEqual(receipt["worker_operation_id"], entry["payload"]["worker_operation_id"])


if __name__ == "__main__":
    unittest.main()

