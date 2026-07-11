import copy
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.approval_callback import build_approval_callback
from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.cicd import build_slack_approval_request
from trustai.contracts import load_contract, register_contract
from trustai.crypto import sign_value
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.provider_approval_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE,
    PROVIDER_APPROVAL_AUTHORITY_SCHEMA,
    append_provider_approval_authority_dossier,
    build_provider_approval_authority_dossier,
    verify_provider_approval_authority_dossier,
    write_provider_approval_authority_dossier,
)
from trustai.provider_webhook import build_provider_webhook_receipt, write_provider_webhook_receipt

from tests import test_provider_delivery_authority as delivery_fixtures
from tests import test_provider_operations_authority as operations_fixtures

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _github_signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


class ProviderApprovalAuthorityTests(unittest.TestCase):
    def _resign_dossier(self, dossier: dict) -> None:
        body = without_keys(dossier, "dossier_id", "signatures")
        dossier_id = content_hash(body)
        dossier["dossier_id"] = dossier_id
        dossier["signatures"] = [sign_value({"dossier_id": dossier_id, "provider_approval_authority": body})]

    def _approval_sources(self, tmp: Path) -> tuple[dict, dict]:
        chain = EvidenceChain.load(tmp / "approval-chain.json", tenant_id="provider-approval-authority-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        results.pop("approvals", None)
        eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision)
        request = build_slack_approval_request(
            pack,
            channel="C07TRUSTAI",
            requested_roles=["model_risk"],
            requester="risk@example.com",
            callback_url="https://trustai.example/v0/approval-callbacks/slack",
        )
        callback = build_approval_callback(
            request,
            role="model_risk",
            approver="model-risk@example.com",
            approved_at="2026-07-08T06:00:00Z",
            reason="Approved from signed Slack callback.",
            external_user_id="U123",
            team_id="T456",
        )
        return request, callback

    def _webhook_receipt(self) -> dict:
        raw_body = b'{"action":"completed","check_suite":{"id":42}}'
        secret = "github-webhook-secret"
        headers = {
            "Content-Type": "application/json",
            "X-Hub-Signature-256": _github_signature(secret, raw_body),
            "X-GitHub-Delivery": "delivery-123",
            "X-GitHub-Event": "check_suite",
        }
        return build_provider_webhook_receipt("github", raw_body, headers, secret, received_at="2026-07-08T06:01:00Z")

    def _authority_sources(self) -> tuple[dict, dict]:
        _, _, _, delivery_authority = delivery_fixtures.ProviderDeliveryAuthorityTests()._dossier()
        _, _, operations_authority = operations_fixtures.ProviderOperationsAuthorityTests()._dossier()
        return delivery_authority, operations_authority

    def _authority_evidence(self) -> list[dict]:
        return [
            {
                "requirement_id": "hosted-approval-callback-ingress",
                "authority_kind": "hosted-service",
                "evidence_ref": "service:provider-approval/github-prod",
                "evidence_hash": "sha256:provider-approval-hosted-ingress-authority",
                "description": "Hosted approval callback ingress and worker fleet export.",
                "issuer": "TrustAI Cloud",
                "subject": "aitrade-prod provider approval callback fleet",
                "source_uri": "https://ops.example/trustai/provider-approval/github-prod",
                "issued_at": "2026-07-08T06:02:00Z",
                "expires_at": "2026-07-15T06:02:00Z",
            },
            {
                "requirement_id": "slack-interaction-signature-replay",
                "authority_kind": "provider-api",
                "evidence_ref": "slack:interaction/approval-callback/replay",
                "evidence_hash": "sha256:slack-approval-signature-replay-authority",
                "description": "Slack interaction signature replay export for approval callbacks.",
                "issuer": "Slack Enterprise Grid",
                "subject": "aitrade-prod Slack approval callbacks",
                "source_uri": "https://slack.example/audit/approval-callbacks",
                "issued_at": "2026-07-08T06:03:00Z",
                "expires_at": "2026-07-15T06:03:00Z",
            },
        ]

    def _dossier(self, request, callback, webhook, delivery_authority, operations_authority, *, mode: str = "provider-dossier", authority_evidence: list[dict] | None = None) -> dict:
        return build_provider_approval_authority_dossier(
            request,
            callback,
            webhook_receipts=[webhook],
            provider_delivery_authority=delivery_authority,
            provider_operations_authority=operations_authority,
            mode=mode,
            environment="aitrade-prod",
            dossier_ref="dossier:provider-approval-authority/github-prod",
            authority_ref="authority:provider-approval/github-prod",
            producer_ref="oidc:trustai.example/provider-approval-authority-worker",
            authority_evidence=authority_evidence if authority_evidence is not None else self._authority_evidence(),
            generated_at="2026-07-08T06:05:00Z",
        )

    def test_provider_approval_authority_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            request, callback = self._approval_sources(tmp)
            webhook = self._webhook_receipt()
            delivery_authority, operations_authority = self._authority_sources()
            dossier = self._dossier(request, callback, webhook, delivery_authority, operations_authority)
            result = verify_provider_approval_authority_dossier(
                dossier,
                approval_request=request,
                approval_callback=callback,
                webhook_receipts=[webhook],
                provider_delivery_authority=delivery_authority,
                provider_operations_authority=operations_authority,
            )
            chain = EvidenceChain.load(tmp / "authority-chain.json", tenant_id="provider-approval-authority-test")
            entry = append_provider_approval_authority_dossier(
                chain,
                dossier,
                approval_request=request,
                approval_callback=callback,
                webhook_receipts=[webhook],
                provider_delivery_authority=delivery_authority,
                provider_operations_authority=operations_authority,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(PROVIDER_APPROVAL_AUTHORITY_SCHEMA, dossier["schema"])
            self.assertEqual(2, result.covered_count)
            self.assertEqual(len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS), result.required_count)
            self.assertEqual(2, result.fresh_evidence_count)
            self.assertEqual(callback["callback_id"], dossier["source_binding"]["approval_callback"]["callback_id"])
            self.assertEqual(webhook["receipt_id"], dossier["source_binding"]["webhook_receipts"][0]["receipt_id"])
            self.assertTrue(any("evidence missing for" in warning for warning in result.warnings), result.warnings)
            self.assertEqual(PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(dossier["authority_evidence"][0]["source_context"], entry["payload"]["authority_evidence"][0]["source_context"])
            self.assertEqual({"deferred": 2, "passed": 5}, entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_provider_approval_authority_detects_callback_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            request, callback = self._approval_sources(tmp)
            webhook = self._webhook_receipt()
            delivery_authority, operations_authority = self._authority_sources()
            dossier = self._dossier(request, callback, webhook, delivery_authority, operations_authority)
            tampered_callback = copy.deepcopy(callback)
            tampered_callback["approver"] = "other-approver@example.com"

            result = verify_provider_approval_authority_dossier(
                dossier,
                approval_request=request,
                approval_callback=tampered_callback,
                webhook_receipts=[webhook],
                provider_delivery_authority=delivery_authority,
                provider_operations_authority=operations_authority,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("source_binding does not match" in error or "callback source" in error for error in result.errors), result.errors)

    def test_provider_approval_authority_rejects_resigned_authority_source_context_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            request, callback = self._approval_sources(tmp)
            webhook = self._webhook_receipt()
            delivery_authority, operations_authority = self._authority_sources()
            dossier = self._dossier(request, callback, webhook, delivery_authority, operations_authority)
            tampered = copy.deepcopy(dossier)
            item = tampered["authority_evidence"][0]
            item["source_context"]["callback_id"] = "callback:other"
            item["evidence_id"] = content_hash(without_keys(item, "evidence_id"))
            self._resign_dossier(tampered)

            result = verify_provider_approval_authority_dossier(
                tampered,
                approval_request=request,
                approval_callback=callback,
                webhook_receipts=[webhook],
                provider_delivery_authority=delivery_authority,
                provider_operations_authority=operations_authority,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("dossier_id does not match canonical provider approval authority body", result.errors)
            self.assertNotIn("provider approval authority signature verification failed", result.errors)
            self.assertIn("provider approval authority source_context does not match source binding: hosted-approval-callback-ingress", result.errors)

    def test_provider_approval_authority_rejects_resigned_control_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            request, callback = self._approval_sources(tmp)
            webhook = self._webhook_receipt()
            delivery_authority, operations_authority = self._authority_sources()
            dossier = self._dossier(request, callback, webhook, delivery_authority, operations_authority)
            tampered = copy.deepcopy(dossier)
            tampered["controls"][0]["status"] = "deferred"
            self._resign_dossier(tampered)

            result = verify_provider_approval_authority_dossier(
                tampered,
                approval_request=request,
                approval_callback=callback,
                webhook_receipts=[webhook],
                provider_delivery_authority=delivery_authority,
                provider_operations_authority=operations_authority,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("dossier_id does not match canonical provider approval authority body", result.errors)
            self.assertNotIn("provider approval authority signature verification failed", result.errors)
            self.assertIn("provider approval authority controls do not match dossier body", result.errors)

    def test_provider_approval_authority_requires_complete_source_binding_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            request, callback = self._approval_sources(tmp)
            webhook = self._webhook_receipt()
            delivery_authority, operations_authority = self._authority_sources()
            dossier = self._dossier(request, callback, webhook, delivery_authority, operations_authority)
            tampered = copy.deepcopy(dossier)
            tampered["source_binding"]["approval_callback"].pop("callback_hash")
            body = without_keys(tampered, "dossier_id", "signatures")
            dossier_id = content_hash(body)
            tampered["dossier_id"] = dossier_id
            tampered["signatures"] = [sign_value({"dossier_id": dossier_id, "provider_approval_authority": body})]

            result = verify_provider_approval_authority_dossier(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("approval_callback.callback_hash is required" in error for error in result.errors), result.errors)

    def test_provider_approval_authority_requires_freshness_when_strict(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            request, callback = self._approval_sources(tmp)
            webhook = self._webhook_receipt()
            delivery_authority, operations_authority = self._authority_sources()
            evidence = [dict(self._authority_evidence()[0])]
            evidence[0].pop("issued_at")
            evidence[0].pop("expires_at")
            dossier = self._dossier(request, callback, webhook, delivery_authority, operations_authority, authority_evidence=evidence)

            result = verify_provider_approval_authority_dossier(
                dossier,
                approval_request=request,
                approval_callback=callback,
                webhook_receipts=[webhook],
                provider_delivery_authority=delivery_authority,
                provider_operations_authority=operations_authority,
                require_fresh=True,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("freshness metadata missing" in error for error in result.errors), result.errors)

    def test_provider_approval_authority_rejects_incomplete_production_claim(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            request, callback = self._approval_sources(tmp)
            webhook = self._webhook_receipt()
            delivery_authority, operations_authority = self._authority_sources()
            dossier = self._dossier(request, callback, webhook, delivery_authority, operations_authority, mode="production-dossier")

            result = verify_provider_approval_authority_dossier(
                dossier,
                approval_request=request,
                approval_callback=callback,
                webhook_receipts=[webhook],
                provider_delivery_authority=delivery_authority,
                provider_operations_authority=operations_authority,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("production-dossier mode requires" in error for error in result.errors), result.errors)

    def test_cli_provider_approval_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            request, callback = self._approval_sources(tmp)
            webhook = self._webhook_receipt()
            delivery_authority, operations_authority = self._authority_sources()
            request_path = tmp / "approval-request.json"
            callback_path = tmp / "approval-callback.json"
            webhook_path = tmp / "provider-webhook.json"
            delivery_path = tmp / "provider-delivery-authority.json"
            operations_path = tmp / "provider-operations-authority.json"
            dossier_path = tmp / "provider-approval-authority.json"
            entry_path = tmp / "provider-approval-authority-entry.json"
            state_path = tmp / "provider-approval-authority-chain.json"
            _write_json(request_path, request)
            _write_json(callback_path, callback)
            write_provider_webhook_receipt(webhook_path, webhook)
            _write_json(delivery_path, delivery_authority)
            _write_json(operations_path, operations_authority)

            evidence_arg = (
                "hosted-approval-callback-ingress,hosted-service,service:provider-approval/github-prod,"
                "sha256:provider-approval-hosted-ingress-authority,Hosted approval callback ingress and worker fleet export;"
                "issuer=TrustAI Cloud;subject=aitrade-prod provider approval callback fleet;"
                "source_uri=https://ops.example/trustai/provider-approval/github-prod;"
                "issued_at=2026-07-08T06:02:00Z;expires_at=2026-07-15T06:02:00Z"
            )
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(request_path),
                str(callback_path),
                "--webhook",
                str(webhook_path),
                "--delivery-authority",
                str(delivery_path),
                "--operations-authority",
                str(operations_path),
            ]
            authority_args = [
                "--environment",
                "aitrade-prod",
                "--dossier-ref",
                "dossier:provider-approval-authority/github-prod",
                "--authority-ref",
                "authority:provider-approval/github-prod",
                "--producer-ref",
                "oidc:trustai.example/provider-approval-authority-worker",
                "--authority-evidence",
                evidence_arg,
                "--generated-at",
                "2026-07-08T06:05:00Z",
            ]

            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-approval-authority", *source_args, *authority_args, "--out", str(dossier_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "provider-approval-authority-verify", str(dossier_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "provider-approval-authority-append",
                    str(dossier_path),
                    *source_args,
                    "--state",
                    str(state_path),
                    "--tenant",
                    "provider-approval-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(dossier_path.exists())
            self.assertTrue(entry_path.exists())
            dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            self.assertEqual(dossier["dossier_id"], entry["payload"]["dossier_id"])
            self.assertEqual(1, entry["payload"]["summary"]["covered_requirement_count"])


if __name__ == "__main__":
    unittest.main()
