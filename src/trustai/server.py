from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .approval_callback import append_approval_callback, build_approval_callback_from_slack_interaction, validate_slack_request_signature, verify_approval_callback
from .approval_request_store import resolve_pending_approval_request, store_pending_approval_request
from .canonical import content_hash
from .chain import EvidenceChain
from .consent import INSURER_SCOPE, consent_status
from .contracts import load_contract
from .control_plane import ControlPlane
from .ingest import append_events, append_otlp_traces
from .insurer import build_insurer_telemetry
from .provider_lifecycle import load_provider_lifecycle_manifest
from .provider_lifecycle_operation import (
    append_provider_lifecycle_operation_receipt,
    build_provider_lifecycle_operation_receipt,
    verify_provider_lifecycle_operation_receipt,
)
from .provider_webhook import append_provider_webhook_receipt, build_provider_webhook_receipt
from .provider_webhook_store import find_provider_webhook_record, store_provider_webhook_record
from .verifier import load_proof_pack, verify_proof_pack


class TrustAIHandler(BaseHTTPRequestHandler):
    state_path = ".trustai/server/evidence-chain.json"
    control_db_path = ".trustai/server/control-plane.sqlite"
    approval_request_store_path = ".trustai/server/approval-requests.json"
    provider_webhook_store_path = ".trustai/server/provider-webhooks.json"
    tenant_id = "server"
    signing_key: str | None = None
    insurer_api_token: str | None = None
    slack_signing_secret: str | None = None
    slack_replay_window_seconds: int = 300
    github_webhook_secret: str | None = None
    gitlab_webhook_secret: str | None = None
    provider_lifecycle_operation_token: str | None = None

    def _json_response(self, status: int, value: Any) -> None:
        data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0:
            return b""
        return self.rfile.read(size)

    def _read_json(self) -> Any:
        raw_body = self._read_body()
        if not raw_body:
            return {}
        return json.loads(raw_body.decode("utf-8"))

    def _read_slack_callback_body(self) -> dict[str, Any]:
        raw_body = self._read_body()
        should_verify = bool(
            self.slack_signing_secret
            or self.headers.get("X-Slack-Signature")
            or self.headers.get("X-Slack-Request-Timestamp")
        )
        if should_verify:
            validate_slack_request_signature(
                self.slack_signing_secret,
                raw_body,
                self.headers.get("X-Slack-Request-Timestamp"),
                self.headers.get("X-Slack-Signature"),
                tolerance_seconds=self.slack_replay_window_seconds,
            )
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type == "application/x-www-form-urlencoded":
            form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
            payload_values = form.get("payload")
            if not payload_values:
                raise ValueError("payload form field is required")
            body: dict[str, Any] = {"payload": json.loads(payload_values[0])}
            for source, target in (("approval_request", "approval_request"), ("request", "request"), ("contract", "contract")):
                values = form.get(source)
                if values:
                    body[target] = json.loads(values[0])
            for field in ("contract_path", "approved_at", "reason"):
                values = form.get(field)
                if values:
                    body[field] = values[0]
            return body
        if not raw_body:
            return {}
        value = json.loads(raw_body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _drain_request_body(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        if size > 0:
            self.rfile.read(size)

    def _control(self) -> ControlPlane:
        return ControlPlane(self.control_db_path)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _authorized_for_insurer(self) -> bool:
        if not self.insurer_api_token:
            return True
        expected = f"Bearer {self.insurer_api_token}"
        return self.headers.get("Authorization") == expected

    def _authorized_for_provider_lifecycle_operation(self) -> bool:
        if not self.provider_lifecycle_operation_token:
            return True
        expected = f"Bearer {self.provider_lifecycle_operation_token}"
        return self.headers.get("Authorization") == expected

    def _body_hash_ref(self, body: dict[str, Any], hash_field: str, body_field: str) -> str | None:
        value = body.get(hash_field)
        if value:
            return str(value)
        if body_field in body:
            return "sha256:" + content_hash(body[body_field])
        return None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json_response(200, {"ok": True, "service": "trustai"})
            return
        if parsed.path == "/v0/control/summary":
            control = self._control()
            try:
                self._json_response(200, control.summary())
            finally:
                control.close()
            return
        if parsed.path == "/v0/control/contract-evidence":
            query = parse_qs(parsed.query)
            contract_id = query.get("contract_id", [None])[0]
            contract_hash = query.get("contract_hash", [None])[0]
            if not contract_id and not contract_hash:
                self._json_response(422, {"error": "contract_id or contract_hash is required"})
                return
            try:
                limit = int(query.get("limit", ["20"])[0])
            except ValueError:
                self._json_response(422, {"error": "limit must be an integer"})
                return
            control = self._control()
            try:
                self._json_response(
                    200,
                    control.contract_evidence(
                        contract_id=contract_id,
                        contract_hash=contract_hash,
                        limit=limit,
                    ),
                )
            finally:
                control.close()
            return
        if parsed.path == "/v0/control/agent-evidence":
            query = parse_qs(parsed.query)
            agent_name = query.get("agent_name", [None])[0]
            agent_version = query.get("agent_version", [None])[0]
            if not agent_name:
                self._json_response(422, {"error": "agent_name is required"})
                return
            try:
                limit = int(query.get("limit", ["20"])[0])
            except ValueError:
                self._json_response(422, {"error": "limit must be an integer"})
                return
            control = self._control()
            try:
                self._json_response(
                    200,
                    control.agent_evidence(
                        agent_name=agent_name,
                        agent_version=agent_version,
                        limit=limit,
                    ),
                )
            finally:
                control.close()
            return
        if parsed.path == "/v0/contracts":
            control = self._control()
            try:
                self._json_response(200, {"contracts": control.contracts()})
            finally:
                control.close()
            return
        if parsed.path == "/v0/agents":
            control = self._control()
            try:
                self._json_response(200, {"agents": control.agents()})
            finally:
                control.close()
            return
        if parsed.path == "/v0/eval-runs":
            control = self._control()
            try:
                self._json_response(200, {"eval_runs": control.recent_eval_runs()})
            finally:
                control.close()
            return
        if parsed.path == "/v0/gate-decisions":
            control = self._control()
            try:
                self._json_response(200, {"gate_decisions": control.recent_gate_decisions()})
            finally:
                control.close()
            return
        if parsed.path == "/v0/proof-packs":
            control = self._control()
            try:
                self._json_response(200, {"proof_packs": control.recent_proof_packs()})
            finally:
                control.close()
            return
        if parsed.path == "/v0/ingest-events":
            control = self._control()
            try:
                self._json_response(200, {"ingest_events": control.recent_ingest_events()})
            finally:
                control.close()
            return
        if parsed.path == "/v0/promotion-statuses":
            control = self._control()
            try:
                self._json_response(200, {"promotion_statuses": control.recent_promotion_statuses()})
            finally:
                control.close()
            return
        if parsed.path == "/v0/runtime-evidence":
            control = self._control()
            try:
                self._json_response(200, control.runtime_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/holdout-evidence", "/v0/control/holdout-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.holdout_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/mcp-evidence", "/v0/control/mcp-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.mcp_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/onboarding-evidence", "/v0/control/onboarding-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.onboarding_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/promotion-lifecycle-evidence", "/v0/control/promotion-lifecycle-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.promotion_lifecycle_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/framework-adapter-evidence", "/v0/control/framework-adapter-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.framework_adapter_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/review-portal-evidence", "/v0/control/review-portal-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.review_portal_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/standards-auditor-evidence", "/v0/control/standards-auditor-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.standards_auditor_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/trust-network-evidence", "/v0/control/trust-network-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.trust_network_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/provider-delivery-evidence", "/v0/control/provider-delivery-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.provider_delivery_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/provider-operations-evidence", "/v0/control/provider-operations-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.provider_operations_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/compliance-evidence", "/v0/control/compliance-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.compliance_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/policy-backend-evidence", "/v0/control/policy-backend-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.policy_backend_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/insurer-evidence", "/v0/control/insurer-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.insurer_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/multi-agent-evidence", "/v0/control/multi-agent-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.multi_agent_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/byoc-evidence", "/v0/control/byoc-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.byoc_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/identity-provider-evidence", "/v0/control/identity-provider-evidence"):
            control = self._control()
            try:
                self._json_response(200, control.identity_provider_evidence())
            finally:
                control.close()
            return
        if parsed.path == "/v0/roadmap-evidence":
            control = self._control()
            try:
                self._json_response(200, control.roadmap_evidence())
            finally:
                control.close()
            return
        if parsed.path in ("/v0/phase-scoreboards", "/v0/control/phase-scoreboards"):
            control = self._control()
            try:
                self._json_response(200, {"phase_scoreboards": control.recent_phase_scoreboards()})
            finally:
                control.close()
            return
        if parsed.path in ("/v0/design-partner-dossiers", "/v0/control/design-partner-dossiers"):
            control = self._control()
            try:
                self._json_response(200, {"design_partner_dossiers": control.recent_design_partner_dossiers()})
            finally:
                control.close()
            return
        if parsed.path in ("/v0/own-compliance-dossiers", "/v0/control/own-compliance-dossiers"):
            control = self._control()
            try:
                self._json_response(200, {"own_compliance_dossiers": control.recent_own_compliance_dossiers()})
            finally:
                control.close()
            return
        if parsed.path in ("/v0/product-scope-decisions", "/v0/control/product-scope-decisions"):
            control = self._control()
            try:
                self._json_response(200, {"product_scope_decisions": control.recent_product_scope_decisions()})
            finally:
                control.close()
            return
        if parsed.path in ("/v0/vertical-packs", "/v0/control/vertical-packs"):
            control = self._control()
            try:
                self._json_response(200, {"vertical_packs": control.recent_vertical_packs()})
            finally:
                control.close()
            return
        if parsed.path in ("/v0/reliability-reports", "/v0/control/reliability-reports"):
            control = self._control()
            try:
                self._json_response(200, {"reliability_reports": control.recent_reliability_reports()})
            finally:
                control.close()
            return
        if parsed.path in ("/v0/readiness", "/v0/control/readiness"):
            control = self._control()
            try:
                self._json_response(200, control.readiness())
            finally:
                control.close()
            return
        if parsed.path == "/v0/external-evidence":
            control = self._control()
            try:
                self._json_response(200, {"external_evidence_manifests": control.recent_external_evidence_manifests()})
            finally:
                control.close()
            return
        if parsed.path in ("/v0/external-authority-gaps", "/v0/control/external-authority-gaps"):
            query = parse_qs(parsed.query)
            raw_limit = (query.get("limit") or [None])[0]
            try:
                limit = int(raw_limit) if raw_limit is not None else None
            except ValueError:
                self._json_response(422, {"error": "limit must be a positive integer"})
                return
            control = self._control()
            try:
                self._json_response(
                    200,
                    control.external_authority_gaps(
                        authority_kind=(query.get("authority_kind") or [None])[0],
                        requirement_id=(query.get("requirement_id") or [None])[0],
                        limit=limit,
                    ),
                )
            except ValueError as exc:
                self._json_response(422, {"error": str(exc)})
            finally:
                control.close()
            return
        if parsed.path == "/v0/authority-dossiers":
            control = self._control()
            try:
                self._json_response(200, {"authority_dossiers": control.recent_authority_dossiers()})
            finally:
                control.close()
            return
        self._json_response(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/v0/ingest":
            body = self._read_json()
            events = body.get("events", body if isinstance(body, list) else [])
            chain = EvidenceChain.load(self.state_path, tenant_id=self.tenant_id)
            entries = append_events(chain, events, key=self.signing_key)
            chain.save()
            self._json_response(200, {"entries": [entry["entry_id"] for entry in entries], "tree": chain.tree()})
            return

        if parsed.path == "/v1/traces":
            body = self._read_json()
            chain = EvidenceChain.load(self.state_path, tenant_id=self.tenant_id)
            entries = append_otlp_traces(chain, body, key=self.signing_key)
            chain.save()
            self._json_response(200, {"partialSuccess": {}, "entries": [entry["entry_id"] for entry in entries], "tree": chain.tree()})
            return

        if parsed.path == "/v0/control/index":
            body = self._read_json()
            chain = EvidenceChain.load(body.get("state_path", self.state_path), tenant_id=self.tenant_id)
            control = self._control()
            try:
                counts = control.rebuild_from_chain(chain) if body.get("rebuild") else control.index_chain(chain)
                if body.get("proof_pack_path"):
                    pack = load_proof_pack(body["proof_pack_path"])
                    result = verify_proof_pack(pack, key=self.signing_key)
                    if not result.ok:
                        self._json_response(422, {"ok": False, "errors": result.errors})
                        return
                    control.index_proof_pack(pack, body["proof_pack_path"])
                self._json_response(200, {"ok": True, "indexed": counts, "summary": control.summary()})
            finally:
                control.close()
            return

        if parsed.path == "/v0/verify":
            body = self._read_json()
            proof_pack = body.get("proof_pack")
            if proof_pack is None and body.get("path"):
                proof_pack = load_proof_pack(body["path"])
            result = verify_proof_pack(proof_pack, key=self.signing_key)
            self._json_response(
                200 if result.ok else 422,
                {"ok": result.ok, "errors": result.errors, "warnings": result.warnings, "decision": result.decision},
            )
            return

        if parsed.path == "/v0/approval-requests/slack":
            try:
                body = self._read_json()
                request_payload = body.get("approval_request") or body.get("request")
                contract = body.get("contract")
                contract_path = body.get("contract_path")
                if not isinstance(request_payload, dict):
                    self._json_response(422, {"ok": False, "error": "approval_request is required"})
                    return
                if contract is None and contract_path:
                    load_contract(contract_path)
                if contract is not None and not isinstance(contract, dict):
                    self._json_response(422, {"ok": False, "error": "contract must be an object"})
                    return
                record = store_pending_approval_request(
                    self.approval_request_store_path,
                    request_payload,
                    contract=contract,
                    contract_path=contract_path,
                    stored_at=body.get("stored_at"),
                )
            except (OSError, ValueError) as exc:
                self._json_response(422, {"ok": False, "error": str(exc)})
                return
            self._json_response(
                200,
                {
                    "ok": True,
                    "record_id": record["record_id"],
                    "approval_request_id": record["approval_request_id"],
                    "payload_hash": record["payload_hash"],
                    "action_bindings": record["action_bindings"],
                    "expires_at": record.get("expires_at"),
                },
            )
            return

        if parsed.path == "/v0/approval-callbacks/slack":
            try:
                body = self._read_slack_callback_body()
            except ValueError as exc:
                self._json_response(422, {"ok": False, "error": str(exc)})
                return
            request_payload = body.get("approval_request") or body.get("request")
            interaction = body.get("interaction") or body.get("payload")
            contract = body.get("contract")
            request_source = "inline"
            if contract is None and body.get("contract_path"):
                contract = load_contract(body["contract_path"])
            if not isinstance(interaction, dict):
                self._json_response(422, {"ok": False, "error": "interaction is required"})
                return
            if not isinstance(request_payload, dict) or not isinstance(contract, dict):
                try:
                    resolved = resolve_pending_approval_request(
                        self.approval_request_store_path,
                        interaction,
                        now=body.get("approved_at"),
                    )
                    request_payload = resolved["approval_request"]
                    contract = resolved["contract"]
                    request_source = "pending-store"
                except (OSError, ValueError) as exc:
                    self._json_response(422, {"ok": False, "error": "approval_request and contract are required unless a matching pending request is registered: " + str(exc)})
                    return
            try:
                callback = build_approval_callback_from_slack_interaction(
                    request_payload,
                    interaction,
                    approved_at=body.get("approved_at"),
                    reason=body.get("reason"),
                    key=self.signing_key,
                )
                verification = verify_approval_callback(request_payload, callback, key=self.signing_key)
                if not verification.ok:
                    self._json_response(422, {"ok": False, "errors": verification.errors})
                    return
                chain = EvidenceChain.load(self.state_path, tenant_id=self.tenant_id)
                entry = append_approval_callback(chain, contract, request_payload, callback, key=self.signing_key)
                chain.save()
            except (OSError, ValueError) as exc:
                self._json_response(422, {"ok": False, "error": str(exc)})
                return
            self._json_response(
                200,
                {
                    "ok": True,
                    "callback_id": callback["callback_id"],
                    "approval_entry_id": entry["entry_id"],
                    "role": callback["role"],
                    "approver": callback["approver"],
                    "approval_request_source": request_source,
                    "tree": chain.tree(),
                },
            )
            return

        if parsed.path in {"/v0/provider-webhooks/github", "/v0/provider-webhooks/gitlab"}:
            provider = parsed.path.rsplit("/", 1)[-1]
            secret = self.github_webhook_secret if provider == "github" else self.gitlab_webhook_secret
            raw_body = self._read_body()
            if not secret:
                self._json_response(422, {"ok": False, "error": f"{provider} webhook secret is not configured"})
                return
            headers = dict(self.headers.items())
            try:
                existing_record = find_provider_webhook_record(
                    self.provider_webhook_store_path,
                    provider,
                    raw_body,
                    headers,
                    secret,
                )
                chain = EvidenceChain.load(self.state_path, tenant_id=self.tenant_id)
                if existing_record is not None:
                    self._json_response(
                        200,
                        {
                            "ok": True,
                            "duplicate": True,
                            "dedup_key": existing_record["dedup_key"],
                            "receipt_id": existing_record["receipt_id"],
                            "webhook_entry_id": existing_record["entry_id"],
                            "provider": existing_record["provider"],
                            "event": existing_record.get("event"),
                            "delivery_id": existing_record.get("delivery_id"),
                            "first_seen_at": existing_record.get("first_seen_at"),
                            "tree": chain.tree(),
                        },
                    )
                    return
                receipt = build_provider_webhook_receipt(
                    provider,
                    raw_body,
                    headers,
                    secret,
                    key=self.signing_key,
                )
                entry = append_provider_webhook_receipt(
                    chain,
                    receipt,
                    raw_body,
                    headers=headers,
                    secret=secret,
                    key=self.signing_key,
                )
                chain.save()
                record = store_provider_webhook_record(
                    self.provider_webhook_store_path,
                    receipt,
                    entry,
                    raw_body,
                    headers,
                    secret,
                    stored_at=receipt.get("received_at"),
                )
            except (OSError, ValueError) as exc:
                self._json_response(422, {"ok": False, "error": str(exc)})
                return
            self._json_response(
                200,
                {
                    "ok": True,
                    "duplicate": False,
                    "dedup_key": record["dedup_key"],
                    "receipt_id": receipt["receipt_id"],
                    "webhook_entry_id": entry["entry_id"],
                    "provider": receipt["provider"],
                    "event": receipt["webhook"].get("event"),
                    "delivery_id": receipt["webhook"].get("delivery_id"),
                    "tree": chain.tree(),
                },
            )
            return
        if parsed.path == "/v0/provider-lifecycle-operations":
            if not self._authorized_for_provider_lifecycle_operation():
                self._drain_request_body()
                self._json_response(401, {"ok": False, "error": "missing or invalid provider lifecycle operation token"})
                return
            try:
                body = self._read_json()
                if not isinstance(body, dict):
                    self._json_response(422, {"ok": False, "error": "request body must be a JSON object"})
                    return
                lifecycle = body.get("lifecycle") or body.get("lifecycle_manifest")
                if lifecycle is None and body.get("lifecycle_path"):
                    lifecycle = load_provider_lifecycle_manifest(body["lifecycle_path"])
                if not isinstance(lifecycle, dict):
                    self._json_response(422, {"ok": False, "error": "lifecycle or lifecycle_path is required"})
                    return
                operation = body.get("operation") if isinstance(body.get("operation"), dict) else body
                request_hash = self._body_hash_ref(body, "request_hash", "request_body")
                response_hash = self._body_hash_ref(body, "response_hash", "response_body")
                receipt = build_provider_lifecycle_operation_receipt(
                    lifecycle_manifest=lifecycle,
                    operation_kind=body.get("operation_kind") or operation.get("kind"),
                    operation_ref=body.get("operation_ref") or operation.get("operation_ref"),
                    endpoint_url=body.get("endpoint_url") or operation.get("endpoint_url"),
                    credential_ref=body.get("credential_ref") or operation.get("credential_ref"),
                    request_hash=request_hash,
                    response_status=int(body.get("response_status", operation.get("response_status"))),
                    response_hash=response_hash,
                    actor_ref=body.get("actor_ref") or operation.get("actor_ref"),
                    provider_event_ref=body.get("provider_event_ref") or operation.get("provider_event_ref"),
                    token_ref=body.get("token_ref") or operation.get("token_ref"),
                    audit_log_ref=body.get("audit_log_ref") or operation.get("audit_log_ref"),
                    idempotency_key=body.get("idempotency_key") or operation.get("idempotency_key"),
                    mode=body.get("mode") or operation.get("mode") or "recorded-provider-response",
                    environment=body.get("environment") or operation.get("environment") or "local",
                    recorded_at=body.get("recorded_at") or operation.get("recorded_at"),
                    key=self.signing_key,
                )
                verification = verify_provider_lifecycle_operation_receipt(receipt, lifecycle_manifest=lifecycle, key=self.signing_key)
                if not verification.ok:
                    self._json_response(422, {"ok": False, "errors": verification.errors})
                    return
                chain = EvidenceChain.load(self.state_path, tenant_id=self.tenant_id)
                entry = append_provider_lifecycle_operation_receipt(chain, receipt, lifecycle_manifest=lifecycle, key=self.signing_key)
                chain.save()
            except (OSError, ValueError, TypeError) as exc:
                self._json_response(422, {"ok": False, "error": str(exc)})
                return
            self._json_response(
                200,
                {
                    "ok": True,
                    "operation_receipt_id": receipt["operation_receipt_id"],
                    "operation_entry_id": entry["entry_id"],
                    "provider": receipt.get("provider"),
                    "operation": receipt.get("operation"),
                    "warnings": verification.warnings,
                    "receipt": receipt,
                    "tree": chain.tree(),
                },
            )
            return

        if parsed.path == "/v0/insurer-risk":
            if not self._authorized_for_insurer():
                self._drain_request_body()
                self._json_response(401, {"ok": False, "error": "missing or invalid insurer API token"})
                return
            body = self._read_json()
            proof_pack = body.get("proof_pack")
            if proof_pack is None and body.get("path"):
                proof_pack = load_proof_pack(body["path"])
            result = verify_proof_pack(proof_pack, key=self.signing_key)
            if not result.ok:
                self._json_response(422, {"ok": False, "errors": result.errors})
                return
            consent_id = body.get("consent_id")
            if not consent_id:
                self._json_response(422, {"ok": False, "error": "consent_id is required"})
                return
            chain = EvidenceChain.load(self.state_path, tenant_id=self.tenant_id)
            decision = proof_pack.get("gate_decision", {})
            status = consent_status(
                chain,
                consent_id,
                INSURER_SCOPE,
                pack_id=proof_pack.get("pack_id"),
                contract_id=decision.get("contract_id"),
                now=body.get("now"),
            )
            if not status["active"]:
                self._json_response(403, {"ok": False, "error": "consent is not active", "consent": status})
                return
            self._json_response(200, build_insurer_telemetry(proof_pack, consent_id, consent=status))
            return

        self._json_response(404, {"error": "not found"})


def serve(
    host: str,
    port: int,
    state_path: str,
    tenant_id: str,
    key: str | None = None,
    control_db_path: str = ".trustai/server/control-plane.sqlite",
    approval_request_store_path: str = ".trustai/server/approval-requests.json",
    provider_webhook_store_path: str = ".trustai/server/provider-webhooks.json",
    insurer_token: str | None = None,
    slack_signing_secret: str | None = None,
    slack_replay_window_seconds: int = 300,
    github_webhook_secret: str | None = None,
    gitlab_webhook_secret: str | None = None,
    provider_lifecycle_operation_token: str | None = None,
) -> ThreadingHTTPServer:
    class ConfiguredHandler(TrustAIHandler):
        pass

    ConfiguredHandler.state_path = state_path
    ConfiguredHandler.control_db_path = control_db_path
    ConfiguredHandler.approval_request_store_path = approval_request_store_path
    ConfiguredHandler.provider_webhook_store_path = provider_webhook_store_path
    ConfiguredHandler.tenant_id = tenant_id
    ConfiguredHandler.signing_key = key
    ConfiguredHandler.insurer_api_token = insurer_token
    ConfiguredHandler.slack_signing_secret = slack_signing_secret
    ConfiguredHandler.slack_replay_window_seconds = slack_replay_window_seconds
    ConfiguredHandler.github_webhook_secret = github_webhook_secret
    ConfiguredHandler.gitlab_webhook_secret = gitlab_webhook_secret
    ConfiguredHandler.provider_lifecycle_operation_token = provider_lifecycle_operation_token
    Path(state_path).parent.mkdir(parents=True, exist_ok=True)
    Path(control_db_path).parent.mkdir(parents=True, exist_ok=True)
    Path(approval_request_store_path).parent.mkdir(parents=True, exist_ok=True)
    Path(provider_webhook_store_path).parent.mkdir(parents=True, exist_ok=True)
    return ThreadingHTTPServer((host, port), ConfiguredHandler)
