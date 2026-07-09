from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .approval_callback import approval_request_action_bindings, validate_approval_request
from .canonical import content_hash, parse_rfc3339, utc_now
from .contracts import load_contract

APPROVAL_REQUEST_STORE_SCHEMA = "trustai.approval-request-store/0.1"


def load_approval_request_store(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {"schema": APPROVAL_REQUEST_STORE_SCHEMA, "requests": []}
    value = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("approval request store must contain an object")
    if value.get("schema") != APPROVAL_REQUEST_STORE_SCHEMA:
        raise ValueError(f"approval request store schema must be {APPROVAL_REQUEST_STORE_SCHEMA}")
    if not isinstance(value.get("requests"), list):
        raise ValueError("approval request store requests must be a list")
    return value


def write_approval_request_store(path: str | Path, store: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(store, indent=2, sort_keys=True), encoding="utf-8")


def store_pending_approval_request(
    path: str | Path,
    request: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    contract_path: str | None = None,
    stored_at: str | None = None,
) -> dict[str, Any]:
    validate_approval_request(request)
    if contract is None and not contract_path:
        raise ValueError("contract or contract_path is required")
    record = _record_for_request(request, contract=contract, contract_path=contract_path, stored_at=stored_at)
    store = load_approval_request_store(path)
    existing = [item for item in store.get("requests", []) if isinstance(item, dict) and item.get("approval_request_id") != record["approval_request_id"]]
    existing.append(record)
    store["requests"] = existing
    write_approval_request_store(path, store)
    return record


def resolve_pending_approval_request(
    path: str | Path,
    interaction: dict[str, Any],
    *,
    now: str | None = None,
) -> dict[str, Any]:
    if not isinstance(interaction, dict):
        raise ValueError("Slack interaction must be an object")
    store = load_approval_request_store(path)
    request_id = _interaction_request_id(interaction)
    action_values = _interaction_action_values(interaction)
    for record in store.get("requests", []):
        if not isinstance(record, dict):
            continue
        if request_id and record.get("approval_request_id") == request_id:
            return _resolved_record(record, now=now)
        bindings = record.get("action_bindings", [])
        if action_values and any(isinstance(binding, dict) and binding.get("action_value") in action_values for binding in bindings):
            return _resolved_record(record, now=now)
    raise ValueError("no pending approval request matches Slack interaction")


def _record_for_request(
    request: dict[str, Any],
    *,
    contract: dict[str, Any] | None,
    contract_path: str | None,
    stored_at: str | None,
) -> dict[str, Any]:
    action_bindings = approval_request_action_bindings(request)
    record: dict[str, Any] = {
        "schema": "trustai.pending-approval-request/0.1",
        "approval_request_id": request["approval_request_id"],
        "provider": request.get("provider", "slack"),
        "payload_hash": request["payload_hash"],
        "pack_id": request.get("pack_id"),
        "contract_id": request.get("contract_id"),
        "contract_hash": request.get("contract_hash"),
        "channel": request.get("channel"),
        "requested_roles": request.get("requested_roles", []),
        "action_bindings": action_bindings,
        "stored_at": stored_at or utc_now(),
        "approval_request": request,
    }
    if request.get("expires_at"):
        record["expires_at"] = request["expires_at"]
    if contract_path:
        record["contract_path"] = str(contract_path)
    if contract is not None:
        record["contract"] = contract
    record["record_id"] = content_hash({key: value for key, value in record.items() if key != "record_id"})
    return record


def _resolved_record(record: dict[str, Any], *, now: str | None) -> dict[str, Any]:
    request = record.get("approval_request")
    if not isinstance(request, dict):
        raise ValueError("pending approval request record is missing approval_request")
    validate_approval_request(request)
    expires_at = record.get("expires_at") or request.get("expires_at")
    if expires_at and now:
        if parse_rfc3339(now) > parse_rfc3339(str(expires_at)):
            raise ValueError("pending approval request is expired")
    contract = record.get("contract")
    if contract is None and record.get("contract_path"):
        contract = load_contract(record["contract_path"])
    if not isinstance(contract, dict):
        raise ValueError("pending approval request record is missing contract")
    return {"approval_request": request, "contract": contract, "record": record}


def _interaction_request_id(interaction: dict[str, Any]) -> str | None:
    message = interaction.get("message") if isinstance(interaction.get("message"), dict) else {}
    metadata = message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
    payload = metadata.get("event_payload") if isinstance(metadata.get("event_payload"), dict) else {}
    value = payload.get("approval_request_id")
    return str(value) if value else None


def _interaction_action_values(interaction: dict[str, Any]) -> set[str]:
    actions = interaction.get("actions")
    if not isinstance(actions, list):
        return set()
    return {str(action.get("value")) for action in actions if isinstance(action, dict) and action.get("value")}