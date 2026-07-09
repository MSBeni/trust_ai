from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approvals import append_approval, normalize_approval
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .contracts import contract_hash
from .crypto import sign_value, verify_value

APPROVAL_CALLBACK_SCHEMA = "trustai.approval-callback/0.1"


@dataclass
class ApprovalCallbackVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_approval_request(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("approval request file must contain an object")
    return value


def load_approval_callback(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("approval callback file must contain an object")
    return value


def validate_approval_request(request: dict[str, Any]) -> None:
    _validate_request_shape(request)


def approval_request_action_bindings(request: dict[str, Any]) -> list[dict[str, str]]:
    _validate_request_shape(request)
    return [
        {
            "role": str(role),
            "action_id": _slack_action_id(str(role)),
            "action_value": _expected_action_value(request, str(role)),
        }
        for role in request.get("requested_roles", [])
    ]


def validate_slack_request_signature(
    signing_secret: str | None,
    body: bytes,
    timestamp: str | None,
    signature: str | None,
    *,
    now: int | None = None,
    tolerance_seconds: int = 300,
) -> None:
    if not signing_secret:
        raise ValueError("Slack signing secret is required for signature validation")
    if not timestamp:
        raise ValueError("X-Slack-Request-Timestamp header is required")
    if not signature:
        raise ValueError("X-Slack-Signature header is required")
    try:
        request_timestamp = int(timestamp)
    except ValueError as exc:
        raise ValueError("Slack request timestamp must be an integer") from exc
    current_timestamp = int(time.time()) if now is None else int(now)
    if tolerance_seconds >= 0 and abs(current_timestamp - request_timestamp) > tolerance_seconds:
        raise ValueError("Slack request timestamp is outside replay window")
    signing_base = b"v0:" + timestamp.encode("utf-8") + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), signing_base, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("Slack request signature verification failed")


def build_approval_callback(
    request: dict[str, Any],
    *,
    role: str,
    approver: str,
    approved_at: str,
    reason: str | None = None,
    external_user_id: str | None = None,
    team_id: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _validate_request_shape(request)
    if not role:
        raise ValueError("role is required")
    if not approver:
        raise ValueError("approver is required")
    parse_rfc3339(approved_at)

    body = {
        "schema": APPROVAL_CALLBACK_SCHEMA,
        "provider": request.get("provider", "slack"),
        "approval_request_id": request.get("approval_request_id"),
        "request_payload_hash": _request_hash(request),
        "pack_id": request.get("pack_id"),
        "contract_id": request.get("contract_id"),
        "contract_hash": request.get("contract_hash"),
        "channel": request.get("channel"),
        "role": role,
        "action_id": _slack_action_id(role),
        "action_value": _expected_action_value(request, role),
        "approver": approver,
        "approved_at": approved_at,
        "reason": reason,
        "external_user_id": external_user_id,
        "team_id": team_id,
    }
    callback_id = content_hash(body)
    return {
        **body,
        "callback_id": callback_id,
        "signatures": [sign_value({"callback_id": callback_id, "callback": body}, key)],
    }


def build_approval_callback_from_slack_interaction(
    request: dict[str, Any],
    interaction: dict[str, Any],
    *,
    approved_at: str | None = None,
    reason: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _validate_request_shape(request)
    action = _slack_action_from_interaction(request, interaction)
    role = _role_for_action(request, action)
    user = interaction.get("user", {}) if isinstance(interaction.get("user"), dict) else {}
    team = interaction.get("team", {}) if isinstance(interaction.get("team"), dict) else {}
    profile = user.get("profile", {}) if isinstance(user.get("profile"), dict) else {}
    approver = profile.get("email") or user.get("username") or user.get("name") or user.get("id")
    if not approver:
        raise ValueError("Slack interaction user identity is required")
    return build_approval_callback(
        request,
        role=role,
        approver=str(approver),
        approved_at=approved_at or utc_now(),
        reason=reason or "Approved via Slack interaction callback.",
        external_user_id=user.get("id"),
        team_id=team.get("id"),
        key=key,
    )


def verify_approval_callback(
    request: dict[str, Any],
    callback: dict[str, Any],
    *,
    key: str | None = None,
) -> ApprovalCallbackVerification:
    errors: list[str] = []
    warnings: list[str] = []

    request_errors = _request_errors(request)
    errors.extend(f"request invalid: {error}" for error in request_errors)

    if callback.get("schema") != APPROVAL_CALLBACK_SCHEMA:
        errors.append(f"callback schema must be {APPROVAL_CALLBACK_SCHEMA}")
    body = without_keys(callback, "callback_id", "signatures")
    callback_id = content_hash(body)
    if callback.get("callback_id") != callback_id:
        errors.append("callback_id does not match canonical callback body")
    signatures = callback.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("callback must include at least one signature")
    else:
        signed_value = {"callback_id": callback.get("callback_id"), "callback": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("callback signature verification failed")

    for field in ("approval_request_id", "request_payload_hash", "pack_id", "contract_id", "contract_hash", "role", "action_id", "action_value", "approver", "approved_at"):
        if not callback.get(field):
            errors.append(f"callback.{field} is required")
    if callback.get("provider") != request.get("provider", "slack"):
        errors.append("callback provider does not match request")
    if callback.get("approval_request_id") != request.get("approval_request_id"):
        errors.append("callback approval_request_id does not match request")
    if callback.get("request_payload_hash") != _request_hash(request):
        errors.append("callback request_payload_hash does not match request")
    for field in ("pack_id", "contract_id", "contract_hash", "channel"):
        if callback.get(field) != request.get(field):
            errors.append(f"callback {field} does not match request")

    role = callback.get("role")
    requested_roles = request.get("requested_roles", [])
    if role not in requested_roles:
        errors.append("callback role was not requested")
    if callback.get("action_id") != _slack_action_id(str(role or "")):
        errors.append("callback action_id does not match role")
    if callback.get("action_value") != _expected_action_value(request, str(role or "")):
        errors.append("callback action_value does not match request action value")

    try:
        approved_at = parse_rfc3339(callback.get("approved_at", ""))
    except ValueError as exc:
        errors.append(f"callback approved_at invalid: {exc}")
        approved_at = None
    expires_at = request.get("expires_at")
    if approved_at is not None and expires_at:
        try:
            if approved_at > parse_rfc3339(expires_at):
                errors.append("callback approved_at is after request expiry")
        except ValueError as exc:
            errors.append(f"request expires_at invalid: {exc}")

    return ApprovalCallbackVerification(ok=not errors, errors=errors, warnings=warnings)


def approval_from_callback(request: dict[str, Any], callback: dict[str, Any], *, key: str | None = None) -> dict[str, Any]:
    result = verify_approval_callback(request, callback, key=key)
    if not result.ok:
        raise ValueError("invalid approval callback: " + "; ".join(result.errors))
    template = _template_for_role(request, callback["role"])
    approval = {
        **template,
        "source": f"{request.get('provider', 'slack')}-callback",
        "role": callback["role"],
        "approver": callback["approver"],
        "approved_at": callback["approved_at"],
        "reason": callback.get("reason") or template.get("reason") or "Approved via verified TrustAI callback.",
        "metadata": {
            **(template.get("metadata", {}) if isinstance(template.get("metadata"), dict) else {}),
            "callback_id": callback["callback_id"],
            "request_payload_hash": callback["request_payload_hash"],
            "action_id": callback["action_id"],
            "action_value": callback["action_value"],
            "external_user_id": callback.get("external_user_id"),
            "team_id": callback.get("team_id"),
        },
    }
    return normalize_approval(approval)


def append_approval_callback(
    chain: EvidenceChain,
    contract: dict[str, Any],
    request: dict[str, Any],
    callback: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    digest = contract_hash(contract)
    if callback.get("contract_hash") != digest:
        raise ValueError("callback contract_hash does not match contract")
    approval = approval_from_callback(request, callback, key=key)
    return append_approval(chain, contract, approval, key=key)


def write_approval_callback(path: str | Path, callback: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(callback, indent=2, sort_keys=True), encoding="utf-8")


def _validate_request_shape(request: dict[str, Any]) -> None:
    errors = _request_errors(request)
    if errors:
        raise ValueError("invalid approval request: " + "; ".join(errors))


def _request_errors(request: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if request.get("schema") != "trustai.slack-approval-request/0.1":
        errors.append("schema must be trustai.slack-approval-request/0.1")
    if request.get("payload_hash") != _request_hash(request):
        errors.append("payload_hash does not match request body")
    for field in ("approval_request_id", "pack_id", "contract_id", "contract_hash", "channel", "requested_roles"):
        if not request.get(field):
            errors.append(f"{field} is required")
    if not isinstance(request.get("requested_roles"), list):
        errors.append("requested_roles must be a list")
    return errors


def _request_hash(request: dict[str, Any]) -> str:
    return content_hash(without_keys(request, "payload_hash"))


def _expected_action_value(request: dict[str, Any], role: str) -> str:
    return content_hash({"approval_request_id": request.get("approval_request_id"), "role": role})[:75]


def _slack_action_id(role: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in role.lower()).strip("_")
    return f"trustai_approve_{safe or 'role'}"


def _slack_action_from_interaction(request: dict[str, Any], interaction: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(interaction, dict):
        raise ValueError("Slack interaction must be an object")
    actions = interaction.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ValueError("Slack interaction actions are required")
    requested_roles = request.get("requested_roles", [])
    for action in actions:
        if not isinstance(action, dict):
            continue
        for role in requested_roles:
            if action.get("action_id") == _slack_action_id(str(role)) and action.get("value") == _expected_action_value(request, str(role)):
                return action
    raise ValueError("Slack interaction does not contain a matching TrustAI approval action")


def _role_for_action(request: dict[str, Any], action: dict[str, Any]) -> str:
    requested_roles = request.get("requested_roles", [])
    for role in requested_roles:
        role_value = str(role)
        if action.get("action_id") == _slack_action_id(role_value) and action.get("value") == _expected_action_value(request, role_value):
            return role_value
    raise ValueError("Slack interaction action does not match a requested role")


def _template_for_role(request: dict[str, Any], role: str) -> dict[str, Any]:
    templates = request.get("approval_templates", [])
    if isinstance(templates, list):
        for template in templates:
            if isinstance(template, dict) and template.get("role") == role:
                return dict(template)
    return {
        "schema": "trustai.human-approval/0.1",
        "source": request.get("provider", "slack"),
        "role": role,
        "external_ref": f"{request.get('provider', 'slack')}://{request.get('channel')}/{request.get('approval_request_id')}/{role}",
    }
