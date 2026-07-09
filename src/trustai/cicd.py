from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .approvals import APPROVAL_SCHEMA
from .canonical import content_hash
from .verifier import VerificationResult


def _decision(proof_pack: dict[str, Any]) -> dict[str, Any]:
    decision = proof_pack.get("gate_decision", {})
    return decision if isinstance(decision, dict) else {}


def _success(proof_pack: dict[str, Any], verification: VerificationResult) -> bool:
    return verification.ok and _decision(proof_pack).get("outcome") == "passed"


def _summary(proof_pack: dict[str, Any], verification: VerificationResult) -> dict[str, Any]:
    decision = _decision(proof_pack)
    return {
        "pack_id": proof_pack.get("pack_id"),
        "agent": decision.get("agent", {}),
        "contract_id": decision.get("contract_id"),
        "contract_hash": decision.get("contract_hash"),
        "verified": verification.ok,
        "gate_outcome": decision.get("outcome"),
        "errors": verification.errors,
        "warnings": verification.warnings,
    }


def _check_annotations(decision: dict[str, Any]) -> list[dict[str, Any]]:
    annotations = []
    for check in decision.get("checks", []):
        annotations.append(
            {
                "path": "trustai-proof-pack",
                "start_line": 1,
                "end_line": 1,
                "annotation_level": "notice" if check.get("passed") else "failure",
                "message": (
                    f"{check.get('name')}: actual={check.get('actual')} "
                    f"{check.get('operator')} threshold={check.get('threshold')}"
                ),
            }
        )
    return annotations


def build_ci_report(
    proof_pack: dict[str, Any],
    verification: VerificationResult,
    provider: str = "github",
) -> dict[str, Any]:
    decision = _decision(proof_pack)
    success = _success(proof_pack, verification)
    summary = _summary(proof_pack, verification)

    if provider == "gitlab":
        return {
            "schema": "trustai.gitlab-check/0.1",
            "status": "success" if success else "failed",
            "summary": summary,
            "metrics": decision.get("checks", []),
        }

    return {
        "schema": "trustai.github-check/0.1",
        "name": "TrustAI promotion gate",
        "status": "completed",
        "conclusion": "success" if success else "failure",
        "output": {
            "title": f"TrustAI gate {decision.get('outcome', 'unknown')}",
            "summary": json.dumps(summary, indent=2, sort_keys=True),
            "annotations": _check_annotations(decision),
        },
    }


def build_promotion_check_payload(
    proof_pack: dict[str, Any],
    verification: VerificationResult,
    *,
    provider: str = "github",
    commit_sha: str,
    repository: str | None = None,
    branch: str | None = None,
    target_url: str | None = None,
) -> dict[str, Any]:
    if not commit_sha:
        raise ValueError("commit_sha is required")
    if provider not in {"github", "gitlab"}:
        raise ValueError("provider must be github or gitlab")

    report = build_ci_report(proof_pack, verification, provider=provider)
    decision = _decision(proof_pack)
    summary = _summary(proof_pack, verification)
    success = _success(proof_pack, verification)

    if provider == "gitlab":
        body: dict[str, Any] = {
            "state": "success" if success else "failed",
            "name": "TrustAI promotion gate",
            "description": f"TrustAI gate {decision.get('outcome', 'unknown')} for {decision.get('contract_id')}",
        }
        if target_url:
            body["target_url"] = target_url
        if branch:
            body["ref"] = branch
        payload = {
            "schema": "trustai.gitlab-status-payload/0.1",
            "provider": "gitlab",
            "pack_id": proof_pack.get("pack_id"),
            "contract_id": decision.get("contract_id"),
            "contract_hash": decision.get("contract_hash"),
            "agent": decision.get("agent", {}),
            "summary": summary,
            "source_report_hash": content_hash(report),
            "request": {
                "method": "POST",
                "path": f"/projects/{repository or ':id'}/statuses/{commit_sha}",
                "body": body,
            },
        }
    else:
        output = report.get("output", {})
        if target_url:
            output = {**output, "text": f"Proof pack: {target_url}"}
        payload = {
            "schema": "trustai.github-check-run-payload/0.1",
            "provider": "github",
            "pack_id": proof_pack.get("pack_id"),
            "contract_id": decision.get("contract_id"),
            "contract_hash": decision.get("contract_hash"),
            "agent": decision.get("agent", {}),
            "summary": summary,
            "source_report_hash": content_hash(report),
            "request": {
                "method": "POST",
                "path": f"/repos/{repository or ':owner/:repo'}/check-runs",
                "body": {
                    "name": report.get("name", "TrustAI promotion gate"),
                    "head_sha": commit_sha,
                    "status": report.get("status", "completed"),
                    "conclusion": report.get("conclusion", "failure"),
                    "output": output,
                },
            },
        }
    payload["payload_hash"] = content_hash(payload)
    return payload


def _approval_roles(decision: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    approvals = decision.get("approvals", {})
    required = approvals.get("required", []) if isinstance(approvals, dict) else []
    actual = approvals.get("actual", []) if isinstance(approvals, dict) else []
    required = [item for item in required if isinstance(item, dict) and item.get("role")]
    actual = [item for item in actual if isinstance(item, dict) and item.get("role")]
    return required, actual


def _role_items(required: list[dict[str, Any]], requested_roles: list[str] | None) -> list[dict[str, Any]]:
    if not requested_roles:
        return required
    by_role = {item["role"]: item for item in required}
    return [by_role.get(role, {"role": role, "description": ""}) for role in requested_roles]


def _slack_action_id(role: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in role.lower()).strip("_")
    return f"trustai_approve_{safe or 'role'}"


def build_slack_approval_request(
    proof_pack: dict[str, Any],
    *,
    channel: str,
    requested_roles: list[str] | None = None,
    requester: str | None = None,
    callback_url: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    if not channel:
        raise ValueError("channel is required")

    decision = _decision(proof_pack)
    required, actual = _approval_roles(decision)
    approved_roles = sorted({item["role"] for item in actual})
    missing_roles = [item for item in required if item["role"] not in approved_roles]
    role_items = _role_items(missing_roles or required, requested_roles)
    roles = [item["role"] for item in role_items]
    basis = {
        "pack_id": proof_pack.get("pack_id"),
        "contract_id": decision.get("contract_id"),
        "contract_hash": decision.get("contract_hash"),
        "channel": channel,
        "roles": roles,
    }
    request_id = content_hash(basis)[:32]
    agent = decision.get("agent", {})
    agent_name = agent.get("name", "agent")
    text = f"TrustAI approval requested for {agent_name} / {decision.get('contract_id')}"
    role_text = "\n".join(
        f"- `{item['role']}`: {item.get('description', '')}" if item.get("description") else f"- `{item['role']}`"
        for item in role_items
    ) or "- No pending roles"

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": "TrustAI promotion approval"}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Agent*\n{agent_name}"},
                {"type": "mrkdwn", "text": f"*Contract*\n{decision.get('contract_id')}"},
                {"type": "mrkdwn", "text": f"*Gate*\n{decision.get('outcome', 'unknown')}"},
                {"type": "mrkdwn", "text": f"*Pack*\n{str(proof_pack.get('pack_id', ''))[:12]}"},
            ],
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Requested approvals*\n{role_text}"}},
    ]
    actions = []
    for item in role_items[:5]:
        role = item["role"]
        actions.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": f"Approve {role}"},
                "style": "primary",
                "value": content_hash({"approval_request_id": request_id, "role": role})[:75],
                "action_id": _slack_action_id(role),
            }
        )
    if actions:
        blocks.append({"type": "actions", "elements": actions})

    body: dict[str, Any] = {"channel": channel, "text": text, "blocks": blocks}
    if callback_url:
        body["metadata"] = {
            "event_type": "trustai_approval_request",
            "event_payload": {"approval_request_id": request_id, "callback_url": callback_url},
        }

    templates = [
        {
            "schema": APPROVAL_SCHEMA,
            "source": "slack",
            "role": role,
            "external_ref": f"slack://{channel}/{request_id}/{role}",
            "metadata": {
                "approval_request_id": request_id,
                "pack_id": proof_pack.get("pack_id"),
                "contract_id": decision.get("contract_id"),
                "contract_hash": decision.get("contract_hash"),
            },
        }
        for role in roles
    ]

    payload: dict[str, Any] = {
        "schema": "trustai.slack-approval-request/0.1",
        "provider": "slack",
        "approval_request_id": request_id,
        "pack_id": proof_pack.get("pack_id"),
        "contract_id": decision.get("contract_id"),
        "contract_hash": decision.get("contract_hash"),
        "agent": agent,
        "gate_outcome": decision.get("outcome"),
        "channel": channel,
        "requester": requester,
        "requested_roles": roles,
        "missing_roles": [item["role"] for item in missing_roles],
        "already_approved_roles": approved_roles,
        "approval_templates": templates,
        "request": {"method": "POST", "path": "/api/chat.postMessage", "body": body},
    }
    if callback_url:
        payload["callback_url"] = callback_url
    if expires_at:
        payload["expires_at"] = expires_at
    payload["payload_hash"] = content_hash(payload)
    return payload


def write_ci_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")