from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approvals import APPROVAL_SCHEMA
from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .delivery import verify_provider_delivery
from .verifier import VerificationResult

PROMOTION_STATUS_SCHEMA = "trustai.promotion-status/0.1"
PROMOTION_STATUS_ENTRY_TYPE = "promotion_status.attested"


@dataclass
class PromotionStatusVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


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
    external_id = _promotion_status_external_id(
        pack_id=proof_pack.get("pack_id"),
        contract_hash=decision.get("contract_hash"),
        commit_sha=commit_sha,
    )

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
            "proof_pack_url": target_url,
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
            "proof_pack_url": target_url,
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
                    "external_id": external_id,
                    "output": output,
                },
            },
        }
        if target_url:
            payload["request"]["body"]["details_url"] = target_url
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


def load_promotion_status_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("promotion status receipt must contain an object")
    return value


def write_promotion_status_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_promotion_status_receipt(
    proof_pack: dict[str, Any],
    verification: VerificationResult,
    payload: dict[str, Any],
    *,
    delivery: dict[str, Any] | None = None,
    delivery_payload_artifact_path: str | Path | None = None,
    delivery_response_artifact_path: str | Path | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    body = _promotion_status_body(
        proof_pack,
        verification,
        payload,
        delivery=delivery,
        delivery_payload_artifact_path=delivery_payload_artifact_path,
        delivery_response_artifact_path=delivery_response_artifact_path,
        attested_at=attested_at or utc_now(),
    )
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "promotion_status": body}, key)],
    }


def verify_promotion_status_receipt(
    receipt: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    verification: VerificationResult | None = None,
    payload: dict[str, Any] | None = None,
    delivery: dict[str, Any] | None = None,
    delivery_payload_artifact_path: str | Path | None = None,
    delivery_response_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> PromotionStatusVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if receipt.get("schema") != PROMOTION_STATUS_SCHEMA:
        errors.append(f"unsupported promotion status schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    if receipt.get("receipt_id") != content_hash(body):
        errors.append("receipt_id does not match canonical promotion status body")
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("promotion status receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "promotion_status": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("promotion status signature verification failed")

    source = receipt.get("source")
    if not isinstance(source, dict):
        errors.append("promotion status source must be an object")
        source = {}
    expected_violations = _promotion_status_violations(source)
    if receipt.get("violations") != expected_violations:
        errors.append("promotion status violations do not match source checks")
    if receipt.get("passed") is not (not expected_violations):
        errors.append("promotion status passed flag does not match violations")
    if expected_violations:
        warnings.append("promotion status receipt contains provider status violations")

    if proof_pack is not None or payload is not None or delivery is not None:
        if proof_pack is None or verification is None or payload is None:
            errors.append("proof_pack, verification, and payload are required to replay promotion status sources")
        else:
            try:
                expected = _promotion_status_body(
                    proof_pack,
                    verification,
                    payload,
                    delivery=delivery,
                    delivery_payload_artifact_path=delivery_payload_artifact_path,
                    delivery_response_artifact_path=delivery_response_artifact_path,
                    attested_at=str(receipt.get("attested_at") or ""),
                )
            except ValueError as exc:
                errors.append(f"promotion status source replay failed: {exc}")
            else:
                for field in ("provider", "proof_pack", "gate_decision", "provider_payload", "provider_delivery", "provider_status", "source", "controls", "violations", "passed"):
                    if receipt.get(field) != expected.get(field):
                        errors.append(f"promotion status {field} mismatch")
    else:
        warnings.append("promotion status source artifacts were not supplied; receipt signature only was verified")
    return PromotionStatusVerification(ok=not errors, errors=errors, warnings=warnings)


def append_promotion_status_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    proof_pack: dict[str, Any] | None = None,
    verification: VerificationResult | None = None,
    payload: dict[str, Any] | None = None,
    delivery: dict[str, Any] | None = None,
    delivery_payload_artifact_path: str | Path | None = None,
    delivery_response_artifact_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_promotion_status_receipt(
        receipt,
        proof_pack=proof_pack,
        verification=verification,
        payload=payload,
        delivery=delivery,
        delivery_payload_artifact_path=delivery_payload_artifact_path,
        delivery_response_artifact_path=delivery_response_artifact_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid promotion status receipt: " + "; ".join(result.errors))
    entry_payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "provider": receipt.get("provider"),
        "proof_pack": receipt.get("proof_pack"),
        "gate_decision": receipt.get("gate_decision"),
        "provider_payload": receipt.get("provider_payload"),
        "provider_delivery": receipt.get("provider_delivery"),
        "provider_status": receipt.get("provider_status"),
        "source": receipt.get("source"),
        "violation_count": len(receipt.get("violations", [])),
        "passed": receipt.get("passed"),
    }
    return chain.append(PROMOTION_STATUS_ENTRY_TYPE, entry_payload, key=key, timestamp=receipt.get("attested_at"))


def _promotion_status_body(
    proof_pack: dict[str, Any],
    verification: VerificationResult,
    payload: dict[str, Any],
    *,
    delivery: dict[str, Any] | None,
    delivery_payload_artifact_path: str | Path | None,
    delivery_response_artifact_path: str | Path | None,
    attested_at: str,
) -> dict[str, Any]:
    if payload.get("provider") not in {"github", "gitlab"}:
        raise ValueError("promotion status payload provider must be github or gitlab")
    if payload.get("payload_hash") != content_hash(without_keys(payload, "payload_hash")):
        raise ValueError("promotion status payload_hash does not match payload body")
    decision = _decision(proof_pack)
    provider_status = _provider_status(payload)
    provider_target = _provider_target_ref(payload)
    provider_proof_pack_ref = _provider_proof_pack_ref(payload, provider_target)
    expected_success = verification.ok and decision.get("outcome") == "passed"
    delivery_binding = (
        _promotion_delivery_binding(
            delivery,
            payload,
            payload_artifact_path=delivery_payload_artifact_path,
            response_artifact_path=delivery_response_artifact_path,
        )
        if delivery is not None
        else None
    )
    source = {
        "proof_pack_verified": bool(verification.ok),
        "pack_id_matches": proof_pack.get("pack_id") == payload.get("pack_id"),
        "contract_id_matches": decision.get("contract_id") == payload.get("contract_id"),
        "contract_hash_matches": decision.get("contract_hash") == payload.get("contract_hash"),
        "gate_outcome_matches": decision.get("outcome") == payload.get("summary", {}).get("gate_outcome"),
        "payload_verified_flag_matches": payload.get("summary", {}).get("verified") is bool(verification.ok),
        "provider_status_shape_valid": provider_status.get("shape_valid") is True,
        "provider_status_matches_gate": provider_status.get("success") is expected_success,
        "provider_target_ref_bound": provider_target.get("bound") is True,
        "provider_proof_pack_ref_bound": provider_proof_pack_ref.get("bound") is True,
        "delivery_verified": True if delivery_binding is None else delivery_binding.get("verification_ok"),
        "delivery_payload_matches": True if delivery_binding is None else delivery_binding.get("payload_hash_matches"),
        "delivery_payload_artifact_replayed": True if delivery_binding is None else delivery_binding.get("payload_artifact_replayed"),
        "delivery_response_artifact_replayed": True if delivery_binding is None else delivery_binding.get("response_artifact_replayed"),
        "delivery_accepted": True if delivery_binding is None else delivery_binding.get("accepted"),
        "delivery_present": delivery_binding is not None,
        "verification_error_count": len(verification.errors),
        "verification_warning_count": len(verification.warnings),
    }
    violations = _promotion_status_violations(source)
    return {
        "schema": PROMOTION_STATUS_SCHEMA,
        "attested_at": attested_at,
        "provider": payload.get("provider"),
        "proof_pack": {
            "pack_id": proof_pack.get("pack_id"),
            "pack_hash": content_hash(proof_pack),
            "verified": verification.ok,
            "error_count": len(verification.errors),
            "warning_count": len(verification.warnings),
        },
        "gate_decision": {
            "contract_id": decision.get("contract_id"),
            "contract_hash": decision.get("contract_hash"),
            "agent": decision.get("agent"),
            "outcome": decision.get("outcome"),
            "passed": decision.get("passed"),
            "gate_entry_id": decision.get("gate_entry_id"),
            "eval_entry_id": decision.get("eval_entry_id"),
        },
        "provider_payload": {
            "schema": payload.get("schema"),
            "payload_hash": payload.get("payload_hash"),
            "body_hash": content_hash(payload.get("request", {}).get("body")),
            "pack_id": payload.get("pack_id"),
            "contract_id": payload.get("contract_id"),
            "contract_hash": payload.get("contract_hash"),
            "target_ref": provider_target,
            "proof_pack_ref": provider_proof_pack_ref,
            "request": {
                "method": payload.get("request", {}).get("method"),
                "path": payload.get("request", {}).get("path"),
            },
        },
        "provider_delivery": delivery_binding,
        "provider_status": provider_status,
        "source": source,
        "controls": _promotion_status_controls(source),
        "violations": violations,
        "passed": not violations,
        "limitations": [
            "This receipt proves the provider check/status payload matches the verified TrustAI proof-pack gate decision and, when supplied, the provider delivery receipt.",
            "It does not prove the external provider displayed or retained the status unless paired with provider-owned webhook/audit-log exports and production authority dossiers.",
        ],
    }


def _provider_status(payload: dict[str, Any]) -> dict[str, Any]:
    request_body = payload.get("request", {}).get("body", {})
    if not isinstance(request_body, dict):
        request_body = {}
    if payload.get("provider") == "gitlab":
        state = request_body.get("state")
        return {
            "kind": "gitlab-status",
            "state": state,
            "target_url": request_body.get("target_url"),
            "success": state == "success",
            "shape_valid": state in {"success", "failed"},
        }
    conclusion = request_body.get("conclusion")
    status = request_body.get("status")
    head_sha = request_body.get("head_sha")
    return {
        "kind": "github-check-run",
        "status": status,
        "conclusion": conclusion,
        "head_sha": head_sha,
        "details_url": request_body.get("details_url"),
        "external_id": request_body.get("external_id"),
        "success": status == "completed" and conclusion == "success",
        "shape_valid": status == "completed" and conclusion in {"success", "failure"} and _is_commit_sha(head_sha),
    }


def _provider_target_ref(payload: dict[str, Any]) -> dict[str, Any]:
    request = payload.get("request", {})
    request_body = request.get("body", {}) if isinstance(request, dict) else {}
    if not isinstance(request_body, dict):
        request_body = {}
    path = str(request.get("path") or "") if isinstance(request, dict) else ""
    method = request.get("method") if isinstance(request, dict) else None
    method_ok = method == "POST"
    if payload.get("provider") == "gitlab":
        project_ref, commit_sha = _gitlab_project_and_commit(path)
        project_bound = bool(project_ref and project_ref != ":id" and ":" not in project_ref)
        commit_bound = _is_commit_sha(commit_sha)
        branch_ref = request_body.get("ref")
        branch_bound = branch_ref is None or (isinstance(branch_ref, str) and bool(branch_ref))
        return {
            "provider": "gitlab",
            "method": method,
            "project_ref": project_ref,
            "commit_sha": commit_sha,
            "branch_ref": branch_ref,
            "project_bound": project_bound,
            "commit_sha_bound": commit_bound,
            "branch_ref_bound": branch_bound,
            "bound": method_ok and project_bound and commit_bound and branch_bound,
        }
    repository = _github_repository_from_path(path)
    head_sha = request_body.get("head_sha")
    repository_bound = bool(repository and ":" not in repository and len([part for part in repository.split("/") if part]) >= 2)
    commit_bound = _is_commit_sha(head_sha)
    return {
        "provider": "github",
        "method": method,
        "repository": repository,
        "commit_sha": head_sha,
        "repository_bound": repository_bound,
        "commit_sha_bound": commit_bound,
        "bound": method_ok and repository_bound and commit_bound,
    }


def _github_repository_from_path(path: str) -> str | None:
    prefix = "/repos/"
    suffix = "/check-runs"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    repository = path[len(prefix) : -len(suffix)]
    return repository or None


def _gitlab_project_and_commit(path: str) -> tuple[str | None, str | None]:
    prefix = "/projects/"
    separator = "/statuses/"
    if not path.startswith(prefix) or separator not in path[len(prefix) :]:
        return None, None
    rest = path[len(prefix) :]
    project_ref, commit_sha = rest.rsplit(separator, 1)
    return project_ref or None, commit_sha or None


def _is_commit_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _promotion_status_external_id(*, pack_id: Any, contract_hash: Any, commit_sha: Any) -> str:
    return content_hash(
        {
            "pack_id": pack_id,
            "contract_hash": contract_hash,
            "commit_sha": commit_sha,
        }
    )[:64]


def _provider_proof_pack_ref(payload: dict[str, Any], provider_target: dict[str, Any]) -> dict[str, Any]:
    request = payload.get("request", {})
    request_body = request.get("body", {}) if isinstance(request, dict) else {}
    if not isinstance(request_body, dict):
        request_body = {}
    proof_pack_url = payload.get("proof_pack_url")
    if payload.get("provider") == "gitlab":
        native_url = request_body.get("target_url")
        url_bound = proof_pack_url is None or (native_url == proof_pack_url and _is_http_url(native_url))
        return {
            "provider": "gitlab",
            "proof_pack_url": proof_pack_url,
            "target_url": native_url,
            "url_bound": url_bound,
            "external_id_bound": True,
            "bound": url_bound,
        }
    expected_external_id = _promotion_status_external_id(
        pack_id=payload.get("pack_id"),
        contract_hash=payload.get("contract_hash"),
        commit_sha=provider_target.get("commit_sha"),
    )
    external_id = request_body.get("external_id")
    native_url = request_body.get("details_url")
    url_bound = proof_pack_url is None or (native_url == proof_pack_url and _is_http_url(native_url))
    external_id_bound = external_id == expected_external_id
    return {
        "provider": "github",
        "proof_pack_url": proof_pack_url,
        "details_url": native_url,
        "external_id": external_id,
        "expected_external_id": expected_external_id,
        "url_bound": url_bound,
        "external_id_bound": external_id_bound,
        "bound": url_bound and external_id_bound,
    }


def _is_http_url(value: Any) -> bool:
    return isinstance(value, str) and (value.startswith("https://") or value.startswith("http://"))


def _promotion_delivery_binding(
    delivery: dict[str, Any],
    payload: dict[str, Any],
    *,
    payload_artifact_path: str | Path | None,
    response_artifact_path: str | Path | None,
) -> dict[str, Any]:
    result = verify_provider_delivery(
        delivery,
        payload,
        payload_artifact_path=payload_artifact_path,
        response_artifact_path=response_artifact_path,
    )
    response = delivery.get("response") if isinstance(delivery.get("response"), dict) else {}
    return {
        "delivery_id": delivery.get("delivery_id"),
        "delivery_hash": content_hash(delivery),
        "mode": delivery.get("mode"),
        "payload_hash": delivery.get("payload_hash"),
        "payload_hash_matches": delivery.get("payload_hash") == payload.get("payload_hash"),
        "target_url": delivery.get("target_url"),
        "accepted": bool(response.get("accepted")) if response else delivery.get("mode") == "dry-run",
        "response": response or None,
        "payload_artifact": delivery.get("payload_artifact"),
        "response_artifact": delivery.get("response_artifact"),
        "payload_artifact_replayed": delivery.get("payload_artifact") is None or payload_artifact_path is not None,
        "response_artifact_replayed": delivery.get("response_artifact") is None or response_artifact_path is not None,
        "verification_ok": result.ok,
        "verification_errors": result.errors,
        "verification_warnings": result.warnings,
    }


def _promotion_status_violations(source: dict[str, Any]) -> list[dict[str, Any]]:
    checks = (
        ("proof_pack_verified", "proof pack did not verify offline"),
        ("pack_id_matches", "provider payload pack_id does not match proof pack"),
        ("contract_id_matches", "provider payload contract_id does not match gate decision"),
        ("contract_hash_matches", "provider payload contract_hash does not match gate decision"),
        ("gate_outcome_matches", "provider payload gate outcome summary does not match gate decision"),
        ("payload_verified_flag_matches", "provider payload verified flag does not match offline verification"),
        ("provider_status_shape_valid", "provider status/check payload has an invalid provider status shape"),
        ("provider_status_matches_gate", "provider status/check result does not match gate decision"),
        ("provider_target_ref_bound", "provider status/check payload is not bound to a concrete repository/project commit ref"),
        ("provider_proof_pack_ref_bound", "provider status/check payload is not bound to a native proof-pack URL or correlation ID"),
        ("delivery_verified", "provider delivery receipt verification failed"),
        ("delivery_payload_matches", "provider delivery payload hash does not match status payload"),
        ("delivery_payload_artifact_replayed", "provider delivery retained payload artifact was not replayed"),
        ("delivery_response_artifact_replayed", "provider delivery retained response artifact was not replayed"),
        ("delivery_accepted", "provider delivery receipt does not show accepted dispatch"),
    )
    violations: list[dict[str, Any]] = []
    for field, message in checks:
        if source.get(field) is not True:
            violations.append({"check": field, "violation": message})
    return violations


def _promotion_status_controls(source: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"id": "proof-pack-verified", "status": "passed" if source.get("proof_pack_verified") else "failed", "description": "Proof pack verifies offline before CI/CD status is trusted."},
        {"id": "provider-payload-bound", "status": "passed" if source.get("pack_id_matches") and source.get("contract_hash_matches") else "failed", "description": "Provider payload is bound to the proof-pack pack ID and contract hash."},
        {"id": "gate-outcome-bound", "status": "passed" if source.get("gate_outcome_matches") and source.get("provider_status_matches_gate") and source.get("provider_status_shape_valid") else "failed", "description": "Provider status/check result and provider-native status shape match the TrustAI gate outcome."},
        {"id": "provider-target-ref-bound", "status": "passed" if source.get("provider_target_ref_bound") else "failed", "description": "Provider status/check payload targets a concrete repository or project commit ref."},
        {"id": "provider-proof-pack-ref-bound", "status": "passed" if source.get("provider_proof_pack_ref_bound") else "failed", "description": "Provider status/check payload carries a native proof-pack URL or correlation ID for third-party review."},
        {"id": "delivery-bound", "status": "passed" if source.get("delivery_present") and source.get("delivery_verified") and source.get("delivery_payload_matches") else "deferred", "description": "Provider delivery receipt is replay-bound when supplied."},
        {"id": "delivery-artifacts-replayed", "status": "passed" if source.get("delivery_payload_artifact_replayed") and source.get("delivery_response_artifact_replayed") else "failed", "description": "Retained provider delivery payload and response artifacts are replayed when the delivery receipt binds them."},
        {"id": "delivery-accepted", "status": "passed" if source.get("delivery_accepted") else "deferred", "description": "Provider delivery was accepted or explicitly dry-run for local rehearsal."},
    ]

def write_ci_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")