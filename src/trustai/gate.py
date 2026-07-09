from __future__ import annotations

import operator
from typing import Any, Callable

from .approvals import approvals_from_entries
from .canonical import content_hash, parse_rfc3339, utc_now
from .chain import EvidenceChain
from .contracts import contract_hash, find_contract_registration

EVAL_ENTRY_TYPE = "eval.completed"
GATE_ENTRY_TYPE = "promotion_gate.decided"

OPS: dict[str, Callable[[Any, Any], bool]] = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "==": operator.eq,
    "!=": operator.ne,
}


def evaluate_contract(
    contract: dict[str, Any],
    results: dict[str, Any],
    approval_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    digest = contract_hash(contract)
    metric_results = results.get("metrics", {})
    checks: list[dict[str, Any]] = []
    for metric in contract["metrics"]:
        name = metric["name"]
        op_name = metric["operator"]
        threshold = metric["threshold"]
        actual = metric_results.get(name)
        passed = False
        reason = None
        if actual is None:
            reason = "missing metric"
        else:
            try:
                passed = bool(OPS[op_name](actual, threshold))
            except TypeError as exc:
                reason = f"type mismatch: {exc}"
        checks.append(
            {
                "name": name,
                "operator": op_name,
                "threshold": threshold,
                "actual": actual,
                "passed": passed,
                "reason": reason,
            }
        )

    holdout = evaluate_holdout(contract, results)
    approvals = evaluate_approvals(contract, results, approval_entries=approval_entries)
    passed = all(check["passed"] for check in checks) and holdout["passed"] and approvals["passed"]
    return {
        "contract_id": contract["id"],
        "contract_hash": digest,
        "agent": contract["agent"],
        "evaluated_at": results.get("evaluated_at") or utc_now(),
        "outcome": "passed" if passed else "failed",
        "passed": passed,
        "checks": checks,
        "holdout": holdout,
        "approvals": approvals,
        "results_hash": content_hash(results),
    }


def evaluate_holdout(contract: dict[str, Any], results: dict[str, Any]) -> dict[str, Any]:
    freeze_at = parse_rfc3339(contract["freeze"]["frozen_at"])
    min_timestamp = parse_rfc3339(contract["holdout"]["min_timestamp"])
    require_post_freeze = contract["holdout"].get("require_post_freeze", True)
    records = results.get("dataset", {}).get("records", [])
    errors: list[str] = []
    checked = 0

    if not isinstance(records, list) or not records:
        errors.append("dataset.records must be a non-empty list")
    else:
        for record in records:
            checked += 1
            timestamp = record.get("timestamp") if isinstance(record, dict) else None
            if not timestamp:
                errors.append(f"record {checked} missing timestamp")
                continue
            parsed = parse_rfc3339(timestamp)
            if require_post_freeze and parsed <= freeze_at:
                errors.append(f"record {record.get('id', checked)} is not post-freeze")
            if parsed < min_timestamp:
                errors.append(f"record {record.get('id', checked)} is before holdout minimum")

    return {
        "passed": not errors,
        "records_checked": checked,
        "freeze_at": contract["freeze"]["frozen_at"],
        "min_timestamp": contract["holdout"]["min_timestamp"],
        "errors": errors,
    }


def evaluate_approvals(
    contract: dict[str, Any],
    results: dict[str, Any],
    approval_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    required = contract.get("required_approvals", [])
    digest = contract_hash(contract)
    result_approvals = results.get("approvals", [])
    if not isinstance(result_approvals, list):
        result_approvals = []
    chain_approvals = approvals_from_entries(approval_entries or [], digest)
    actual = [*result_approvals, *chain_approvals]
    errors: list[str] = []
    actual_by_role = {
        approval.get("role"): approval
        for approval in actual
        if isinstance(approval, dict) and approval.get("role")
    }
    for approval in required:
        role = approval["role"]
        if role not in actual_by_role:
            errors.append(f"missing approval role: {role}")
        elif not actual_by_role[role].get("approved_at"):
            errors.append(f"approval role {role} missing approved_at")
    return {"passed": not errors, "required": required, "actual": actual, "errors": errors}


def append_eval_and_gate(
    chain: EvidenceChain,
    contract: dict[str, Any],
    results: dict[str, Any],
    key: str | None = None,
    approval_entries: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    digest = contract_hash(contract)
    registration = find_contract_registration(chain, digest)
    if registration is None:
        raise ValueError("contract must be registered before eval results can be gated")

    eval_payload = {
        "contract_id": contract["id"],
        "contract_hash": digest,
        "agent": contract["agent"],
        "results_hash": content_hash(results),
        "results": results,
    }
    eval_entry = chain.append(EVAL_ENTRY_TYPE, eval_payload, key=key, timestamp=results.get("evaluated_at"))

    decision = evaluate_contract(contract, results, approval_entries=approval_entries)
    decision["contract_entry_id"] = registration["entry_id"]
    decision["eval_entry_id"] = eval_entry["entry_id"]
    gate_payload = {
        "contract_id": contract["id"],
        "contract_hash": digest,
        "agent": contract["agent"],
        "decision": decision,
    }
    gate_entry = chain.append(GATE_ENTRY_TYPE, gate_payload, key=key)
    decision["gate_entry_id"] = gate_entry["entry_id"]
    return eval_entry, gate_entry, decision
