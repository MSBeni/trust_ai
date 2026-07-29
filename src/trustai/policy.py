from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now
from .chain import EvidenceChain
from .gate import OPS

POLICY_PACK_SPEC_VERSION = "trustai.policy-pack/0.1"
POLICY_DECISION_ENTRY_TYPE = "policy.decision"


def load_policy_pack(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("policy pack must contain an object")
    validate_policy_pack(value)
    return value


def validate_policy_pack(policy_pack: dict[str, Any]) -> None:
    if policy_pack.get("spec_version") != POLICY_PACK_SPEC_VERSION:
        raise ValueError(f"policy pack spec_version must be {POLICY_PACK_SPEC_VERSION}")
    for field in ("id", "version", "rules"):
        if not policy_pack.get(field):
            raise ValueError(f"policy pack missing required field: {field}")
    if not isinstance(policy_pack["rules"], list):
        raise ValueError("policy pack rules must be a list")


def _resolve_field(context: dict[str, Any], dotted: str) -> Any:
    current: Any = context
    for part in dotted.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _condition_matches(condition: dict[str, Any], context: dict[str, Any]) -> bool:
    actual = _resolve_field(context, condition["field"])
    operator = condition["operator"]
    expected = condition.get("value")
    if operator not in OPS:
        raise ValueError(f"unsupported policy operator: {operator}")
    try:
        return bool(OPS[operator](actual, expected))
    except TypeError:
        return False


def _approval_present(action: dict[str, Any], role: str | None) -> bool:
    approvals = action.get("approvals")
    if approvals is None:
        approval = action.get("approval")
        approvals = [approval] if isinstance(approval, dict) else []
    if not isinstance(approvals, list):
        return False
    for approval in approvals:
        if not isinstance(approval, dict):
            continue
        role_matches = not role or approval.get("role") == role
        if role_matches and approval.get("approved_at"):
            return True
    return False


def _age_hours(timestamp: str, now: datetime) -> float:
    return (now - parse_rfc3339(timestamp)).total_seconds() / 3600


def _freshness_age_check(
    name: str,
    timestamp: Any,
    threshold: float,
    now: datetime,
    *,
    entry_type: str | None = None,
    timestamp_label: str = "timestamp",
) -> dict[str, Any]:
    check: dict[str, Any] = {
        "name": name,
        "operator": "<=",
        "threshold": threshold,
        "passed": False,
    }
    if entry_type:
        check["entry_type"] = entry_type
    if not timestamp:
        check["reason"] = f"missing {timestamp_label}"
        return check
    try:
        actual = _age_hours(str(timestamp), now)
    except ValueError as exc:
        check["reason"] = f"invalid {timestamp_label}: {exc}"
        return check
    check["actual"] = actual
    check["passed"] = actual <= threshold
    return check


def evaluate_proof_freshness(
    proof_pack: dict[str, Any] | None,
    policy_pack: dict[str, Any],
    now: str | None = None,
) -> dict[str, Any]:
    decay = policy_pack.get("proof_decay", {})
    now_dt = parse_rfc3339(now) if now else datetime.now(timezone.utc)
    checks: list[dict[str, Any]] = []

    if not proof_pack:
        return {
            "passed": False,
            "checks": [
                {
                    "name": "active_proof_pack",
                    "passed": False,
                    "reason": "missing proof pack",
                }
            ],
        }

    decision = proof_pack.get("gate_decision", {})
    gate_ts = decision.get("evaluated_at") or proof_pack.get("issued_at")
    if decay.get("max_gate_age_hours") is not None:
        checks.append(
            _freshness_age_check(
                "max_gate_age_hours",
                gate_ts,
                decay["max_gate_age_hours"],
                now_dt,
                timestamp_label="gate decision timestamp",
            )
        )

    latest_by_type: dict[str, str] = {}
    latest_parsed_by_type: dict[str, datetime] = {}
    invalid_timestamp_by_type: dict[str, str] = {}
    for entry in proof_pack.get("chain", {}).get("entries", []):
        entry_type = entry.get("entry_type")
        timestamp = entry.get("timestamp")
        if entry_type and timestamp:
            try:
                parsed_timestamp = parse_rfc3339(str(timestamp))
            except ValueError as exc:
                invalid_timestamp_by_type.setdefault(str(entry_type), str(exc))
                continue
            if entry_type not in latest_by_type or parsed_timestamp > latest_parsed_by_type[str(entry_type)]:
                latest_by_type[str(entry_type)] = str(timestamp)
                latest_parsed_by_type[str(entry_type)] = parsed_timestamp

    freshness_entry_map = {
        "max_soak_age_hours": "soak_report.completed",
        "max_runtime_attestation_age_hours": "runtime.attested",
        "max_shadow_replay_age_hours": "shadow_replay.completed",
    }
    for policy_key, entry_type in freshness_entry_map.items():
        if decay.get(policy_key) is None:
            continue
        if entry_type in invalid_timestamp_by_type:
            checks.append(
                {
                    "name": policy_key,
                    "entry_type": entry_type,
                    "passed": False,
                    "reason": f"invalid {entry_type} timestamp: {invalid_timestamp_by_type[entry_type]}",
                }
            )
            continue
        timestamp = latest_by_type.get(entry_type)
        if not timestamp:
            checks.append(
                {
                    "name": policy_key,
                    "entry_type": entry_type,
                    "passed": False,
                    "reason": f"missing {entry_type} evidence",
                }
            )
            continue
        checks.append(
            _freshness_age_check(
                policy_key,
                timestamp,
                decay[policy_key],
                now_dt,
                entry_type=entry_type,
                timestamp_label=f"{entry_type} timestamp",
            )
        )

    return {"passed": all(check["passed"] for check in checks), "checks": checks}


def evaluate_policy(
    policy_pack: dict[str, Any],
    action: dict[str, Any],
    proof_pack: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    validate_policy_pack(policy_pack)
    context = {
        "action": action,
        "proof": proof_pack or {},
        "policy": policy_pack,
    }
    matched_rules: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    denied = False

    freshness = evaluate_proof_freshness(proof_pack, policy_pack, now=now)
    checks.append({"name": "proof_freshness", **freshness})
    if not freshness["passed"]:
        denied = True

    for rule in policy_pack["rules"]:
        conditions = rule.get("conditions", [])
        if not conditions:
            matches = True
        else:
            matches = all(_condition_matches(condition, context) for condition in conditions)
        if not matches:
            continue

        effect = rule.get("effect", "deny")
        approval_role = rule.get("approval_role")
        rule_check = {
            "name": rule["id"],
            "effect": effect,
            "matched": True,
            "passed": True,
        }
        if effect == "deny":
            rule_check["passed"] = False
            denied = True
        elif effect == "require_approval":
            approved = _approval_present(action, approval_role)
            rule_check["approval_role"] = approval_role
            rule_check["passed"] = approved
            if not approved:
                denied = True
        elif effect == "allow":
            rule_check["passed"] = True
        else:
            raise ValueError(f"unsupported policy effect: {effect}")
        matched_rules.append(rule)
        checks.append(rule_check)

    passed = not denied
    return {
        "policy_pack_id": policy_pack["id"],
        "policy_pack_version": policy_pack["version"],
        "policy_pack_hash": content_hash(policy_pack),
        "policy_pack": policy_pack,
        "contract_hash": (proof_pack or {}).get("contract", {}).get("hash") or action.get("contract_hash"),
        "action_hash": content_hash(action),
        "evaluated_at": now or utc_now(),
        "passed": passed,
        "outcome": "allowed" if passed else "denied",
        "checks": checks,
        "matched_rules": matched_rules,
        "action": action,
    }


def append_policy_decision(
    chain: EvidenceChain,
    policy_pack: dict[str, Any],
    action: dict[str, Any],
    proof_pack: dict[str, Any] | None = None,
    key: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    decision = evaluate_policy(policy_pack, action, proof_pack=proof_pack, now=now)
    return chain.append(POLICY_DECISION_ENTRY_TYPE, decision, key=key, timestamp=decision["evaluated_at"])
