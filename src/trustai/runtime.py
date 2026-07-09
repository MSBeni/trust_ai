from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now
from .chain import EvidenceChain
from .contracts import contract_hash

RUNTIME_ENTRY_TYPE = "runtime.attested"


def load_action(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("runtime action file must contain an object")
    return value


def evaluate_runtime_action(contract: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    timestamp = action.get("timestamp") or utc_now()
    parse_rfc3339(timestamp)
    blast_radius = contract.get("blast_radius", {})
    checks: list[dict[str, Any]] = []

    if "max_notional_usd" in blast_radius and "notional_usd" in action:
        actual = action["notional_usd"]
        threshold = blast_radius["max_notional_usd"]
        checks.append(
            {
                "name": "max_notional_usd",
                "actual": actual,
                "operator": "<=",
                "threshold": threshold,
                "passed": actual <= threshold,
            }
        )

    if "max_daily_orders" in blast_radius and "daily_order_count" in action:
        actual = action["daily_order_count"]
        threshold = blast_radius["max_daily_orders"]
        checks.append(
            {
                "name": "max_daily_orders",
                "actual": actual,
                "operator": "<=",
                "threshold": threshold,
                "passed": actual <= threshold,
            }
        )

    if contract.get("agent", {}).get("risk_class") and action.get("risk_class"):
        expected = contract["agent"]["risk_class"]
        actual = action["risk_class"]
        checks.append(
            {
                "name": "risk_class",
                "actual": actual,
                "operator": "==",
                "threshold": expected,
                "passed": actual == expected,
            }
        )

    if action.get("requires_human_approval"):
        approval = action.get("approval", {})
        checks.append(
            {
                "name": "human_approval",
                "actual": bool(approval.get("approved_at")),
                "operator": "==",
                "threshold": True,
                "passed": bool(approval.get("approved_at")),
            }
        )

    passed = all(check["passed"] for check in checks)
    return {
        "contract_id": contract["id"],
        "contract_hash": contract_hash(contract),
        "action_hash": content_hash(action),
        "timestamp": timestamp,
        "passed": passed,
        "outcome": "passed" if passed else "failed",
        "checks": checks,
        "action": action,
    }


def append_runtime_attestation(
    chain: EvidenceChain,
    contract: dict[str, Any],
    action: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    attestation = evaluate_runtime_action(contract, action)
    return chain.append(RUNTIME_ENTRY_TYPE, attestation, key=key, timestamp=attestation["timestamp"])
