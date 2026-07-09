from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now
from .chain import EvidenceChain
from .contracts import contract_hash
from .gate import OPS

SHADOW_REPLAY_ENTRY_TYPE = "shadow_replay.completed"
SOAK_REPORT_ENTRY_TYPE = "soak_report.completed"


def load_shadow_replay(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("shadow replay file must contain an object")
    return value


def load_soak_window(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("soak window file must contain an object")
    return value


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil((pct / 100) * len(ordered)) - 1))
    return ordered[index]


def evaluate_shadow_replay(contract: dict[str, Any], replay: dict[str, Any]) -> dict[str, Any]:
    records = replay.get("records") or replay.get("traffic") or []
    if not isinstance(records, list) or not records:
        raise ValueError("shadow replay requires a non-empty records list")

    freeze_at = parse_rfc3339(contract["freeze"]["frozen_at"])
    min_timestamp = parse_rfc3339(contract["holdout"]["min_timestamp"])
    holdout_errors: list[str] = []
    comparable = 0
    matches = 0
    violations = 0
    latencies: list[float] = []
    position_errors: list[float] = []

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            holdout_errors.append(f"record {index + 1} is not an object")
            continue
        timestamp = record.get("timestamp")
        if not timestamp:
            holdout_errors.append(f"record {index + 1} missing timestamp")
            continue
        parsed = parse_rfc3339(timestamp)
        if parsed <= freeze_at:
            holdout_errors.append(f"record {record.get('id', index + 1)} is not post-freeze")
        if parsed < min_timestamp:
            holdout_errors.append(f"record {record.get('id', index + 1)} is before holdout minimum")

        if "expected_action" in record and "candidate_action" in record:
            comparable += 1
            if record["expected_action"] == record["candidate_action"]:
                matches += 1
        if record.get("policy_violation") or record.get("violations"):
            violations += 1
        if "latency_ms" in record:
            latencies.append(float(record["latency_ms"]))
        if "position_error_usd" in record:
            position_errors.append(abs(float(record["position_error_usd"])))

    total = len(records)
    metrics = {
        "shadow_match_rate": matches / comparable if comparable else 1.0,
        "trade_policy_compliance_rate": 1 - (violations / total),
        "max_position_error_usd": max(position_errors) if position_errors else 0,
        "p95_decision_latency_ms": percentile(latencies, 95) if latencies else 0,
    }

    threshold_checks: list[dict[str, Any]] = []
    for metric in contract["metrics"]:
        name = metric["name"]
        if name not in metrics:
            continue
        actual = metrics[name]
        passed = bool(OPS[metric["operator"]](actual, metric["threshold"]))
        threshold_checks.append(
            {
                "name": name,
                "actual": actual,
                "operator": metric["operator"],
                "threshold": metric["threshold"],
                "passed": passed,
            }
        )

    passed = not holdout_errors and all(check["passed"] for check in threshold_checks)
    return {
        "run_id": replay.get("run_id"),
        "contract_id": contract["id"],
        "contract_hash": contract_hash(contract),
        "candidate_version": replay.get("candidate_version") or contract["agent"]["version"],
        "evaluated_at": replay.get("evaluated_at") or utc_now(),
        "records_checked": total,
        "metrics": metrics,
        "checks": threshold_checks,
        "holdout": {
            "passed": not holdout_errors,
            "errors": holdout_errors,
            "freeze_at": contract["freeze"]["frozen_at"],
            "min_timestamp": contract["holdout"]["min_timestamp"],
        },
        "passed": passed,
        "outcome": "passed" if passed else "failed",
    }


def shadow_replay_to_eval_results(contract: dict[str, Any], replay: dict[str, Any]) -> dict[str, Any]:
    evaluation = evaluate_shadow_replay(contract, replay)
    records = replay.get("records") or replay.get("traffic") or []
    return {
        "run_id": evaluation["run_id"] or "shadow-replay",
        "evaluated_at": evaluation["evaluated_at"],
        "dataset": {
            "id": replay.get("dataset_id") or "shadow-replay",
            "description": replay.get("description") or "Shadow replay candidate evaluation",
            "records": [
                {"id": record.get("id", str(index + 1)), "timestamp": record["timestamp"]}
                for index, record in enumerate(records)
                if isinstance(record, dict) and record.get("timestamp")
            ],
        },
        "metrics": {
            metric["name"]: evaluation["metrics"][metric["name"]]
            for metric in contract["metrics"]
            if metric["name"] in evaluation["metrics"]
        },
        "approvals": replay.get("approvals", []),
        "environment": replay.get("environment", {"runner": "trustai-shadow-replay"}),
    }


def append_shadow_replay(
    chain: EvidenceChain,
    contract: dict[str, Any],
    replay: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    evaluation = evaluate_shadow_replay(contract, replay)
    payload = {
        **evaluation,
        "replay_hash": content_hash(replay),
        "replay": replay,
    }
    return chain.append(SHADOW_REPLAY_ENTRY_TYPE, payload, key=key, timestamp=evaluation["evaluated_at"])


def evaluate_soak_window(contract: dict[str, Any], soak: dict[str, Any]) -> dict[str, Any]:
    windows = soak.get("windows", [])
    if not isinstance(windows, list) or not windows:
        raise ValueError("soak report requires a non-empty windows list")

    metric_values: dict[str, list[float]] = {}
    incidents: list[dict[str, Any]] = []
    for window in windows:
        if not isinstance(window, dict):
            continue
        for metric, value in window.get("metrics", {}).items():
            metric_values.setdefault(metric, []).append(float(value))
        incidents.extend(window.get("incidents", []))

    checks: list[dict[str, Any]] = []
    for metric in contract["metrics"]:
        name = metric["name"]
        values = metric_values.get(name)
        if not values:
            continue
        actual = min(values) if metric["operator"] in (">=", ">") else max(values)
        checks.append(
            {
                "name": name,
                "actual": actual,
                "operator": metric["operator"],
                "threshold": metric["threshold"],
                "passed": bool(OPS[metric["operator"]](actual, metric["threshold"])),
            }
        )

    severe_incidents = [
        incident
        for incident in incidents
        if incident.get("severity", "").lower() in {"high", "critical"}
    ]
    drift_alarms = soak.get("drift_alarms", [])
    blocking_drift = [
        alarm
        for alarm in drift_alarms
        if alarm.get("severity", "").lower() in {"high", "critical"}
    ]
    passed = all(check["passed"] for check in checks) and not severe_incidents and not blocking_drift
    return {
        "report_id": soak.get("report_id"),
        "contract_id": contract["id"],
        "contract_hash": contract_hash(contract),
        "evaluated_at": soak.get("evaluated_at") or utc_now(),
        "window_count": len(windows),
        "checks": checks,
        "incidents": incidents,
        "drift_alarms": drift_alarms,
        "passed": passed,
        "outcome": "passed" if passed else "failed",
    }


def append_soak_report(
    chain: EvidenceChain,
    contract: dict[str, Any],
    soak: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    report = evaluate_soak_window(contract, soak)
    payload = {
        **report,
        "soak_hash": content_hash(soak),
        "soak": soak,
    }
    return chain.append(SOAK_REPORT_ENTRY_TYPE, payload, key=key, timestamp=report["evaluated_at"])
