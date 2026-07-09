from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import EvidenceChain
from .contracts import contract_hash
from .shadow import SOAK_REPORT_ENTRY_TYPE

INCIDENT_ENTRY_TYPE = "incident.recorded"
DEMOTION_ENTRY_TYPE = "promotion_gate.demoted"
ROLLBACK_ENTRY_TYPE = "promotion_gate.rolled_back"


def load_incident(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("incident file must contain an object")
    for field in ("id", "severity", "summary"):
        if not value.get(field):
            raise ValueError(f"incident missing required field: {field}")
    return value


def append_incident(
    chain: EvidenceChain,
    incident: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    timestamp = incident.get("detected_at") or utc_now()
    payload = {
        "incident_hash": content_hash(incident),
        "contract_hash": incident.get("contract_hash"),
        "agent": incident.get("agent", {}),
        "incident": incident,
    }
    return chain.append(INCIDENT_ENTRY_TYPE, payload, key=key, timestamp=timestamp)


def append_demotion(
    chain: EvidenceChain,
    contract: dict[str, Any],
    reason: str,
    triggering_entry_id: str | None = None,
    from_environment: str = "prod",
    to_environment: str = "shadow",
    key: str | None = None,
    trigger: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "contract_id": contract["id"],
        "contract_hash": contract_hash(contract),
        "agent": contract["agent"],
        "from_environment": from_environment,
        "to_environment": to_environment,
        "reason": reason,
        "triggering_entry_id": triggering_entry_id,
        "decided_at": utc_now(),
    }
    if trigger is not None:
        payload["trigger"] = trigger
    return chain.append(DEMOTION_ENTRY_TYPE, payload, key=key, timestamp=payload["decided_at"])


def append_soak_failure_demotion(
    chain: EvidenceChain,
    contract: dict[str, Any],
    soak_entry: dict[str, Any],
    *,
    reason: str | None = None,
    from_environment: str = "prod",
    to_environment: str = "shadow",
    key: str | None = None,
) -> dict[str, Any]:
    if soak_entry.get("entry_type") != SOAK_REPORT_ENTRY_TYPE:
        raise ValueError("demotion trigger must be a soak_report.completed entry")
    payload = soak_entry.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("soak report entry payload missing")
    digest = contract_hash(contract)
    if payload.get("contract_hash") != digest:
        raise ValueError("soak report contract_hash does not match contract")
    if payload.get("passed") is True or payload.get("outcome") == "passed":
        raise ValueError("soak report passed; demotion not required")

    failed_checks = [check for check in payload.get("checks", []) if isinstance(check, dict) and not check.get("passed")]
    blocking_incidents = [
        incident
        for incident in payload.get("incidents", [])
        if isinstance(incident, dict) and str(incident.get("severity", "")).lower() in {"high", "critical"}
    ]
    blocking_drift = [
        alarm
        for alarm in payload.get("drift_alarms", [])
        if isinstance(alarm, dict) and str(alarm.get("severity", "")).lower() in {"high", "critical"}
    ]
    trigger = {
        "entry_type": SOAK_REPORT_ENTRY_TYPE,
        "entry_id": soak_entry.get("entry_id"),
        "report_id": payload.get("report_id"),
        "outcome": payload.get("outcome"),
        "failed_checks": failed_checks,
        "blocking_incidents": blocking_incidents,
        "blocking_drift_alarms": blocking_drift,
    }
    return append_demotion(
        chain,
        contract,
        reason=reason or _soak_failure_reason(payload, failed_checks, blocking_incidents, blocking_drift),
        triggering_entry_id=soak_entry.get("entry_id"),
        from_environment=from_environment,
        to_environment=to_environment,
        key=key,
        trigger=trigger,
    )


def _soak_failure_reason(
    payload: dict[str, Any],
    failed_checks: list[dict[str, Any]],
    blocking_incidents: list[dict[str, Any]],
    blocking_drift: list[dict[str, Any]],
) -> str:
    parts = []
    if failed_checks:
        parts.append("failed metrics: " + ", ".join(str(check.get("name")) for check in failed_checks))
    if blocking_incidents:
        parts.append("blocking incidents: " + ", ".join(str(item.get("id") or item.get("summary")) for item in blocking_incidents))
    if blocking_drift:
        parts.append("blocking drift alarms: " + ", ".join(str(item.get("id") or item.get("description")) for item in blocking_drift))
    detail = "; ".join(parts) or "soak report outcome failed"
    return f"Soak report {payload.get('report_id') or 'unknown'} failed: {detail}"


def append_rollback(
    chain: EvidenceChain,
    contract: dict[str, Any],
    target_agent_version: str,
    reason: str,
    triggering_entry_id: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    payload = {
        "contract_id": contract["id"],
        "contract_hash": contract_hash(contract),
        "agent": contract["agent"],
        "target_agent_version": target_agent_version,
        "reason": reason,
        "triggering_entry_id": triggering_entry_id,
        "decided_at": utc_now(),
    }
    return chain.append(ROLLBACK_ENTRY_TYPE, payload, key=key, timestamp=payload["decided_at"])
