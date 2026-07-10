from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain
from .contracts import contract_hash
from .crypto import sign_value, verify_value
from .shadow import SOAK_REPORT_ENTRY_TYPE, verify_soak_report_payload

INCIDENT_ENTRY_TYPE = "incident.recorded"
DEMOTION_ENTRY_TYPE = "promotion_gate.demoted"
ROLLBACK_ENTRY_TYPE = "promotion_gate.rolled_back"
SOAK_DEMOTION_SCHEMA = "trustai.soak-demotion/0.1"
SOAK_DEMOTION_ENTRY_TYPE = "soak_demotion.attested"


@dataclass
class SoakDemotionVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


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


def load_soak_demotion_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("soak demotion receipt must contain an object")
    return value


def write_soak_demotion_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_soak_demotion_receipt(
    contract: dict[str, Any],
    soak_entry: dict[str, Any],
    demotion_entry: dict[str, Any],
    *,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    body = _soak_demotion_body(contract, soak_entry, demotion_entry, attested_at=attested_at or utc_now())
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "soak_demotion": body}, key)],
    }


def verify_soak_demotion_receipt(
    receipt: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    soak_entry: dict[str, Any] | None = None,
    demotion_entry: dict[str, Any] | None = None,
    key: str | None = None,
) -> SoakDemotionVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if receipt.get("schema") != SOAK_DEMOTION_SCHEMA:
        errors.append(f"unsupported soak demotion schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    if receipt.get("receipt_id") != content_hash(body):
        errors.append("receipt_id does not match canonical soak demotion body")
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("soak demotion receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "soak_demotion": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("soak demotion signature verification failed")

    source = receipt.get("source")
    if not isinstance(source, dict):
        errors.append("soak demotion source must be an object")
        source = {}
    expected_violations = _soak_demotion_violations(source)
    if receipt.get("violations") != expected_violations:
        errors.append("soak demotion violations do not match source checks")
    if receipt.get("passed") is not (not expected_violations):
        errors.append("soak demotion passed flag does not match violations")
    if expected_violations:
        warnings.append("soak demotion receipt contains binding violations")

    if contract is not None or soak_entry is not None or demotion_entry is not None:
        if contract is None or soak_entry is None or demotion_entry is None:
            errors.append("contract, soak_entry, and demotion_entry are required to replay soak demotion sources")
        else:
            try:
                expected = _soak_demotion_body(
                    contract,
                    soak_entry,
                    demotion_entry,
                    attested_at=str(receipt.get("attested_at") or ""),
                )
            except ValueError as exc:
                errors.append(f"soak demotion source replay failed: {exc}")
            else:
                for field in ("contract", "soak_report", "demotion", "source", "controls", "violations", "passed"):
                    if receipt.get(field) != expected.get(field):
                        errors.append(f"soak demotion {field} mismatch")
    else:
        warnings.append("soak demotion source artifacts were not supplied; receipt signature only was verified")
    return SoakDemotionVerification(ok=not errors, errors=errors, warnings=warnings)


def append_soak_demotion_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    soak_entry: dict[str, Any] | None = None,
    demotion_entry: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_soak_demotion_receipt(
        receipt,
        contract=contract,
        soak_entry=soak_entry,
        demotion_entry=demotion_entry,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid soak demotion receipt: " + "; ".join(result.errors))
    entry_payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "contract": receipt.get("contract"),
        "soak_report": receipt.get("soak_report"),
        "demotion": receipt.get("demotion"),
        "source": receipt.get("source"),
        "violation_count": len(receipt.get("violations", [])),
        "passed": receipt.get("passed"),
    }
    return chain.append(SOAK_DEMOTION_ENTRY_TYPE, entry_payload, key=key, timestamp=receipt.get("attested_at"))

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


def _soak_demotion_body(
    contract: dict[str, Any],
    soak_entry: dict[str, Any],
    demotion_entry: dict[str, Any],
    *,
    attested_at: str,
) -> dict[str, Any]:
    if soak_entry.get("entry_type") != SOAK_REPORT_ENTRY_TYPE:
        raise ValueError("soak_entry must be a soak_report.completed entry")
    if demotion_entry.get("entry_type") != DEMOTION_ENTRY_TYPE:
        raise ValueError("demotion_entry must be a promotion_gate.demoted entry")
    soak_payload = soak_entry.get("payload") if isinstance(soak_entry.get("payload"), dict) else {}
    demotion_payload = demotion_entry.get("payload") if isinstance(demotion_entry.get("payload"), dict) else {}
    digest = contract_hash(contract)
    failed_checks = [check for check in soak_payload.get("checks", []) if isinstance(check, dict) and not check.get("passed")]
    blocking_incidents = [
        incident
        for incident in soak_payload.get("incidents", [])
        if isinstance(incident, dict) and str(incident.get("severity", "")).lower() in {"high", "critical"}
    ]
    blocking_drift = [
        alarm
        for alarm in soak_payload.get("drift_alarms", [])
        if isinstance(alarm, dict) and str(alarm.get("severity", "")).lower() in {"high", "critical"}
    ]
    expected_trigger = {
        "entry_type": SOAK_REPORT_ENTRY_TYPE,
        "entry_id": soak_entry.get("entry_id"),
        "report_id": soak_payload.get("report_id"),
        "outcome": soak_payload.get("outcome"),
        "failed_checks": failed_checks,
        "blocking_incidents": blocking_incidents,
        "blocking_drift_alarms": blocking_drift,
    }
    soak_result = verify_soak_report_payload(soak_payload, contract)
    source = {
        "contract_hash_matches_soak": soak_payload.get("contract_hash") == digest,
        "contract_hash_matches_demotion": demotion_payload.get("contract_hash") == digest,
        "soak_report_verified": soak_result.ok,
        "soak_failed": soak_payload.get("passed") is False and soak_payload.get("outcome") == "failed",
        "demotion_trigger_entry_matches": demotion_payload.get("triggering_entry_id") == soak_entry.get("entry_id"),
        "demotion_trigger_summary_matches": demotion_payload.get("trigger") == expected_trigger,
        "demotion_environment_changes": bool(demotion_payload.get("from_environment")) and bool(demotion_payload.get("to_environment")) and demotion_payload.get("from_environment") != demotion_payload.get("to_environment"),
        "demotion_reason_present": bool(demotion_payload.get("reason")),
        "demotion_decided_at_present": bool(demotion_payload.get("decided_at")),
        "failed_check_count": len(failed_checks),
        "blocking_incident_count": len(blocking_incidents),
        "blocking_drift_count": len(blocking_drift),
        "soak_verification_error_count": len(soak_result.errors),
        "soak_verification_warning_count": len(soak_result.warnings),
    }
    violations = _soak_demotion_violations(source)
    return {
        "schema": SOAK_DEMOTION_SCHEMA,
        "attested_at": attested_at,
        "contract": {
            "contract_id": contract.get("id"),
            "contract_hash": digest,
            "agent": contract.get("agent"),
        },
        "soak_report": {
            "entry_id": soak_entry.get("entry_id"),
            "entry_hash": content_hash(soak_entry),
            "report_id": soak_payload.get("report_id"),
            "evaluated_at": soak_payload.get("evaluated_at"),
            "outcome": soak_payload.get("outcome"),
            "passed": soak_payload.get("passed"),
            "failed_checks": failed_checks,
            "blocking_incidents": blocking_incidents,
            "blocking_drift_alarms": blocking_drift,
        },
        "demotion": {
            "entry_id": demotion_entry.get("entry_id"),
            "entry_hash": content_hash(demotion_entry),
            "from_environment": demotion_payload.get("from_environment"),
            "to_environment": demotion_payload.get("to_environment"),
            "reason": demotion_payload.get("reason"),
            "triggering_entry_id": demotion_payload.get("triggering_entry_id"),
            "decided_at": demotion_payload.get("decided_at"),
        },
        "source": source,
        "controls": _soak_demotion_controls(source),
        "violations": violations,
        "passed": not violations,
        "limitations": [
            "This receipt proves a failed soak report replay-binds to a demotion event in the TrustAI evidence chain.",
            "It does not prove a production orchestrator actually removed traffic without deployment, provider, or runtime authority evidence.",
        ],
    }


def _soak_demotion_violations(source: dict[str, Any]) -> list[dict[str, Any]]:
    checks = (
        ("contract_hash_matches_soak", "soak report contract hash does not match contract"),
        ("contract_hash_matches_demotion", "demotion contract hash does not match contract"),
        ("soak_report_verified", "soak report does not replay against the contract"),
        ("soak_failed", "soak report did not fail"),
        ("demotion_trigger_entry_matches", "demotion triggering entry does not match failed soak report"),
        ("demotion_trigger_summary_matches", "demotion trigger summary does not match failed soak details"),
        ("demotion_environment_changes", "demotion does not move between environments"),
        ("demotion_reason_present", "demotion reason is missing"),
        ("demotion_decided_at_present", "demotion decided_at timestamp is missing"),
    )
    violations: list[dict[str, Any]] = []
    for field, message in checks:
        if source.get(field) is not True:
            violations.append({"check": field, "violation": message})
    return violations


def _soak_demotion_controls(source: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"id": "soak-report-replayed", "status": "passed" if source.get("soak_report_verified") else "failed", "description": "Failed soak evidence replays against the contract before demotion is trusted."},
        {"id": "contract-bound", "status": "passed" if source.get("contract_hash_matches_soak") and source.get("contract_hash_matches_demotion") else "failed", "description": "Soak and demotion entries are bound to the same verification contract."},
        {"id": "failure-bound", "status": "passed" if source.get("soak_failed") and (source.get("failed_check_count") or source.get("blocking_incident_count") or source.get("blocking_drift_count")) else "failed", "description": "Demotion is justified by failed metrics, high-severity incidents, or blocking drift alarms."},
        {"id": "demotion-trigger-bound", "status": "passed" if source.get("demotion_trigger_entry_matches") and source.get("demotion_trigger_summary_matches") else "failed", "description": "Demotion trigger points to the failed soak entry and exact failure summary."},
        {"id": "environment-demoted", "status": "passed" if source.get("demotion_environment_changes") else "failed", "description": "Demotion moves the agent from one environment to another."},
    ]

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
