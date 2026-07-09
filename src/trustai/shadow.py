from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .contracts import contract_hash
from .crypto import sign_value, verify_value
from .keyring import verify_value_with_keyring
from .gate import OPS

SHADOW_REPLAY_ENTRY_TYPE = "shadow_replay.completed"
SOAK_REPORT_ENTRY_TYPE = "soak_report.completed"
TEMPORAL_HOLDOUT_SCHEMA = "trustai.temporal-holdout-manifest/0.1"
TEMPORAL_HOLDOUT_CHAIN_SCHEMA = "trustai.temporal-holdout-record-chain/0.1"
TEMPORAL_HOLDOUT_ENTRY_TYPE = "temporal_holdout.manifest_attested"


@dataclass
class TemporalHoldoutVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class SoakReportVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


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


def load_temporal_holdout_manifest(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("temporal holdout manifest must contain an object")
    return value


def write_temporal_holdout_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil((pct / 100) * len(ordered)) - 1))
    return ordered[index]


def build_temporal_holdout_manifest(
    contract: dict[str, Any],
    replay: dict[str, Any],
    *,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    records = _shadow_records(replay)
    freeze_at = contract["freeze"]["frozen_at"]
    min_timestamp = contract["holdout"]["min_timestamp"]
    parse_rfc3339(freeze_at)
    parse_rfc3339(min_timestamp)
    generated = generated_at or replay.get("evaluated_at") or utc_now()
    parse_rfc3339(str(generated))

    record_nodes: list[dict[str, Any]] = []
    previous_node_hash: str | None = None
    previous_timestamp: str | None = None
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"shadow replay record {index + 1} is not an object")
        timestamp = record.get("timestamp")
        if not timestamp:
            raise ValueError(f"shadow replay record {index + 1} missing timestamp")
        parsed_timestamp = parse_rfc3339(str(timestamp))
        record_id = str(record.get("id") or index + 1)
        record_hash = content_hash(record)
        node_body = {
            "schema": TEMPORAL_HOLDOUT_CHAIN_SCHEMA,
            "sequence": index,
            "record_count": len(records),
            "record_id": record_id,
            "timestamp": str(timestamp),
            "record_hash": record_hash,
            "previous_record_node_hash": previous_node_hash,
        }
        node_hash = content_hash(node_body)
        record_nodes.append(
            {
                **node_body,
                "post_freeze": parsed_timestamp > parse_rfc3339(freeze_at),
                "post_holdout_minimum": parsed_timestamp >= parse_rfc3339(min_timestamp),
                "chronological_after_previous": previous_timestamp is None
                or parsed_timestamp >= parse_rfc3339(previous_timestamp),
                "record_node_hash": node_hash,
            }
        )
        previous_node_hash = node_hash
        previous_timestamp = str(timestamp)

    violations = _temporal_holdout_violations(record_nodes, freeze_at, min_timestamp)
    timestamps = [node["timestamp"] for node in record_nodes]
    body = {
        "schema": TEMPORAL_HOLDOUT_SCHEMA,
        "generated_at": str(generated),
        "run_id": replay.get("run_id"),
        "dataset_id": replay.get("dataset_id") or "shadow-replay",
        "contract": {
            "id": contract["id"],
            "hash": contract_hash(contract),
            "freeze_at": freeze_at,
            "min_timestamp": min_timestamp,
            "require_post_freeze": bool(contract.get("holdout", {}).get("require_post_freeze", True)),
        },
        "candidate_version": replay.get("candidate_version") or contract["agent"]["version"],
        "replay_hash": content_hash(replay),
        "record_count": len(record_nodes),
        "records_root": record_nodes[-1]["record_node_hash"],
        "first_record_timestamp": timestamps[0],
        "last_record_timestamp": timestamps[-1],
        "earliest_record_timestamp": min(timestamps),
        "latest_record_timestamp": max(timestamps),
        "records": record_nodes,
        "violations": violations,
        "passed": not violations,
        "limitations": [
            "This manifest proves replay record timestamps and record hashes against the registered freeze and holdout boundary.",
            "It does not prove production traffic completeness without collector or provider-owned production export evidence.",
        ],
    }
    manifest_id = content_hash(body)
    return {
        **body,
        "manifest_id": manifest_id,
        "signatures": [sign_value({"manifest_id": manifest_id, "temporal_holdout": body}, key)],
    }


def verify_temporal_holdout_manifest(
    manifest: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    replay: dict[str, Any] | None = None,
    key: str | None = None,
    keyring: dict[str, Any] | None = None,
) -> TemporalHoldoutVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if manifest.get("schema") != TEMPORAL_HOLDOUT_SCHEMA:
        errors.append(f"unsupported temporal holdout schema: {manifest.get('schema')}")
    body = without_keys(manifest, "manifest_id", "signatures")
    if manifest.get("manifest_id") != content_hash(body):
        errors.append("manifest_id does not match canonical temporal holdout body")

    signatures = manifest.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("temporal holdout manifest must include at least one signature")
    else:
        signed_value = {"manifest_id": manifest.get("manifest_id"), "temporal_holdout": body}
        if keyring is not None:
            verified = any(
                isinstance(signature, dict) and verify_value_with_keyring(signed_value, signature, keyring)
                for signature in signatures
            )
        else:
            verified = any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures)
        if not verified:
            errors.append("temporal holdout signature verification failed")

    try:
        parse_rfc3339(str(manifest.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"temporal holdout generated_at invalid: {exc}")

    manifest_contract = manifest.get("contract", {})
    if not isinstance(manifest_contract, dict):
        errors.append("temporal holdout contract must be an object")
        manifest_contract = {}
    freeze_at = str(manifest_contract.get("freeze_at") or "")
    min_timestamp = str(manifest_contract.get("min_timestamp") or "")
    try:
        parse_rfc3339(freeze_at)
        parse_rfc3339(min_timestamp)
    except ValueError as exc:
        errors.append(f"temporal holdout boundary invalid: {exc}")

    records = manifest.get("records", [])
    if not isinstance(records, list) or not records:
        errors.append("temporal holdout manifest requires records")
        records = []
    if manifest.get("record_count") != len(records):
        errors.append("temporal holdout record_count does not match records")

    previous_node_hash: str | None = None
    previous_timestamp: str | None = None
    expected_violations: list[dict[str, Any]] = []
    for index, node in enumerate(records):
        if not isinstance(node, dict):
            errors.append(f"temporal holdout record {index + 1} must be an object")
            continue
        node_body = {
            "schema": node.get("schema"),
            "sequence": node.get("sequence"),
            "record_count": node.get("record_count"),
            "record_id": node.get("record_id"),
            "timestamp": node.get("timestamp"),
            "record_hash": node.get("record_hash"),
            "previous_record_node_hash": node.get("previous_record_node_hash"),
        }
        if node.get("schema") != TEMPORAL_HOLDOUT_CHAIN_SCHEMA:
            errors.append(f"temporal holdout record {index + 1} has unsupported schema")
        if node.get("sequence") != index:
            errors.append(f"temporal holdout record {index + 1} sequence mismatch")
        if node.get("record_count") != len(records):
            errors.append(f"temporal holdout record {index + 1} record_count mismatch")
        if node.get("previous_record_node_hash") != previous_node_hash:
            errors.append(f"temporal holdout record {index + 1} previous hash mismatch")
        if node.get("record_node_hash") != content_hash(node_body):
            errors.append(f"temporal holdout record {index + 1} node hash mismatch")
        try:
            parsed_timestamp = parse_rfc3339(str(node.get("timestamp") or ""))
            expected_post_freeze = parsed_timestamp > parse_rfc3339(freeze_at)
            expected_post_minimum = parsed_timestamp >= parse_rfc3339(min_timestamp)
            expected_chronological = previous_timestamp is None or parsed_timestamp >= parse_rfc3339(previous_timestamp)
            if node.get("post_freeze") is not expected_post_freeze:
                errors.append(f"temporal holdout record {index + 1} post_freeze mismatch")
            if node.get("post_holdout_minimum") is not expected_post_minimum:
                errors.append(f"temporal holdout record {index + 1} post_holdout_minimum mismatch")
            if node.get("chronological_after_previous") is not expected_chronological:
                errors.append(f"temporal holdout record {index + 1} chronological_after_previous mismatch")
            expected_violations.extend(_record_temporal_violations(node, parsed_timestamp, freeze_at, min_timestamp))
            if not expected_chronological:
                expected_violations.append(
                    {
                        "sequence": index,
                        "record_id": node.get("record_id"),
                        "timestamp": node.get("timestamp"),
                        "violation": "record timestamp is earlier than previous replay record",
                    }
                )
            previous_timestamp = str(node.get("timestamp"))
        except ValueError as exc:
            errors.append(f"temporal holdout record {index + 1} timestamp invalid: {exc}")
        previous_node_hash = node.get("record_node_hash")

    if records:
        if manifest.get("records_root") != records[-1].get("record_node_hash"):
            errors.append("temporal holdout records_root does not match final record node hash")
        timestamps = [str(node.get("timestamp")) for node in records if isinstance(node, dict) and node.get("timestamp")]
        if timestamps:
            if manifest.get("first_record_timestamp") != timestamps[0]:
                errors.append("temporal holdout first_record_timestamp mismatch")
            if manifest.get("last_record_timestamp") != timestamps[-1]:
                errors.append("temporal holdout last_record_timestamp mismatch")
            if manifest.get("earliest_record_timestamp") != min(timestamps):
                errors.append("temporal holdout earliest_record_timestamp mismatch")
            if manifest.get("latest_record_timestamp") != max(timestamps):
                errors.append("temporal holdout latest_record_timestamp mismatch")

    if manifest.get("violations") != expected_violations:
        errors.append("temporal holdout violations do not match record timestamps")
    if manifest.get("passed") is not (not expected_violations):
        errors.append("temporal holdout passed flag does not match violations")
    if expected_violations:
        warnings.append("temporal holdout manifest records boundary violations")

    if contract is not None:
        expected_contract_hash = contract_hash(contract)
        if manifest_contract.get("id") != contract.get("id"):
            errors.append("temporal holdout contract id mismatch")
        if manifest_contract.get("hash") != expected_contract_hash:
            errors.append("temporal holdout contract hash mismatch")
        if manifest_contract.get("freeze_at") != contract.get("freeze", {}).get("frozen_at"):
            errors.append("temporal holdout contract freeze_at mismatch")
        if manifest_contract.get("min_timestamp") != contract.get("holdout", {}).get("min_timestamp"):
            errors.append("temporal holdout contract min_timestamp mismatch")
    if replay is not None:
        if manifest.get("replay_hash") != content_hash(replay):
            errors.append("temporal holdout replay_hash mismatch")
        replay_records = _shadow_records(replay)
        if len(replay_records) != len(records):
            errors.append("temporal holdout replay record count mismatch")
        else:
            for index, (record, node) in enumerate(zip(replay_records, records)):
                if node.get("record_hash") != content_hash(record):
                    errors.append(f"temporal holdout replay record hash mismatch at sequence {index}")
                if str(record.get("id") or index + 1) != node.get("record_id"):
                    errors.append(f"temporal holdout replay record id mismatch at sequence {index}")
                if str(record.get("timestamp") or "") != node.get("timestamp"):
                    errors.append(f"temporal holdout replay record timestamp mismatch at sequence {index}")
    return TemporalHoldoutVerification(ok=not errors, errors=errors, warnings=warnings)


def append_temporal_holdout_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    replay: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_temporal_holdout_manifest(manifest, contract=contract, replay=replay, key=key)
    if not result.ok:
        raise ValueError("invalid temporal holdout manifest: " + "; ".join(result.errors))
    payload = {
        "manifest_id": manifest["manifest_id"],
        "manifest_hash": content_hash(manifest),
        "run_id": manifest.get("run_id"),
        "dataset_id": manifest.get("dataset_id"),
        "contract": manifest.get("contract"),
        "candidate_version": manifest.get("candidate_version"),
        "record_count": manifest.get("record_count"),
        "records_root": manifest.get("records_root"),
        "first_record_timestamp": manifest.get("first_record_timestamp"),
        "last_record_timestamp": manifest.get("last_record_timestamp"),
        "earliest_record_timestamp": manifest.get("earliest_record_timestamp"),
        "latest_record_timestamp": manifest.get("latest_record_timestamp"),
        "violation_count": len(manifest.get("violations", [])),
        "passed": manifest.get("passed"),
    }
    return chain.append(TEMPORAL_HOLDOUT_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("generated_at"))


def evaluate_shadow_replay(contract: dict[str, Any], replay: dict[str, Any]) -> dict[str, Any]:
    records = _shadow_records(replay)

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
    records = _shadow_records(replay)
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
    holdout_manifest = build_temporal_holdout_manifest(
        contract,
        replay,
        generated_at=evaluation["evaluated_at"],
        key=key,
    )
    payload = {
        **evaluation,
        "replay_hash": content_hash(replay),
        "temporal_holdout_manifest": holdout_manifest,
        "temporal_holdout": {
            "manifest_id": holdout_manifest["manifest_id"],
            "manifest_hash": content_hash(holdout_manifest),
            "records_root": holdout_manifest["records_root"],
            "record_count": holdout_manifest["record_count"],
            "passed": holdout_manifest["passed"],
        },
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


def verify_soak_report_payload(payload: dict[str, Any], contract: dict[str, Any]) -> SoakReportVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(payload, dict):
        return SoakReportVerification(ok=False, errors=["soak report payload missing"], warnings=[])

    soak = payload.get("soak")
    if not isinstance(soak, dict):
        errors.append("soak report source soak window missing")
        soak = {}
    elif payload.get("soak_hash") != content_hash(soak):
        errors.append("soak report soak_hash mismatch")

    if not soak.get("evaluated_at"):
        errors.append("soak report source evaluated_at missing")
    else:
        try:
            parse_rfc3339(str(soak.get("evaluated_at")))
        except ValueError as exc:
            errors.append(f"soak report evaluated_at invalid: {exc}")

    windows = soak.get("windows")
    if not isinstance(windows, list) or not windows:
        errors.append("soak report requires a non-empty windows list")
        windows = []
    for index, window in enumerate(windows):
        if not isinstance(window, dict):
            errors.append(f"soak report window {index + 1} must be an object")
            continue
        for field in ("started_at", "ended_at"):
            if not window.get(field):
                errors.append(f"soak report window {index + 1} missing {field}")
        try:
            started = parse_rfc3339(str(window.get("started_at") or ""))
            ended = parse_rfc3339(str(window.get("ended_at") or ""))
            if ended <= started:
                errors.append(f"soak report window {index + 1} ended_at must be after started_at")
        except ValueError as exc:
            errors.append(f"soak report window {index + 1} timestamp invalid: {exc}")
        metrics = window.get("metrics")
        if not isinstance(metrics, dict):
            errors.append(f"soak report window {index + 1} metrics missing")

    if errors:
        return SoakReportVerification(ok=False, errors=errors, warnings=warnings)

    try:
        expected = evaluate_soak_window(contract, soak)
    except (KeyError, TypeError, ValueError) as exc:
        return SoakReportVerification(ok=False, errors=[f"soak report cannot be replayed: {exc}"], warnings=warnings)

    for field in (
        "report_id",
        "contract_id",
        "contract_hash",
        "evaluated_at",
        "window_count",
        "checks",
        "incidents",
        "drift_alarms",
        "passed",
        "outcome",
    ):
        if payload.get(field) != expected.get(field):
            errors.append(f"soak report {field} mismatch")

    if any(not check.get("passed") for check in expected.get("checks", [])):
        warnings.append("soak report contains failed metric checks")
    if expected.get("outcome") != "passed":
        warnings.append("soak report outcome is failed")
    return SoakReportVerification(ok=not errors, errors=errors, warnings=warnings)

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


def _shadow_records(replay: dict[str, Any]) -> list[Any]:
    records = replay.get("records") or replay.get("traffic") or []
    if not isinstance(records, list) or not records:
        raise ValueError("shadow replay requires a non-empty records list")
    return records


def _temporal_holdout_violations(
    record_nodes: list[dict[str, Any]],
    freeze_at: str,
    min_timestamp: str,
) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for node in record_nodes:
        parsed_timestamp = parse_rfc3339(node["timestamp"])
        violations.extend(_record_temporal_violations(node, parsed_timestamp, freeze_at, min_timestamp))
        if node.get("chronological_after_previous") is False:
            violations.append(
                {
                    "sequence": node["sequence"],
                    "record_id": node["record_id"],
                    "timestamp": node["timestamp"],
                    "violation": "record timestamp is earlier than previous replay record",
                }
            )
    return violations


def _record_temporal_violations(
    node: dict[str, Any],
    parsed_timestamp: Any,
    freeze_at: str,
    min_timestamp: str,
) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    if freeze_at and parsed_timestamp <= parse_rfc3339(freeze_at):
        violations.append(
            {
                "sequence": node["sequence"],
                "record_id": node["record_id"],
                "timestamp": node["timestamp"],
                "violation": "record is not post-freeze",
            }
        )
    if min_timestamp and parsed_timestamp < parse_rfc3339(min_timestamp):
        violations.append(
            {
                "sequence": node["sequence"],
                "record_id": node["record_id"],
                "timestamp": node["timestamp"],
                "violation": "record is before holdout minimum",
            }
        )
    return violations
