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
TRAFFIC_HOLDOUT_EXPORT_SCHEMA = "trustai.traffic-holdout-export/0.1"
TRAFFIC_HOLDOUT_EXPORT_RECORD_SCHEMA = "trustai.traffic-holdout-export-record/0.1"
TRAFFIC_HOLDOUT_EXPORT_ENTRY_TYPE = "traffic_holdout.export_attested"
TRAFFIC_COMPLETENESS_SCHEMA = "trustai.traffic-completeness-receipt/0.1"
TRAFFIC_COMPLETENESS_ENTRY_TYPE = "traffic_holdout.completeness_attested"
TRAFFIC_COMPLETENESS_MODES = {"local-export", "provider-export", "production-export"}


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


@dataclass
class TrafficHoldoutExportVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class TrafficCompletenessVerification:
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


def load_traffic_holdout_export(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("traffic holdout export receipt must contain an object")
    return value


def write_traffic_holdout_export(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def load_traffic_completeness_provider_export(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("traffic completeness provider export must contain an object")
    return value


def load_traffic_completeness_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("traffic completeness receipt must contain an object")
    return value


def write_traffic_completeness_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

def build_traffic_holdout_export(
    contract: dict[str, Any],
    replay: dict[str, Any],
    *,
    export_ref: str,
    source_ref: str,
    exporter_ref: str,
    window_start: str,
    window_end: str,
    query_ref: str | None = None,
    cursor_start: str | None = None,
    cursor_end: str | None = None,
    produced_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    export_ref = _require_text(export_ref, "export_ref")
    source_ref = _require_text(source_ref, "source_ref")
    exporter_ref = _require_text(exporter_ref, "exporter_ref")
    parse_rfc3339(window_start)
    parse_rfc3339(window_end)
    if parse_rfc3339(window_end) <= parse_rfc3339(window_start):
        raise ValueError("traffic holdout export window_end must be after window_start")
    produced = produced_at or replay.get("evaluated_at") or utc_now()
    parse_rfc3339(str(produced))

    records = _build_traffic_holdout_export_records(
        replay,
        freeze_at=contract["freeze"]["frozen_at"],
        min_timestamp=contract["holdout"]["min_timestamp"],
        window_start=window_start,
        window_end=window_end,
    )
    timestamps = [record["timestamp"] for record in records]
    violations = _traffic_holdout_export_violations(records)
    body = {
        "schema": TRAFFIC_HOLDOUT_EXPORT_SCHEMA,
        "produced_at": str(produced),
        "export_ref": export_ref,
        "source_ref": source_ref,
        "exporter_ref": exporter_ref,
        "query_ref": query_ref,
        "cursor_start": cursor_start,
        "cursor_end": cursor_end,
        "extraction_window": {
            "started_at": window_start,
            "ended_at": window_end,
        },
        "contract": {
            "id": contract["id"],
            "hash": contract_hash(contract),
            "freeze_at": contract["freeze"]["frozen_at"],
            "min_timestamp": contract["holdout"]["min_timestamp"],
        },
        "replay": {
            "run_id": replay.get("run_id"),
            "dataset_id": replay.get("dataset_id") or "shadow-replay",
            "candidate_version": replay.get("candidate_version") or contract["agent"]["version"],
            "hash": content_hash(replay),
        },
        "record_count": len(records),
        "records_root": records[-1]["export_record_hash"],
        "first_record_timestamp": timestamps[0],
        "last_record_timestamp": timestamps[-1],
        "earliest_record_timestamp": min(timestamps),
        "latest_record_timestamp": max(timestamps),
        "records": records,
        "violations": violations,
        "passed": not violations,
        "privacy": {
            "raw_payloads_embedded": False,
            "record_material": "canonical record hashes only",
            "sensitive_data_limit": "receipt excludes full production traffic payloads; replay source must be supplied separately for offline replay",
        },
        "limitations": [
            "This receipt binds the supplied production traffic export window, source refs, and replay record hashes to the registered freeze and holdout boundary.",
            "It does not prove upstream production traffic completeness without provider-owned collector, stream, storage, or immutable audit-log exports.",
        ],
    }
    export_id = content_hash(body)
    return {
        **body,
        "export_id": export_id,
        "signatures": [sign_value({"export_id": export_id, "traffic_holdout_export": body}, key)],
    }


def verify_traffic_holdout_export(
    receipt: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    replay: dict[str, Any] | None = None,
    key: str | None = None,
) -> TrafficHoldoutExportVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if receipt.get("schema") != TRAFFIC_HOLDOUT_EXPORT_SCHEMA:
        errors.append(f"unsupported traffic holdout export schema: {receipt.get('schema')}")

    body = without_keys(receipt, "export_id", "signatures")
    if receipt.get("export_id") != content_hash(body):
        errors.append("export_id does not match canonical traffic holdout export body")
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("traffic holdout export must include at least one signature")
    else:
        signed_value = {"export_id": receipt.get("export_id"), "traffic_holdout_export": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("traffic holdout export signature verification failed")

    try:
        parse_rfc3339(str(receipt.get("produced_at") or ""))
    except ValueError as exc:
        errors.append(f"traffic holdout export produced_at invalid: {exc}")

    extraction_window = receipt.get("extraction_window")
    if not isinstance(extraction_window, dict):
        errors.append("traffic holdout export extraction_window must be an object")
        extraction_window = {}
    window_start = str(extraction_window.get("started_at") or "")
    window_end = str(extraction_window.get("ended_at") or "")
    try:
        if parse_rfc3339(window_end) <= parse_rfc3339(window_start):
            errors.append("traffic holdout export window_end must be after window_start")
    except ValueError as exc:
        errors.append(f"traffic holdout export window invalid: {exc}")

    receipt_contract = receipt.get("contract")
    if not isinstance(receipt_contract, dict):
        errors.append("traffic holdout export contract must be an object")
        receipt_contract = {}
    freeze_at = str(receipt_contract.get("freeze_at") or "")
    min_timestamp = str(receipt_contract.get("min_timestamp") or "")
    try:
        parse_rfc3339(freeze_at)
        parse_rfc3339(min_timestamp)
    except ValueError as exc:
        errors.append(f"traffic holdout export boundary invalid: {exc}")

    records = receipt.get("records")
    if not isinstance(records, list) or not records:
        errors.append("traffic holdout export requires records")
        records = []
    if receipt.get("record_count") != len(records):
        errors.append("traffic holdout export record_count does not match records")

    previous_export_record_hash: str | None = None
    previous_timestamp: str | None = None
    expected_violations: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"traffic holdout export record {index + 1} must be an object")
            continue
        record_body = {
            "schema": record.get("schema"),
            "sequence": record.get("sequence"),
            "record_count": record.get("record_count"),
            "record_id": record.get("record_id"),
            "timestamp": record.get("timestamp"),
            "record_hash": record.get("record_hash"),
            "previous_export_record_hash": record.get("previous_export_record_hash"),
        }
        if record.get("schema") != TRAFFIC_HOLDOUT_EXPORT_RECORD_SCHEMA:
            errors.append(f"traffic holdout export record {index + 1} has unsupported schema")
        if record.get("sequence") != index:
            errors.append(f"traffic holdout export record {index + 1} sequence mismatch")
        if record.get("record_count") != len(records):
            errors.append(f"traffic holdout export record {index + 1} record_count mismatch")
        if record.get("previous_export_record_hash") != previous_export_record_hash:
            errors.append(f"traffic holdout export record {index + 1} previous hash mismatch")
        if record.get("export_record_hash") != content_hash(record_body):
            errors.append(f"traffic holdout export record {index + 1} hash mismatch")
        try:
            parsed_timestamp = parse_rfc3339(str(record.get("timestamp") or ""))
            expected_post_freeze = parsed_timestamp > parse_rfc3339(freeze_at)
            expected_post_minimum = parsed_timestamp >= parse_rfc3339(min_timestamp)
            expected_in_window = parse_rfc3339(window_start) <= parsed_timestamp <= parse_rfc3339(window_end)
            expected_chronological = previous_timestamp is None or parsed_timestamp >= parse_rfc3339(previous_timestamp)
            if record.get("post_freeze") is not expected_post_freeze:
                errors.append(f"traffic holdout export record {index + 1} post_freeze mismatch")
            if record.get("post_holdout_minimum") is not expected_post_minimum:
                errors.append(f"traffic holdout export record {index + 1} post_holdout_minimum mismatch")
            if record.get("within_export_window") is not expected_in_window:
                errors.append(f"traffic holdout export record {index + 1} within_export_window mismatch")
            if record.get("chronological_after_previous") is not expected_chronological:
                errors.append(f"traffic holdout export record {index + 1} chronological_after_previous mismatch")
            expected_violations.extend(_traffic_holdout_export_record_violations(record))
            previous_timestamp = str(record.get("timestamp"))
        except ValueError as exc:
            errors.append(f"traffic holdout export record {index + 1} timestamp invalid: {exc}")
        previous_export_record_hash = record.get("export_record_hash")

    if records:
        if receipt.get("records_root") != records[-1].get("export_record_hash"):
            errors.append("traffic holdout export records_root mismatch")
        timestamps = [str(record.get("timestamp")) for record in records if isinstance(record, dict) and record.get("timestamp")]
        if timestamps:
            if receipt.get("first_record_timestamp") != timestamps[0]:
                errors.append("traffic holdout export first_record_timestamp mismatch")
            if receipt.get("last_record_timestamp") != timestamps[-1]:
                errors.append("traffic holdout export last_record_timestamp mismatch")
            if receipt.get("earliest_record_timestamp") != min(timestamps):
                errors.append("traffic holdout export earliest_record_timestamp mismatch")
            if receipt.get("latest_record_timestamp") != max(timestamps):
                errors.append("traffic holdout export latest_record_timestamp mismatch")

    if receipt.get("violations") != expected_violations:
        errors.append("traffic holdout export violations do not match record checks")
    if receipt.get("passed") is not (not expected_violations):
        errors.append("traffic holdout export passed flag does not match violations")
    if expected_violations:
        warnings.append("traffic holdout export contains boundary or ordering violations")

    if receipt.get("privacy", {}).get("raw_payloads_embedded") is not False:
        errors.append("traffic holdout export must not embed raw production traffic payloads")

    if contract is not None:
        if receipt_contract.get("id") != contract.get("id"):
            errors.append("traffic holdout export contract id mismatch")
        if receipt_contract.get("hash") != contract_hash(contract):
            errors.append("traffic holdout export contract hash mismatch")
        if receipt_contract.get("freeze_at") != contract.get("freeze", {}).get("frozen_at"):
            errors.append("traffic holdout export contract freeze_at mismatch")
        if receipt_contract.get("min_timestamp") != contract.get("holdout", {}).get("min_timestamp"):
            errors.append("traffic holdout export contract min_timestamp mismatch")
    if replay is not None:
        replay_ref = receipt.get("replay", {})
        if not isinstance(replay_ref, dict):
            errors.append("traffic holdout export replay must be an object")
            replay_ref = {}
        if replay_ref.get("hash") != content_hash(replay):
            errors.append("traffic holdout export replay hash mismatch")
        replay_records = _shadow_records(replay)
        if len(replay_records) != len(records):
            errors.append("traffic holdout export replay record count mismatch")
        else:
            for index, (source_record, record) in enumerate(zip(replay_records, records)):
                if record.get("record_hash") != content_hash(source_record):
                    errors.append(f"traffic holdout export replay record hash mismatch at sequence {index}")
                if record.get("record_id") != str(source_record.get("id") or index + 1):
                    errors.append(f"traffic holdout export replay record id mismatch at sequence {index}")
                if record.get("timestamp") != str(source_record.get("timestamp") or ""):
                    errors.append(f"traffic holdout export replay record timestamp mismatch at sequence {index}")
    return TrafficHoldoutExportVerification(ok=not errors, errors=errors, warnings=warnings)


def append_traffic_holdout_export(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    replay: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_traffic_holdout_export(receipt, contract=contract, replay=replay, key=key)
    if not result.ok:
        raise ValueError("invalid traffic holdout export: " + "; ".join(result.errors))
    payload = {
        "export_id": receipt["export_id"],
        "export_hash": content_hash(receipt),
        "export_ref": receipt.get("export_ref"),
        "source_ref": receipt.get("source_ref"),
        "exporter_ref": receipt.get("exporter_ref"),
        "query_ref": receipt.get("query_ref"),
        "cursor_start": receipt.get("cursor_start"),
        "cursor_end": receipt.get("cursor_end"),
        "extraction_window": receipt.get("extraction_window"),
        "contract": receipt.get("contract"),
        "replay": receipt.get("replay"),
        "record_count": receipt.get("record_count"),
        "records_root": receipt.get("records_root"),
        "earliest_record_timestamp": receipt.get("earliest_record_timestamp"),
        "latest_record_timestamp": receipt.get("latest_record_timestamp"),
        "violation_count": len(receipt.get("violations", [])),
        "passed": receipt.get("passed"),
        "privacy": receipt.get("privacy"),
    }
    return chain.append(TRAFFIC_HOLDOUT_EXPORT_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("produced_at"))


def build_traffic_completeness_receipt(
    traffic_export: dict[str, Any],
    provider_export: dict[str, Any],
    *,
    mode: str = "provider-export",
    authority_ref: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    actor_ref: str,
    produced_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in TRAFFIC_COMPLETENESS_MODES:
        raise ValueError(f"mode must be one of {sorted(TRAFFIC_COMPLETENESS_MODES)}")
    traffic_result = verify_traffic_holdout_export(traffic_export, key=key)
    if not traffic_result.ok:
        raise ValueError("invalid traffic holdout export source: " + "; ".join(traffic_result.errors))
    for value, field in (
        (authority_ref, "authority_ref"),
        (endpoint_url, "endpoint_url"),
        (request_hash, "request_hash"),
        (response_hash, "response_hash"),
        (actor_ref, "actor_ref"),
    ):
        _require_text(value, field)
    if not isinstance(response_status, int):
        raise ValueError("traffic completeness response_status must be an integer")
    produced = produced_at or utc_now()
    parse_rfc3339(str(produced))
    body = _build_traffic_completeness_body(
        traffic_export,
        provider_export,
        mode=mode,
        authority_ref=authority_ref,
        endpoint_url=endpoint_url,
        request_hash=request_hash,
        response_status=response_status,
        response_hash=response_hash,
        actor_ref=actor_ref,
        produced_at=str(produced),
    )
    completeness_id = content_hash(body)
    return {
        **body,
        "completeness_id": completeness_id,
        "signatures": [sign_value({"completeness_id": completeness_id, "traffic_completeness": body}, key)],
    }


def verify_traffic_completeness_receipt(
    receipt: dict[str, Any],
    *,
    traffic_export: dict[str, Any] | None = None,
    provider_export: dict[str, Any] | None = None,
    key: str | None = None,
) -> TrafficCompletenessVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if receipt.get("schema") != TRAFFIC_COMPLETENESS_SCHEMA:
        errors.append(f"unsupported traffic completeness schema: {receipt.get('schema')}")
    body = without_keys(receipt, "completeness_id", "signatures")
    if receipt.get("completeness_id") != content_hash(body):
        errors.append("completeness_id does not match canonical traffic completeness body")
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("traffic completeness receipt must include at least one signature")
    else:
        signed_value = {"completeness_id": receipt.get("completeness_id"), "traffic_completeness": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("traffic completeness signature verification failed")

    if receipt.get("mode") not in TRAFFIC_COMPLETENESS_MODES:
        errors.append("traffic completeness mode is unsupported")
    elif receipt.get("mode") != "production-export":
        warnings.append(f"traffic completeness mode is {receipt.get('mode')}; live provider-owned completeness is not claimed")
    try:
        parse_rfc3339(str(receipt.get("produced_at") or ""))
    except ValueError as exc:
        errors.append(f"traffic completeness produced_at invalid: {exc}")

    provider_exchange = receipt.get("provider_exchange")
    if not isinstance(provider_exchange, dict):
        errors.append("traffic completeness provider_exchange must be an object")
        provider_exchange = {}
    else:
        for field in ("endpoint_url", "request_hash", "response_status", "response_hash", "actor_ref"):
            if provider_exchange.get(field) in (None, ""):
                errors.append(f"traffic completeness provider_exchange.{field} is required")
        if provider_exchange.get("success") is not (isinstance(provider_exchange.get("response_status"), int) and 200 <= provider_exchange.get("response_status") < 300):
            errors.append("traffic completeness provider_exchange success flag mismatch")

    coverage = receipt.get("source_completeness")
    if not isinstance(coverage, dict):
        errors.append("traffic completeness source_completeness must be an object")
        coverage = {}
    expected_violations = _traffic_completeness_violations_from_coverage(coverage, provider_exchange)
    if receipt.get("violations") != expected_violations:
        errors.append("traffic completeness violations do not match source completeness checks")
    if receipt.get("passed") is not (not expected_violations):
        errors.append("traffic completeness passed flag does not match violations")
    if expected_violations:
        warnings.append("traffic completeness receipt contains provider coverage violations")

    if receipt.get("privacy", {}).get("raw_payloads_embedded") is not False:
        errors.append("traffic completeness receipt must not embed raw production traffic payloads")

    if traffic_export is not None:
        traffic_result = verify_traffic_holdout_export(traffic_export, key=key)
        if not traffic_result.ok:
            errors.append("traffic completeness source traffic export failed verification: " + "; ".join(traffic_result.errors))
        expected_traffic = _traffic_export_summary(traffic_export)
        if receipt.get("traffic_export") != expected_traffic:
            errors.append("traffic completeness traffic_export binding mismatch")
    else:
        warnings.append("traffic completeness traffic export source was not supplied; source receipt hash was not replayed")

    if provider_export is not None:
        try:
            expected_provider = _traffic_provider_export_summary(provider_export)
        except ValueError as exc:
            errors.append(f"traffic completeness provider export invalid: {exc}")
            expected_provider = None
        if expected_provider is not None and receipt.get("provider_export") != expected_provider:
            errors.append("traffic completeness provider_export binding mismatch")
    else:
        warnings.append("traffic completeness provider export source was not supplied; provider records were not replayed")

    if traffic_export is not None and provider_export is not None:
        try:
            expected_body = _build_traffic_completeness_body(
                traffic_export,
                provider_export,
                mode=str(receipt.get("mode") or ""),
                authority_ref=str(receipt.get("authority_ref") or ""),
                endpoint_url=str(provider_exchange.get("endpoint_url") or ""),
                request_hash=str(provider_exchange.get("request_hash") or ""),
                response_status=int(provider_exchange.get("response_status")),
                response_hash=str(provider_exchange.get("response_hash") or ""),
                actor_ref=str(provider_exchange.get("actor_ref") or ""),
                produced_at=str(receipt.get("produced_at") or ""),
            )
        except (TypeError, ValueError) as exc:
            errors.append(f"traffic completeness source replay failed: {exc}")
        else:
            for field in (
                "traffic_export",
                "provider_export",
                "source_completeness",
                "matched_records",
                "extra_provider_records",
                "matched_audit_records",
                "controls",
                "violations",
                "passed",
            ):
                if receipt.get(field) != expected_body.get(field):
                    errors.append(f"traffic completeness {field} mismatch")
    return TrafficCompletenessVerification(ok=not errors, errors=errors, warnings=warnings)


def append_traffic_completeness_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    traffic_export: dict[str, Any] | None = None,
    provider_export: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_traffic_completeness_receipt(receipt, traffic_export=traffic_export, provider_export=provider_export, key=key)
    if not result.ok:
        raise ValueError("invalid traffic completeness receipt: " + "; ".join(result.errors))
    payload = {
        "completeness_id": receipt["completeness_id"],
        "completeness_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "authority_ref": receipt.get("authority_ref"),
        "traffic_export": receipt.get("traffic_export"),
        "provider_export": receipt.get("provider_export"),
        "source_completeness": receipt.get("source_completeness"),
        "provider_exchange": receipt.get("provider_exchange"),
        "violation_count": len(receipt.get("violations", [])),
        "passed": receipt.get("passed"),
        "privacy": receipt.get("privacy"),
    }
    return chain.append(TRAFFIC_COMPLETENESS_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("produced_at"))

def _build_traffic_holdout_export_records(
    replay: dict[str, Any],
    *,
    freeze_at: str,
    min_timestamp: str,
    window_start: str,
    window_end: str,
) -> list[dict[str, Any]]:
    records = _shadow_records(replay)
    export_records: list[dict[str, Any]] = []
    previous_export_record_hash: str | None = None
    previous_timestamp: str | None = None
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"traffic holdout export record {index + 1} is not an object")
        timestamp = str(record.get("timestamp") or "")
        if not timestamp:
            raise ValueError(f"traffic holdout export record {index + 1} missing timestamp")
        parsed_timestamp = parse_rfc3339(timestamp)
        record_id = str(record.get("id") or index + 1)
        record_body = {
            "schema": TRAFFIC_HOLDOUT_EXPORT_RECORD_SCHEMA,
            "sequence": index,
            "record_count": len(records),
            "record_id": record_id,
            "timestamp": timestamp,
            "record_hash": content_hash(record),
            "previous_export_record_hash": previous_export_record_hash,
        }
        export_record_hash = content_hash(record_body)
        export_records.append(
            {
                **record_body,
                "post_freeze": parsed_timestamp > parse_rfc3339(freeze_at),
                "post_holdout_minimum": parsed_timestamp >= parse_rfc3339(min_timestamp),
                "within_export_window": parse_rfc3339(window_start) <= parsed_timestamp <= parse_rfc3339(window_end),
                "chronological_after_previous": previous_timestamp is None
                or parsed_timestamp >= parse_rfc3339(previous_timestamp),
                "export_record_hash": export_record_hash,
            }
        )
        previous_export_record_hash = export_record_hash
        previous_timestamp = timestamp
    return export_records


def _traffic_holdout_export_violations(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for record in records:
        violations.extend(_traffic_holdout_export_record_violations(record))
    return violations


def _traffic_holdout_export_record_violations(record: dict[str, Any]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    checks = (
        ("post_freeze", "record is not post-freeze"),
        ("post_holdout_minimum", "record is before holdout minimum"),
        ("within_export_window", "record is outside production traffic export window"),
        ("chronological_after_previous", "record timestamp is earlier than previous export record"),
    )
    for field, message in checks:
        if record.get(field) is False:
            violations.append(
                {
                    "sequence": record.get("sequence"),
                    "record_id": record.get("record_id"),
                    "timestamp": record.get("timestamp"),
                    "violation": message,
                }
            )
    return violations


def _build_traffic_completeness_body(
    traffic_export: dict[str, Any],
    provider_export: dict[str, Any],
    *,
    mode: str,
    authority_ref: str,
    endpoint_url: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    actor_ref: str,
    produced_at: str,
) -> dict[str, Any]:
    traffic_summary = _traffic_export_summary(traffic_export)
    provider_summary = _traffic_provider_export_summary(provider_export)
    stream_records = _traffic_provider_records(provider_export, "stream_records")
    audit_records = _traffic_provider_records(provider_export, "audit_records")
    matched_records, extra_provider_records = _traffic_completeness_record_matches(traffic_export, stream_records)
    matched_audit_records = _traffic_completeness_audit_matches(traffic_export, audit_records)
    export_window = traffic_export.get("extraction_window", {}) if isinstance(traffic_export.get("extraction_window"), dict) else {}
    provider_window_start = provider_summary.get("window_start")
    provider_window_end = provider_summary.get("window_end")
    traffic_window_start = export_window.get("started_at")
    traffic_window_end = export_window.get("ended_at")
    window_covers = False
    if provider_window_start and provider_window_end and traffic_window_start and traffic_window_end:
        window_covers = parse_rfc3339(str(provider_window_start)) <= parse_rfc3339(str(traffic_window_start)) and parse_rfc3339(str(provider_window_end)) >= parse_rfc3339(str(traffic_window_end))
    cursor_start = traffic_export.get("cursor_start")
    cursor_end = traffic_export.get("cursor_end")
    provider_cursor_start = provider_summary.get("cursor_start")
    provider_cursor_end = provider_summary.get("cursor_end")
    cursor_bounds_match = True
    if cursor_start and provider_cursor_start:
        cursor_bounds_match = cursor_bounds_match and cursor_start == provider_cursor_start
    if cursor_end and provider_cursor_end:
        cursor_bounds_match = cursor_bounds_match and cursor_end == provider_cursor_end
    source_ref_match = provider_summary.get("source_ref") == traffic_export.get("source_ref")
    traffic_record_count = int(traffic_export.get("record_count") or 0)
    provider_stream_count = int(provider_summary.get("stream_record_count") or 0)
    provider_declared_count = provider_summary.get("traffic_record_count")
    record_count_matches = provider_stream_count == traffic_record_count and (provider_declared_count in (None, traffic_record_count))
    provider_root = provider_summary.get("traffic_records_root")
    records_root_matches = provider_root == traffic_export.get("records_root")
    missing_count = sum(1 for record in matched_records if not record.get("matched"))
    extra_count = len(extra_provider_records)
    coverage = {
        "source_ref_match": source_ref_match,
        "record_count_matches": record_count_matches,
        "records_root_matches": records_root_matches,
        "window_covers_export": window_covers,
        "cursor_bounds_match": cursor_bounds_match,
        "audit_records_bound": bool(matched_audit_records),
        "traffic_record_count": traffic_record_count,
        "provider_stream_record_count": provider_stream_count,
        "provider_declared_traffic_record_count": provider_declared_count,
        "matched_record_count": len(matched_records) - missing_count,
        "missing_record_count": missing_count,
        "extra_provider_record_count": extra_count,
    }
    provider_exchange = {
        "endpoint_url": endpoint_url,
        "request_hash": request_hash,
        "response_status": response_status,
        "response_hash": response_hash,
        "success": 200 <= response_status < 300,
        "actor_ref": actor_ref,
    }
    violations = _traffic_completeness_violations_from_coverage(coverage, provider_exchange)
    return {
        "schema": TRAFFIC_COMPLETENESS_SCHEMA,
        "mode": mode,
        "produced_at": produced_at,
        "authority_ref": authority_ref,
        "traffic_export": traffic_summary,
        "provider_export": provider_summary,
        "source_completeness": coverage,
        "matched_records": matched_records,
        "extra_provider_records": extra_provider_records,
        "matched_audit_records": matched_audit_records,
        "provider_exchange": provider_exchange,
        "controls": _traffic_completeness_controls(coverage, provider_exchange, mode),
        "violations": violations,
        "passed": not violations,
        "privacy": {
            "raw_payloads_embedded": False,
            "record_material": "traffic export hashes, provider stream cursors, provider export hashes, and audit roots only",
            "sensitive_data_limit": "receipt excludes raw production traffic payloads and provider credentials",
        },
        "limitations": [
            "This receipt binds a signed traffic holdout export to a supplied collector/provider export, stream record roots, cursor bounds, and audit records for the replay window.",
            "It proves completeness only for the supplied provider export. Production completeness still depends on the provider export being provider-owned, immutable, and independently retained.",
        ],
    }


def _traffic_export_summary(traffic_export: dict[str, Any]) -> dict[str, Any]:
    return {
        "export_id": traffic_export.get("export_id"),
        "export_hash": content_hash(traffic_export),
        "export_ref": traffic_export.get("export_ref"),
        "source_ref": traffic_export.get("source_ref"),
        "exporter_ref": traffic_export.get("exporter_ref"),
        "query_ref": traffic_export.get("query_ref"),
        "cursor_start": traffic_export.get("cursor_start"),
        "cursor_end": traffic_export.get("cursor_end"),
        "extraction_window": traffic_export.get("extraction_window"),
        "contract": traffic_export.get("contract"),
        "replay": traffic_export.get("replay"),
        "record_count": traffic_export.get("record_count"),
        "records_root": traffic_export.get("records_root"),
        "earliest_record_timestamp": traffic_export.get("earliest_record_timestamp"),
        "latest_record_timestamp": traffic_export.get("latest_record_timestamp"),
        "passed": traffic_export.get("passed"),
    }


def _traffic_provider_export_summary(provider_export: dict[str, Any]) -> dict[str, Any]:
    stream_records = _traffic_provider_records(provider_export, "stream_records")
    audit_records = _traffic_provider_records(provider_export, "audit_records")
    window_start = provider_export.get("window_start") or _nested(provider_export, "extraction_window", "started_at")
    window_end = provider_export.get("window_end") or _nested(provider_export, "extraction_window", "ended_at")
    if window_start:
        parse_rfc3339(str(window_start))
    if window_end:
        parse_rfc3339(str(window_end))
    return {
        "export_ref": provider_export.get("export_ref"),
        "schema": provider_export.get("schema"),
        "provider": provider_export.get("provider"),
        "environment": provider_export.get("environment"),
        "source_ref": provider_export.get("source_ref") or provider_export.get("collector_ref") or provider_export.get("stream_ref"),
        "collector_ref": provider_export.get("collector_ref"),
        "stream_ref": provider_export.get("stream_ref"),
        "topic": provider_export.get("topic"),
        "window_start": window_start,
        "window_end": window_end,
        "cursor_start": provider_export.get("cursor_start"),
        "cursor_end": provider_export.get("cursor_end"),
        "traffic_records_root": provider_export.get("traffic_records_root"),
        "traffic_record_count": provider_export.get("traffic_record_count"),
        "audit_log_ref": provider_export.get("audit_log_ref"),
        "audit_log_root": provider_export.get("audit_log_root"),
        "hash": content_hash(provider_export),
        "stream_record_count": len(stream_records),
        "stream_record_root": content_hash([_traffic_provider_stream_record_summary(record) for record in stream_records]),
        "audit_record_count": len(audit_records),
        "audit_record_root": content_hash([_traffic_provider_audit_record_summary(record) for record in audit_records]),
    }


def _traffic_provider_records(provider_export: dict[str, Any], field: str) -> list[dict[str, Any]]:
    value = provider_export.get(field, [])
    if not isinstance(value, list):
        raise ValueError(f"traffic completeness provider export {field} must be a list")
    records: list[dict[str, Any]] = []
    for index, record in enumerate(value):
        if not isinstance(record, dict):
            raise ValueError(f"traffic completeness provider export {field}[{index}] must be an object")
        records.append(record)
    return records


def _traffic_provider_stream_record_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": record.get("record_id") or record.get("id"),
        "timestamp": record.get("timestamp"),
        "record_hash": record.get("record_hash"),
        "export_record_hash": record.get("export_record_hash"),
        "previous_export_record_hash": record.get("previous_export_record_hash"),
        "cursor_ref": record.get("cursor_ref"),
        "partition": record.get("partition"),
        "offset": record.get("offset"),
        "source_ref": record.get("source_ref"),
        "provider_record_hash": content_hash(record),
    }


def _traffic_provider_audit_record_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_type": record.get("event_type") or record.get("type"),
        "export_ref": record.get("export_ref"),
        "traffic_export_id": record.get("traffic_export_id"),
        "records_root": record.get("records_root") or record.get("traffic_records_root"),
        "record_count": record.get("record_count") or record.get("traffic_record_count"),
        "window_start": record.get("window_start"),
        "window_end": record.get("window_end"),
        "cursor_start": record.get("cursor_start"),
        "cursor_end": record.get("cursor_end"),
        "actor_ref": record.get("actor_ref"),
        "timestamp": record.get("timestamp"),
        "audit_record_hash": content_hash(record),
    }


def _traffic_completeness_record_matches(
    traffic_export: dict[str, Any],
    stream_records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_export_hash = {record.get("export_record_hash"): record for record in stream_records if record.get("export_record_hash")}
    by_record_key = {_traffic_provider_record_key(record): record for record in stream_records}
    used_hashes: set[str] = set()
    matched: list[dict[str, Any]] = []
    for traffic_record in traffic_export.get("records", []):
        if not isinstance(traffic_record, dict):
            continue
        provider_record = by_export_hash.get(traffic_record.get("export_record_hash")) or by_record_key.get(_traffic_export_record_key(traffic_record))
        if provider_record is not None:
            used_hashes.add(content_hash(provider_record))
        matched.append(
            {
                "sequence": traffic_record.get("sequence"),
                "record_id": traffic_record.get("record_id"),
                "timestamp": traffic_record.get("timestamp"),
                "record_hash": traffic_record.get("record_hash"),
                "export_record_hash": traffic_record.get("export_record_hash"),
                "provider_record_hash": content_hash(provider_record) if provider_record is not None else None,
                "cursor_ref": provider_record.get("cursor_ref") if provider_record is not None else None,
                "partition": provider_record.get("partition") if provider_record is not None else None,
                "offset": provider_record.get("offset") if provider_record is not None else None,
                "matched": provider_record is not None,
            }
        )
    extra = []
    for record in stream_records:
        if content_hash(record) not in used_hashes:
            extra.append(_traffic_provider_stream_record_summary(record))
    return matched, extra


def _traffic_completeness_audit_matches(traffic_export: dict[str, Any], audit_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    export_ref = traffic_export.get("export_ref")
    export_id = traffic_export.get("export_id")
    records_root = traffic_export.get("records_root")
    record_count = traffic_export.get("record_count")
    for record in audit_records:
        summary = _traffic_provider_audit_record_summary(record)
        ref_match = summary.get("export_ref") == export_ref or summary.get("traffic_export_id") == export_id or summary.get("records_root") == records_root
        count_match = summary.get("record_count") in (None, record_count)
        if ref_match and count_match:
            matches.append(summary)
    return matches


def _traffic_completeness_violations_from_coverage(
    coverage: dict[str, Any],
    provider_exchange: dict[str, Any],
) -> list[dict[str, Any]]:
    checks = (
        ("source_ref_match", "provider source ref does not match traffic export source ref"),
        ("record_count_matches", "provider stream record count does not match traffic export record count"),
        ("records_root_matches", "provider traffic records root does not match traffic export records root"),
        ("window_covers_export", "provider export window does not cover traffic export extraction window"),
        ("cursor_bounds_match", "provider cursor bounds do not match traffic export cursor bounds"),
        ("audit_records_bound", "provider audit records do not bind the traffic export"),
    )
    violations: list[dict[str, Any]] = []
    for field, message in checks:
        if coverage.get(field) is not True:
            violations.append({"check": field, "violation": message})
    if coverage.get("missing_record_count", 0):
        violations.append({"check": "missing_provider_records", "violation": "traffic export records are missing from provider stream export", "count": coverage.get("missing_record_count")})
    if coverage.get("extra_provider_record_count", 0):
        violations.append({"check": "extra_provider_records", "violation": "provider stream export contains records not included in traffic export", "count": coverage.get("extra_provider_record_count")})
    if provider_exchange.get("success") is not True:
        violations.append({"check": "provider_exchange_success", "violation": "provider export API exchange was not successful"})
    return violations


def _traffic_completeness_controls(coverage: dict[str, Any], provider_exchange: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    return [
        {"id": "source-ref-bound", "status": "passed" if coverage.get("source_ref_match") else "failed", "description": "Provider source ref matches the traffic holdout export source ref."},
        {"id": "record-count-bound", "status": "passed" if coverage.get("record_count_matches") else "failed", "description": "Provider stream record count matches the traffic holdout export record count."},
        {"id": "records-root-bound", "status": "passed" if coverage.get("records_root_matches") else "failed", "description": "Provider traffic records root matches the traffic holdout export records root."},
        {"id": "all-records-provider-bound", "status": "passed" if not coverage.get("missing_record_count") else "failed", "description": "Every traffic export record appears in the provider stream export."},
        {"id": "no-extra-provider-records", "status": "passed" if not coverage.get("extra_provider_record_count") else "failed", "description": "The provider stream export does not contain unmatched records for the same window."},
        {"id": "window-and-cursors-bound", "status": "passed" if coverage.get("window_covers_export") and coverage.get("cursor_bounds_match") else "failed", "description": "Provider window and cursor bounds cover the traffic holdout export."},
        {"id": "provider-audit-bound", "status": "passed" if coverage.get("audit_records_bound") else "failed", "description": "Provider audit records bind the traffic holdout export root or ID."},
        {"id": "provider-exchange-success", "status": "passed" if provider_exchange.get("success") else "failed", "description": "Provider export API exchange returned a successful status."},
        {"id": "production-export-mode", "status": "passed" if mode == "production-export" else "deferred", "description": "Production completeness claims require provider-owned production export mode."},
    ]


def _traffic_export_record_key(record: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (record.get("record_id"), record.get("timestamp"), record.get("record_hash"))


def _traffic_provider_record_key(record: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (record.get("record_id") or record.get("id"), record.get("timestamp"), record.get("record_hash"))


def _nested(value: dict[str, Any], outer: str, inner: str) -> Any:
    child = value.get(outer)
    if isinstance(child, dict):
        return child.get(inner)
    return None

def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value

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
