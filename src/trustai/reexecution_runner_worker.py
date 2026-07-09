from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .reexecution_runner_service import verify_reexecution_runner_service_attestation

REEXECUTION_RUNNER_WORKER_SCHEMA = "trustai.reexecution-runner-worker/0.1"
REEXECUTION_RUNNER_WORKER_ENTRY_TYPE = "reexecution.runner_worker_recorded"
REEXECUTION_RUNNER_WORKER_MODES = {
    "local-reference",
    "scheduled-worker",
    "hosted-worker",
    "isolated-runner-worker",
    "production-design",
}
REEXECUTION_RUNNER_WORKER_OPERATION_KINDS = {
    "reexecution_run",
    "policy_report_compile",
    "artifact_publish",
    "result_reconcile",
    "isolation_audit_replay",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ReexecutionRunnerWorkerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_reexecution_runner_worker_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("re-execution runner worker receipt must contain an object")
    return value


def write_reexecution_runner_worker_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_reexecution_runner_worker_receipt(
    service_attestation: dict[str, Any],
    *,
    isolation_attestation: dict[str, Any] | None = None,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    mode: str = "hosted-worker",
    environment: str = "local",
    worker_ref: str,
    run_ref: str,
    operation_kind: str,
    actor_ref: str,
    schedule_ref: str,
    cadence_seconds: int,
    lease_ref: str,
    checkpoint_ref: str,
    checkpoint_hash: str | None = None,
    previous_cursor_ref: str | None = None,
    next_cursor_ref: str | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    queue_ref: str,
    queue_message_ref: str | None = None,
    dead_letter_queue_ref: str | None = None,
    job_ref: str,
    job_hash: str,
    artifact_manifest_ref: str,
    artifact_manifest_hash: str,
    result_bundle_ref: str,
    result_bundle_hash: str,
    isolation_audit_ref: str,
    isolation_audit_root: str,
    runtime_audit_ref: str | None = None,
    runtime_audit_root: str | None = None,
    request_hash: str | None = None,
    response_status: int | None = None,
    response_hash: str | None = None,
    metrics_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    credential_ref: str,
    retention_until: str,
    evidence_refs: list[str] | None = None,
    started_at: str,
    completed_at: str | None = None,
    next_run_at: str | None = None,
    error_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in REEXECUTION_RUNNER_WORKER_MODES:
        raise ValueError(f"mode must be one of {sorted(REEXECUTION_RUNNER_WORKER_MODES)}")
    if operation_kind not in REEXECUTION_RUNNER_WORKER_OPERATION_KINDS:
        raise ValueError(f"operation_kind must be one of {sorted(REEXECUTION_RUNNER_WORKER_OPERATION_KINDS)}")
    if not isinstance(service_attestation, dict):
        raise ValueError("service_attestation must be an object")
    for value, field in (
        (environment, "environment"),
        (worker_ref, "worker_ref"),
        (run_ref, "run_ref"),
        (actor_ref, "actor_ref"),
        (schedule_ref, "schedule_ref"),
        (lease_ref, "lease_ref"),
        (checkpoint_ref, "checkpoint_ref"),
        (queue_ref, "queue_ref"),
        (job_ref, "job_ref"),
        (job_hash, "job_hash"),
        (artifact_manifest_ref, "artifact_manifest_ref"),
        (artifact_manifest_hash, "artifact_manifest_hash"),
        (result_bundle_ref, "result_bundle_ref"),
        (result_bundle_hash, "result_bundle_hash"),
        (isolation_audit_ref, "isolation_audit_ref"),
        (isolation_audit_root, "isolation_audit_root"),
        (metrics_ref, "metrics_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (credential_ref, "credential_ref"),
        (retention_until, "retention_until"),
        (started_at, "started_at"),
    ):
        _require_text(value, field)
    completed = completed_at or utc_now()
    started = parse_rfc3339(started_at)
    finished = parse_rfc3339(completed)
    retention = parse_rfc3339(retention_until)
    if finished < started:
        raise ValueError("completed_at must be at or after started_at")
    if retention <= finished:
        raise ValueError("retention_until must be after completed_at")
    if next_run_at:
        parse_rfc3339(next_run_at)
    if not isinstance(cadence_seconds, int) or cadence_seconds <= 0:
        raise ValueError("cadence_seconds must be a positive integer")
    if not isinstance(attempt, int) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    if not isinstance(max_attempts, int) or max_attempts < attempt:
        raise ValueError("max_attempts must be greater than or equal to attempt")
    if response_status is not None and (not isinstance(response_status, int) or response_status < 100 or response_status > 599):
        raise ValueError("response_status must be an HTTP status code")
    for field, value in (
        ("checkpoint_hash", checkpoint_hash),
        ("job_hash", job_hash),
        ("artifact_manifest_hash", artifact_manifest_hash),
        ("result_bundle_hash", result_bundle_hash),
        ("isolation_audit_root", isolation_audit_root),
        ("runtime_audit_root", runtime_audit_root),
        ("request_hash", request_hash),
        ("response_hash", response_hash),
        ("audit_log_root", audit_log_root),
    ):
        if value and not _is_sha256_ref(str(value)):
            raise ValueError(f"{field} must be a sha256 reference")

    service_result = verify_reexecution_runner_service_attestation(
        service_attestation,
        isolation_attestation,
        runner_evidence=runner_evidence,
        policy=policy,
        report=report,
        key=key,
    )
    if not service_result.ok:
        raise ValueError("invalid re-execution runner service source: " + "; ".join(service_result.errors))

    source_artifacts = _source_artifacts(service_attestation, isolation_attestation, runner_evidence, policy, report)
    service = _service_record(service_attestation)
    source = _source_summary(source_artifacts)
    response_success = response_status is None or 200 <= response_status < 300
    success = not error_ref and response_success
    body: dict[str, Any] = {
        "schema": REEXECUTION_RUNNER_WORKER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": completed,
        "service": service,
        "source": source,
        "worker": {
            "worker_ref": worker_ref,
            "run_ref": run_ref,
            "operation_kind": operation_kind,
            "actor_ref": actor_ref,
            "started_at": started_at,
            "completed_at": completed,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "success": success,
            "error_ref": error_ref,
        },
        "scheduler": {
            "schedule_ref": schedule_ref,
            "cadence_seconds": cadence_seconds,
            "lease_ref": lease_ref,
            "checkpoint_ref": checkpoint_ref,
            "checkpoint_hash": checkpoint_hash,
            "previous_cursor_ref": previous_cursor_ref,
            "next_cursor_ref": next_cursor_ref,
            "next_run_at": next_run_at,
        },
        "execution": {
            "queue_ref": queue_ref,
            "queue_message_ref": queue_message_ref,
            "dead_letter_queue_ref": dead_letter_queue_ref,
            "job_ref": job_ref,
            "job_hash": job_hash,
            "artifact_manifest_ref": artifact_manifest_ref,
            "artifact_manifest_hash": artifact_manifest_hash,
            "result_bundle_ref": result_bundle_ref,
            "result_bundle_hash": result_bundle_hash,
            "isolation_audit_ref": isolation_audit_ref,
            "isolation_audit_root": isolation_audit_root,
            "runtime_audit_ref": runtime_audit_ref,
            "runtime_audit_root": runtime_audit_root,
            "request_hash": request_hash,
            "response_status": response_status,
            "response_hash": response_hash,
        },
        "observability": {
            "metrics_ref": metrics_ref,
            "audit_log_ref": audit_log_ref,
            "audit_log_root": audit_log_root,
            "retention_until": retention_until,
            "evidence_refs": sorted(evidence_refs or []),
        },
        "credential": _redacted_ref(credential_ref),
        "source_artifacts": source_artifacts,
        "controls": _controls(service, source, mode, cadence_seconds, checkpoint_hash, job_hash, artifact_manifest_hash, result_bundle_hash, isolation_audit_root, audit_log_root, success),
        "limitations": [
            "This receipt records a re-execution runner worker operation and replays the signed service attestation source.",
            "It binds queue, lease, checkpoint, job, artifact/result custody, request/response, metrics, audit, and credential-redaction evidence.",
            "It does not claim live kernel/container enforcement unless backed by runtime-native audit exports and continuously operated worker infrastructure.",
        ],
    }
    worker_operation_id = content_hash(body)
    return {
        **body,
        "worker_operation_id": worker_operation_id,
        "signatures": [sign_value({"worker_operation_id": worker_operation_id, "reexecution_runner_worker": body}, key)],
    }


def verify_reexecution_runner_worker_receipt(
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    isolation_attestation: dict[str, Any] | None = None,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    key: str | None = None,
) -> ReexecutionRunnerWorkerVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != REEXECUTION_RUNNER_WORKER_SCHEMA:
        errors.append(f"unsupported re-execution runner worker schema: {receipt.get('schema')}")
    body = without_keys(receipt, "worker_operation_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("worker_operation_id") != expected_id:
        errors.append("worker_operation_id does not match canonical re-execution runner worker body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("re-execution runner worker receipt must include at least one signature")
    else:
        signed_value = {"worker_operation_id": receipt.get("worker_operation_id"), "reexecution_runner_worker": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("re-execution runner worker signature verification failed")

    try:
        recorded = parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"re-execution runner worker recorded_at invalid: {exc}")
        recorded = None
    mode = receipt.get("mode")
    if mode not in REEXECUTION_RUNNER_WORKER_MODES:
        errors.append("re-execution runner worker mode is unsupported")
    elif mode not in {"hosted-worker", "isolated-runner-worker"}:
        warnings.append(f"re-execution runner worker mode is {mode}; continuously hosted worker operation is not claimed")

    _verify_service(receipt.get("service"), errors)
    _verify_source(receipt.get("source"), errors)
    operation_kind = _verify_worker(receipt.get("worker"), errors)
    _verify_scheduler(receipt.get("scheduler"), errors)
    _verify_execution(receipt.get("execution"), errors)
    _verify_observability(receipt.get("observability"), recorded, errors)
    _verify_redacted_ref(receipt.get("credential"), "re-execution runner worker credential", errors)
    _verify_source_artifacts(receipt.get("source_artifacts"), errors)

    if service_attestation is None:
        warnings.append("re-execution runner worker service attestation artifact was not supplied; service hash was not replayed")
    else:
        _compare_source_hash(receipt, "reexecution-runner-service-attestation", service_attestation, errors)
        service_hash = receipt.get("service", {}).get("attestation_hash") if isinstance(receipt.get("service"), dict) else None
        if service_hash != content_hash(service_attestation):
            errors.append("re-execution runner worker service.attestation_hash does not match supplied service attestation")
        service_result = verify_reexecution_runner_service_attestation(
            service_attestation,
            isolation_attestation,
            runner_evidence=runner_evidence,
            policy=policy,
            report=report,
            key=key,
        )
        if not service_result.ok:
            errors.extend(f"re-execution runner worker service source: {error}" for error in service_result.errors)
        warnings.extend(f"re-execution runner worker service source: {warning}" for warning in service_result.warnings)

    for source_type, source_value in (
        ("reexecution-isolation-attestation", isolation_attestation),
        ("reexecution-runner-evidence", runner_evidence),
        ("reexecution-policy", policy),
        ("reexecution-report", report),
    ):
        if source_value is not None:
            _compare_source_hash(receipt, source_type, source_value, errors)

    if operation_kind == "reexecution_run" and runner_evidence is None:
        warnings.append("re-execution runner worker runner evidence artifact was not supplied; run evidence hash was not replayed")
    _check_no_secret_values(receipt, errors)
    return ReexecutionRunnerWorkerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_reexecution_runner_worker_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    isolation_attestation: dict[str, Any] | None = None,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_reexecution_runner_worker_receipt(
        receipt,
        service_attestation=service_attestation,
        isolation_attestation=isolation_attestation,
        runner_evidence=runner_evidence,
        policy=policy,
        report=report,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid re-execution runner worker receipt: " + "; ".join(result.errors))
    payload = {
        "worker_operation_id": receipt["worker_operation_id"],
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "service": receipt.get("service"),
        "source": receipt.get("source"),
        "worker": receipt.get("worker"),
        "scheduler": receipt.get("scheduler"),
        "execution": receipt.get("execution"),
        "observability": receipt.get("observability"),
        "credential": receipt.get("credential"),
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(REEXECUTION_RUNNER_WORKER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("recorded_at"))


def _service_record(attestation: dict[str, Any]) -> dict[str, Any]:
    service = attestation.get("service", {}) if isinstance(attestation, dict) else {}
    scheduler = attestation.get("scheduler", {}) if isinstance(attestation, dict) and isinstance(attestation.get("scheduler"), dict) else {}
    execution = attestation.get("execution_controls", {}) if isinstance(attestation, dict) and isinstance(attestation.get("execution_controls"), dict) else {}
    audit_log = attestation.get("audit_log", {}) if isinstance(attestation, dict) and isinstance(attestation.get("audit_log"), dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id") if isinstance(attestation, dict) else None,
        "attestation_hash": content_hash(attestation) if isinstance(attestation, dict) else None,
        "mode": attestation.get("mode") if isinstance(attestation, dict) else None,
        "environment": attestation.get("environment") if isinstance(attestation, dict) else None,
        "service_ref": service.get("service_ref") if isinstance(service, dict) else None,
        "service_version": service.get("version") if isinstance(service, dict) else None,
        "runner_image_digest": service.get("runner_image_digest") if isinstance(service, dict) else None,
        "queue_ref": scheduler.get("queue_ref"),
        "dead_letter_queue_ref": scheduler.get("dead_letter_queue_ref"),
        "lease_store_ref": scheduler.get("lease_store_ref"),
        "checkpoint_store_ref": scheduler.get("checkpoint_store_ref"),
        "max_concurrency": scheduler.get("max_concurrency"),
        "artifact_store_ref": execution.get("artifact_store_ref"),
        "result_store_ref": execution.get("result_store_ref"),
        "idempotency_store_ref": execution.get("idempotency_store_ref"),
        "kms_key_ref": execution.get("kms_key_ref"),
        "audit_log_root": audit_log.get("root"),
    }


def _source_artifacts(
    service_attestation: dict[str, Any] | None,
    isolation_attestation: dict[str, Any] | None,
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source_type, value in (
        ("reexecution-runner-service-attestation", service_attestation),
        ("reexecution-isolation-attestation", isolation_attestation),
        ("reexecution-runner-evidence", runner_evidence),
        ("reexecution-policy", policy),
        ("reexecution-report", report),
    ):
        if isinstance(value, dict):
            records.append({"type": source_type, "id": _source_id(value), "schema": value.get("schema"), "hash": content_hash(value)})
    return records


def _source_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_count": len(records),
        "source_hash": content_hash(records),
        "schemas": sorted({str(record.get("schema")) for record in records if record.get("schema")}),
        "required_types": sorted(record["type"] for record in records),
        "artifacts": records,
    }


def _controls(
    service: dict[str, Any],
    source: dict[str, Any],
    mode: str,
    cadence_seconds: int,
    checkpoint_hash: str | None,
    job_hash: str,
    artifact_manifest_hash: str,
    result_bundle_hash: str,
    isolation_audit_root: str,
    audit_log_root: str,
    success: bool,
) -> list[dict[str, str]]:
    return [
        {
            "id": "worker-source-replay",
            "status": "worker-recorded" if source.get("source_count", 0) >= 2 and service.get("attestation_hash") else "planned-production",
            "description": "Worker receipt is bound to service, isolation, runner, policy, and report source hashes.",
        },
        {
            "id": "worker-hosted-mode",
            "status": "worker-recorded" if mode in {"hosted-worker", "isolated-runner-worker"} else "planned-production",
            "description": "Worker mode records hosted runner operation intent.",
        },
        {
            "id": "scheduler-lease-checkpoint",
            "status": "worker-recorded" if cadence_seconds > 0 and checkpoint_hash and service.get("lease_store_ref") and service.get("checkpoint_store_ref") else "planned-production",
            "description": "Schedule, lease store, checkpoint store, cadence, and checkpoint hash are bound.",
        },
        {
            "id": "queue-job-custody",
            "status": "worker-recorded" if service.get("queue_ref") and _is_sha256_ref(job_hash) and _is_sha256_ref(artifact_manifest_hash) and _is_sha256_ref(result_bundle_hash) else "planned-production",
            "description": "Queue, job hash, artifact manifest hash, and result bundle hash are bound.",
        },
        {
            "id": "runtime-audit-roots",
            "status": "worker-recorded" if _is_sha256_ref(isolation_audit_root) and _is_sha256_ref(audit_log_root) else "planned-production",
            "description": "Isolation audit root and worker audit root are bound.",
        },
        {
            "id": "worker-success-recorded",
            "status": "worker-recorded" if success else "failed",
            "description": "Worker outcome is explicitly recorded.",
        },
    ]


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner worker service must be an object")
        return
    for field in ("attestation_id", "attestation_hash", "service_ref", "queue_ref", "lease_store_ref", "checkpoint_store_ref", "artifact_store_ref", "result_store_ref", "kms_key_ref"):
        if not value.get(field):
            errors.append(f"re-execution runner worker service.{field} is required")
    for field in ("attestation_hash", "runner_image_digest", "audit_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"re-execution runner worker service.{field} must be a sha256 reference")


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner worker source must be an object")
        return
    if value.get("source_count", 0) < 2:
        errors.append("re-execution runner worker source.source_count must include service and runner sources")
    if not _is_sha256_ref(str(value.get("source_hash") or "")):
        errors.append("re-execution runner worker source.source_hash must be a sha256 reference")
    required = value.get("required_types", [])
    if not isinstance(required, list) or "reexecution-runner-service-attestation" not in required:
        errors.append("re-execution runner worker source must include reexecution-runner-service-attestation")


def _verify_worker(value: Any, errors: list[str]) -> str | None:
    if not isinstance(value, dict):
        errors.append("re-execution runner worker worker must be an object")
        return None
    for field in ("worker_ref", "run_ref", "operation_kind", "actor_ref", "started_at", "completed_at"):
        if not value.get(field):
            errors.append(f"re-execution runner worker worker.{field} is required")
    operation_kind = value.get("operation_kind")
    if operation_kind not in REEXECUTION_RUNNER_WORKER_OPERATION_KINDS:
        errors.append("re-execution runner worker worker.operation_kind is unsupported")
    try:
        started = parse_rfc3339(str(value.get("started_at") or ""))
        completed = parse_rfc3339(str(value.get("completed_at") or ""))
        if completed < started:
            errors.append("re-execution runner worker worker.completed_at must be at or after started_at")
    except ValueError as exc:
        errors.append(f"re-execution runner worker worker timestamp invalid: {exc}")
    if not isinstance(value.get("attempt"), int) or value.get("attempt") < 1:
        errors.append("re-execution runner worker worker.attempt must be a positive integer")
    if not isinstance(value.get("max_attempts"), int) or value.get("max_attempts") < value.get("attempt", 1):
        errors.append("re-execution runner worker worker.max_attempts must be greater than or equal to attempt")
    if value.get("success") is False and not value.get("error_ref"):
        errors.append("re-execution runner worker worker.error_ref is required when success is false")
    return str(operation_kind) if operation_kind else None


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner worker scheduler must be an object")
        return
    for field in ("schedule_ref", "lease_ref", "checkpoint_ref"):
        if not value.get(field):
            errors.append(f"re-execution runner worker scheduler.{field} is required")
    if not isinstance(value.get("cadence_seconds"), int) or value.get("cadence_seconds") <= 0:
        errors.append("re-execution runner worker scheduler.cadence_seconds must be positive")
    if value.get("checkpoint_hash") and not _is_sha256_ref(str(value.get("checkpoint_hash"))):
        errors.append("re-execution runner worker scheduler.checkpoint_hash must be a sha256 reference")
    if value.get("next_run_at"):
        try:
            parse_rfc3339(str(value.get("next_run_at")))
        except ValueError as exc:
            errors.append(f"re-execution runner worker scheduler.next_run_at invalid: {exc}")


def _verify_execution(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner worker execution must be an object")
        return
    for field in ("queue_ref", "job_ref", "job_hash", "artifact_manifest_ref", "artifact_manifest_hash", "result_bundle_ref", "result_bundle_hash", "isolation_audit_ref", "isolation_audit_root"):
        if not value.get(field):
            errors.append(f"re-execution runner worker execution.{field} is required")
    for field in ("job_hash", "artifact_manifest_hash", "result_bundle_hash", "isolation_audit_root", "runtime_audit_root", "request_hash", "response_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"re-execution runner worker execution.{field} must be a sha256 reference")
    status = value.get("response_status")
    if status is not None and (not isinstance(status, int) or status < 100 or status > 599):
        errors.append("re-execution runner worker execution.response_status must be an HTTP status code")


def _verify_observability(value: Any, recorded: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner worker observability must be an object")
        return
    for field in ("metrics_ref", "audit_log_ref", "audit_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"re-execution runner worker observability.{field} is required")
    if value.get("audit_log_root") and not _is_sha256_ref(str(value.get("audit_log_root"))):
        errors.append("re-execution runner worker observability.audit_log_root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if recorded and retention <= recorded:
            errors.append("re-execution runner worker observability.retention_until must be after recorded_at")
    except ValueError as exc:
        errors.append(f"re-execution runner worker observability.retention_until invalid: {exc}")
    if not isinstance(value.get("evidence_refs", []), list):
        errors.append("re-execution runner worker observability.evidence_refs must be a list")


def _verify_source_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("re-execution runner worker source_artifacts must be a non-empty list")
        return
    if not any(isinstance(item, dict) and item.get("type") == "reexecution-runner-service-attestation" for item in value):
        errors.append("re-execution runner worker source_artifacts must include reexecution-runner-service-attestation")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"re-execution runner worker source_artifacts[{index}] must be an object")
            continue
        if not item.get("type") or not item.get("hash"):
            errors.append(f"re-execution runner worker source_artifacts[{index}] type and hash are required")
        elif not _is_sha256_ref(str(item.get("hash"))):
            errors.append(f"re-execution runner worker source_artifacts[{index}].hash must be a sha256 reference")


def _compare_source_hash(receipt: dict[str, Any], source_type: str, value: dict[str, Any], errors: list[str]) -> None:
    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("re-execution runner worker source_artifacts must be a list")
        return
    actual = content_hash(value)
    if not any(isinstance(item, dict) and item.get("type") == source_type and item.get("hash") == actual for item in artifacts):
        errors.append(f"re-execution runner worker source_artifacts missing current hash for {source_type}")


def _source_id(value: dict[str, Any]) -> str | None:
    for field in (
        "attestation_id",
        "evidence_id",
        "report_id",
        "policy_id",
        "id",
        "worker_operation_id",
    ):
        if value.get(field):
            return str(value.get(field))
    return None


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return summary


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(lowered, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"re-execution runner worker secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    return False
