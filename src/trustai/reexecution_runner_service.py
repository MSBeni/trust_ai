from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .reexecution_isolation import verify_reexecution_isolation_attestation

REEXECUTION_RUNNER_SERVICE_SCHEMA = "trustai.reexecution-runner-service-attestation/0.1"
REEXECUTION_RUNNER_SERVICE_ENTRY_TYPE = "reexecution.runner_service_attested"
REEXECUTION_RUNNER_SERVICE_MODES = {"local-reference", "isolated-runner-service", "production-design"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class ReexecutionRunnerServiceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_reexecution_runner_service_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("re-execution runner service attestation must contain an object")
    return value


def write_reexecution_runner_service_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_reexecution_runner_service_attestation(
    isolation_attestation: dict[str, Any],
    *,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    mode: str = "isolated-runner-service",
    environment: str = "local",
    service_ref: str,
    service_version: str,
    runner_image: str | None = None,
    runner_image_digest: str | None = None,
    runner_binary_hash: str,
    replicas_min: int,
    replicas_max: int,
    availability_zones: list[str] | None = None,
    scheduler_ref: str,
    schedule_cadence_seconds: int,
    queue_ref: str,
    dead_letter_queue_ref: str,
    lease_store_ref: str,
    checkpoint_store_ref: str,
    max_concurrency: int,
    retry_policy_ref: str,
    isolation_profile_ref: str,
    admission_policy_ref: str,
    tenant_isolation_ref: str,
    network_policy_ref: str,
    egress_policy_ref: str,
    artifact_store_ref: str,
    result_store_ref: str,
    idempotency_store_ref: str,
    secret_store_ref: str,
    kms_key_ref: str,
    metrics_ref: str,
    alert_policy_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in REEXECUTION_RUNNER_SERVICE_MODES:
        raise ValueError(f"mode must be one of {sorted(REEXECUTION_RUNNER_SERVICE_MODES)}")

    source_result = verify_reexecution_isolation_attestation(
        isolation_attestation,
        runner_evidence,
        policy=policy,
        report=report,
        key=key,
    )
    if not source_result.ok:
        raise ValueError("invalid re-execution isolation attestation: " + "; ".join(source_result.errors))

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")
    if replicas_min < 1:
        raise ValueError("replicas_min must be at least 1")
    if replicas_max < replicas_min:
        raise ValueError("replicas_max must be greater than or equal to replicas_min")
    if schedule_cadence_seconds < 1:
        raise ValueError("schedule_cadence_seconds must be positive")
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be positive")

    source_isolation = isolation_attestation.get("isolation", {}) if isinstance(isolation_attestation.get("isolation"), dict) else {}
    image = runner_image or source_isolation.get("runner_image")
    image_digest = runner_image_digest or source_isolation.get("runner_image_digest")
    if source_isolation.get("runner_image_digest") and image_digest != source_isolation.get("runner_image_digest"):
        raise ValueError("runner_image_digest must match source isolation runner image digest")

    for field, value in {
        "service_ref": service_ref,
        "service_version": service_version,
        "runner_image": image,
        "runner_image_digest": image_digest,
        "runner_binary_hash": runner_binary_hash,
        "scheduler_ref": scheduler_ref,
        "queue_ref": queue_ref,
        "dead_letter_queue_ref": dead_letter_queue_ref,
        "lease_store_ref": lease_store_ref,
        "checkpoint_store_ref": checkpoint_store_ref,
        "retry_policy_ref": retry_policy_ref,
        "isolation_profile_ref": isolation_profile_ref,
        "admission_policy_ref": admission_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "artifact_store_ref": artifact_store_ref,
        "result_store_ref": result_store_ref,
        "idempotency_store_ref": idempotency_store_ref,
        "secret_store_ref": secret_store_ref,
        "kms_key_ref": kms_key_ref,
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "retention_until": retention_until,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    service = {
        "service_ref": service_ref,
        "version": service_version,
        "runner_image": image,
        "runner_image_digest": image_digest,
        "runner_binary_hash": runner_binary_hash,
        "replicas_min": replicas_min,
        "replicas_max": replicas_max,
        "availability_zones": sorted(set(availability_zones or [])),
    }
    scheduler = {
        "scheduler_ref": scheduler_ref,
        "cadence_seconds": schedule_cadence_seconds,
        "queue_ref": queue_ref,
        "dead_letter_queue_ref": dead_letter_queue_ref,
        "lease_store_ref": lease_store_ref,
        "checkpoint_store_ref": checkpoint_store_ref,
        "max_concurrency": max_concurrency,
        "retry_policy_ref": retry_policy_ref,
    }
    execution_controls = {
        "isolation_profile_ref": isolation_profile_ref,
        "admission_policy_ref": admission_policy_ref,
        "tenant_isolation_ref": tenant_isolation_ref,
        "network_policy_ref": network_policy_ref,
        "egress_policy_ref": egress_policy_ref,
        "artifact_store_ref": artifact_store_ref,
        "result_store_ref": result_store_ref,
        "idempotency_store_ref": idempotency_store_ref,
        "secret_store_ref": secret_store_ref,
        "kms_key_ref": kms_key_ref,
        "source_isolation_ref": source_isolation.get("isolation_ref"),
        "source_network_mode": source_isolation.get("network_mode"),
        "source_read_only_rootfs": source_isolation.get("read_only_rootfs"),
    }
    observability = {
        "metrics_ref": metrics_ref,
        "alert_policy_ref": alert_policy_ref,
    }
    audit_log = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    operation = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    source = _source_record(isolation_attestation, runner_evidence, policy, report)
    source_artifacts = _source_artifacts(isolation_attestation, runner_evidence, policy, report)
    body: dict[str, Any] = {
        "schema": REEXECUTION_RUNNER_SERVICE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": source,
        "service": service,
        "scheduler": scheduler,
        "execution_controls": execution_controls,
        "observability": observability,
        "operation": operation,
        "audit_log": audit_log,
        "source_artifacts": source_artifacts,
        "controls": _controls(service, scheduler, execution_controls, audit_log, observability),
        "limitations": [
            "This attestation binds re-execution isolation evidence to a recorded runner service control plane.",
            "It records service image and binary hashes, scheduler and queue controls, idempotency, tenant isolation, egress policy, metrics, alerting, and audit-log evidence.",
            "It does not claim live kernel/container enforcement unless backed by a continuously operated runner service and runtime-native audit exports.",
            "Production deployments should replace local references with orchestrator admission logs, runtime audit logs, queue/lease exports, and provider-managed artifact/result stores.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "reexecution_runner_service": body}, key)],
    }


def verify_reexecution_runner_service_attestation(
    attestation: dict[str, Any],
    isolation_attestation: dict[str, Any] | None = None,
    *,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    key: str | None = None,
) -> ReexecutionRunnerServiceVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != REEXECUTION_RUNNER_SERVICE_SCHEMA:
        errors.append(f"unsupported re-execution runner service attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical re-execution runner service attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("re-execution runner service attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "reexecution_runner_service": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("re-execution runner service attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"re-execution runner service attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in REEXECUTION_RUNNER_SERVICE_MODES:
        errors.append("re-execution runner service mode is unsupported")
    elif mode != "isolated-runner-service":
        warnings.append(f"re-execution runner service mode is {mode}; live hosted runner operation is not fully claimed")

    _verify_source_record(attestation.get("source"), errors)
    _verify_service(attestation.get("service"), errors)
    _verify_scheduler(attestation.get("scheduler"), errors)
    _verify_execution_controls(attestation.get("execution_controls"), errors)
    _verify_observability(attestation.get("observability"), errors)
    _verify_operation(attestation.get("operation"), errors)
    _verify_audit_log(attestation.get("audit_log"), attested, errors)
    _verify_source_artifacts(attestation.get("source_artifacts"), errors)

    if isolation_attestation is not None:
        source_result = verify_reexecution_isolation_attestation(
            isolation_attestation,
            runner_evidence,
            policy=policy,
            report=report,
            key=key,
        )
        errors.extend(f"source isolation invalid: {error}" for error in source_result.errors)
        warnings.extend(f"source isolation warning: {warning}" for warning in source_result.warnings)
        expected_source = _source_record(isolation_attestation, runner_evidence, policy, report)
        if attestation.get("source") != expected_source:
            errors.append("re-execution runner service source record does not match supplied source artifacts")
        expected_artifacts = _source_artifacts(isolation_attestation, runner_evidence, policy, report)
        if attestation.get("source_artifacts") != expected_artifacts:
            errors.append("re-execution runner service source_artifacts do not match supplied source artifacts")
        service = attestation.get("service", {}) if isinstance(attestation.get("service"), dict) else {}
        isolation = isolation_attestation.get("isolation", {}) if isinstance(isolation_attestation.get("isolation"), dict) else {}
        if isolation.get("runner_image_digest") and service.get("runner_image_digest") != isolation.get("runner_image_digest"):
            errors.append("re-execution runner service runner_image_digest does not match source isolation")

    _check_no_secret_values(attestation, errors)
    return ReexecutionRunnerServiceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_reexecution_runner_service_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    isolation_attestation: dict[str, Any] | None = None,
    *,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_reexecution_runner_service_attestation(
        attestation,
        isolation_attestation,
        runner_evidence=runner_evidence,
        policy=policy,
        report=report,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid re-execution runner service attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "service": attestation.get("service"),
        "scheduler": attestation.get("scheduler"),
        "execution_controls": attestation.get("execution_controls"),
        "observability": attestation.get("observability"),
        "operation": attestation.get("operation"),
        "audit_log": attestation.get("audit_log"),
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(REEXECUTION_RUNNER_SERVICE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_record(
    isolation_attestation: dict[str, Any] | None,
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> dict[str, Any]:
    isolation = isolation_attestation.get("isolation", {}) if isinstance(isolation_attestation, dict) and isinstance(isolation_attestation.get("isolation"), dict) else {}
    source = isolation_attestation.get("source", {}) if isinstance(isolation_attestation, dict) and isinstance(isolation_attestation.get("source"), dict) else {}
    return {
        "isolation_attestation_id": isolation_attestation.get("attestation_id") if isinstance(isolation_attestation, dict) else None,
        "isolation_attestation_hash": content_hash(isolation_attestation) if isinstance(isolation_attestation, dict) else None,
        "isolation_mode": isolation_attestation.get("mode") if isinstance(isolation_attestation, dict) else None,
        "runner_evidence_id": runner_evidence.get("evidence_id") if isinstance(runner_evidence, dict) else source.get("runner_evidence_id"),
        "runner_evidence_hash": content_hash(runner_evidence) if isinstance(runner_evidence, dict) else source.get("runner_evidence_hash"),
        "policy_id": policy.get("id") if isinstance(policy, dict) else source.get("policy_id"),
        "policy_hash": content_hash(policy) if isinstance(policy, dict) else source.get("policy_hash"),
        "report_id": report.get("report_id") if isinstance(report, dict) else source.get("report_id"),
        "report_hash": content_hash(report) if isinstance(report, dict) else source.get("report_hash"),
        "run_count": source.get("run_count"),
        "runner_image_digest": isolation.get("runner_image_digest"),
        "network_mode": isolation.get("network_mode"),
        "read_only_rootfs": isolation.get("read_only_rootfs"),
        "audit_log_ref": isolation_attestation.get("audit_log", {}).get("audit_log_ref") if isinstance(isolation_attestation, dict) and isinstance(isolation_attestation.get("audit_log"), dict) else None,
        "audit_log_root": isolation_attestation.get("audit_log", {}).get("root") if isinstance(isolation_attestation, dict) and isinstance(isolation_attestation.get("audit_log"), dict) else None,
    }


def _source_artifacts(
    isolation_attestation: dict[str, Any] | None,
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if isinstance(isolation_attestation, dict):
        artifacts.append(
            {
                "type": "reexecution-isolation-attestation",
                "id": isolation_attestation.get("attestation_id"),
                "schema": isolation_attestation.get("schema"),
                "hash": content_hash(isolation_attestation),
            }
        )
    if isinstance(runner_evidence, dict):
        artifacts.append(
            {
                "type": "reexecution-runner-evidence",
                "id": runner_evidence.get("evidence_id"),
                "schema": runner_evidence.get("schema"),
                "hash": content_hash(runner_evidence),
            }
        )
    if isinstance(policy, dict):
        artifacts.append(
            {
                "type": "reexecution-policy",
                "id": policy.get("id"),
                "hash": content_hash(policy),
            }
        )
    if isinstance(report, dict):
        artifacts.append(
            {
                "type": "reexecution-report",
                "id": report.get("report_id"),
                "schema": report.get("schema"),
                "hash": content_hash(report),
            }
        )
    return artifacts


def _verify_source_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner service source must be an object")
        return
    for field in ("isolation_attestation_id", "isolation_attestation_hash", "runner_evidence_id", "runner_evidence_hash", "runner_image_digest", "network_mode", "read_only_rootfs"):
        if value.get(field) in (None, ""):
            errors.append(f"re-execution runner service source.{field} is required")
    if value.get("network_mode") != "disabled":
        errors.append("re-execution runner service source.network_mode must be disabled")
    if value.get("read_only_rootfs") is not True:
        errors.append("re-execution runner service source.read_only_rootfs must be true")
    for field in ("isolation_attestation_hash", "runner_evidence_hash", "runner_image_digest"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"re-execution runner service source.{field} must be a sha256 reference")


def _verify_service(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner service service must be an object")
        return
    for field in ("service_ref", "version", "runner_image", "runner_image_digest", "runner_binary_hash"):
        if not value.get(field):
            errors.append(f"re-execution runner service service.{field} is required")
    for field in ("runner_image_digest", "runner_binary_hash"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"re-execution runner service service.{field} must be a sha256 reference")
    if not isinstance(value.get("replicas_min"), int) or value.get("replicas_min") < 2:
        errors.append("re-execution runner service service.replicas_min must be an integer >= 2")
    if not isinstance(value.get("replicas_max"), int) or value.get("replicas_max") < value.get("replicas_min", 0):
        errors.append("re-execution runner service service.replicas_max must be >= replicas_min")
    zones = value.get("availability_zones")
    if not isinstance(zones, list) or len(zones) < 2 or not all(isinstance(zone, str) and zone for zone in zones):
        errors.append("re-execution runner service service.availability_zones must contain at least two zones")


def _verify_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner service scheduler must be an object")
        return
    for field in ("scheduler_ref", "queue_ref", "dead_letter_queue_ref", "lease_store_ref", "checkpoint_store_ref", "retry_policy_ref"):
        if not value.get(field):
            errors.append(f"re-execution runner service scheduler.{field} is required")
    if not isinstance(value.get("cadence_seconds"), int) or value.get("cadence_seconds") < 1:
        errors.append("re-execution runner service scheduler.cadence_seconds must be positive")
    if not isinstance(value.get("max_concurrency"), int) or value.get("max_concurrency") < 1:
        errors.append("re-execution runner service scheduler.max_concurrency must be positive")


def _verify_execution_controls(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner service execution_controls must be an object")
        return
    for field in (
        "isolation_profile_ref",
        "admission_policy_ref",
        "tenant_isolation_ref",
        "network_policy_ref",
        "egress_policy_ref",
        "artifact_store_ref",
        "result_store_ref",
        "idempotency_store_ref",
        "secret_store_ref",
        "kms_key_ref",
        "source_isolation_ref",
    ):
        if not value.get(field):
            errors.append(f"re-execution runner service execution_controls.{field} is required")
    if value.get("source_network_mode") != "disabled":
        errors.append("re-execution runner service execution_controls.source_network_mode must be disabled")
    if value.get("source_read_only_rootfs") is not True:
        errors.append("re-execution runner service execution_controls.source_read_only_rootfs must be true")


def _verify_observability(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner service observability must be an object")
        return
    for field in ("metrics_ref", "alert_policy_ref"):
        if not value.get(field):
            errors.append(f"re-execution runner service observability.{field} is required")


def _verify_operation(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner service operation must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("re-execution runner service operation.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "re-execution runner service operation.credential", errors)


def _verify_audit_log(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("re-execution runner service audit_log must be an object")
        return
    for field in ("audit_log_ref", "root", "retention_until"):
        if not value.get(field):
            errors.append(f"re-execution runner service audit_log.{field} is required")
    if value.get("root") and not _is_sha256_ref(str(value.get("root"))):
        errors.append("re-execution runner service audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("re-execution runner service audit_log.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"re-execution runner service audit_log.retention_until invalid: {exc}")


def _verify_source_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("re-execution runner service source_artifacts must be a non-empty list")
        return
    if not any(isinstance(item, dict) and item.get("type") == "reexecution-isolation-attestation" for item in value):
        errors.append("re-execution runner service source_artifacts must include reexecution-isolation-attestation")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"re-execution runner service source_artifacts[{index}] must be an object")
            continue
        if not item.get("type") or not item.get("hash"):
            errors.append(f"re-execution runner service source_artifacts[{index}] type and hash are required")
        elif not _is_sha256_ref(str(item.get("hash"))):
            errors.append(f"re-execution runner service source_artifacts[{index}].hash must be a sha256 reference")


def _controls(
    service: dict[str, Any],
    scheduler: dict[str, Any],
    execution_controls: dict[str, Any],
    audit_log: dict[str, Any],
    observability: dict[str, Any],
) -> list[dict[str, str]]:
    return [
        {
            "id": "runner-service-image-integrity",
            "status": "service-attested" if _is_sha256_ref(str(service.get("runner_image_digest") or "")) and _is_sha256_ref(str(service.get("runner_binary_hash") or "")) else "planned-production",
            "description": "Runner service image digest and binary hash are bound.",
        },
        {
            "id": "multi-zone-runner-fleet",
            "status": "service-attested" if service.get("replicas_min", 0) >= 2 and len(service.get("availability_zones", [])) >= 2 else "planned-production",
            "description": "Runner service replica floor and availability-zone spread are bound.",
        },
        {
            "id": "scheduler-queue-leases",
            "status": "service-attested" if scheduler.get("queue_ref") and scheduler.get("lease_store_ref") and scheduler.get("checkpoint_store_ref") else "planned-production",
            "description": "Scheduler, queue, DLQ, lease, checkpoint, concurrency, and retry policy evidence are bound.",
        },
        {
            "id": "isolation-admission-egress",
            "status": "service-attested" if execution_controls.get("admission_policy_ref") and execution_controls.get("source_network_mode") == "disabled" and execution_controls.get("source_read_only_rootfs") is True else "planned-production",
            "description": "Admission policy, tenant isolation, network policy, egress policy, and source isolation controls are bound.",
        },
        {
            "id": "artifact-result-custody",
            "status": "service-attested" if execution_controls.get("artifact_store_ref") and execution_controls.get("result_store_ref") and execution_controls.get("kms_key_ref") else "planned-production",
            "description": "Artifact/result stores, idempotency, secret store, and KMS key references are bound.",
        },
        {
            "id": "runner-service-observability",
            "status": "service-attested" if observability.get("metrics_ref") and observability.get("alert_policy_ref") and _is_sha256_ref(str(audit_log.get("root") or "")) else "planned-production",
            "description": "Metrics, alerting, audit-log root, and retention evidence are bound.",
        },
    ]


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return summary


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


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
                    errors.append(f"re-execution runner service secret-like field must be redacted reference: {child_path}")
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
