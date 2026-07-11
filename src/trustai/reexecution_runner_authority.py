from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .reexecution_runner_service import verify_reexecution_runner_service_attestation
from .reexecution_runner_worker import verify_reexecution_runner_worker_receipt

REEXECUTION_RUNNER_AUTHORITY_SCHEMA = "trustai.reexecution-runner-production-authority-dossier/0.1"
REEXECUTION_RUNNER_AUTHORITY_ENTRY_TYPE = "reexecution.runner_authority_recorded"
REEXECUTION_RUNNER_AUTHORITY_MODES = {"local-dossier", "runner-service-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "production-runner-fleet", "title": "Continuously operated re-execution runner fleet", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "scheduler-queue-lease-checkpoint", "title": "Runtime-native scheduler, queue, lease, checkpoint, cursor, and dead-letter exports", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "container-orchestrator-admission", "title": "Container orchestrator admission, image policy, namespace, and workload identity evidence", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
    {"id": "kernel-container-isolation-enforcement", "title": "Kernel, cgroup, seccomp, AppArmor, filesystem, and network isolation enforcement", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
    {"id": "immutable-runtime-audit-logs", "title": "Immutable runner service, worker, container runtime, and kernel audit logs", "authority_kinds": ["hosted-service", "cloud-object-lock", "customer"]},
    {"id": "artifact-result-custody", "title": "Artifact, input, output, and result custody with WORM retention", "authority_kinds": ["hosted-service", "cloud-object-lock", "customer"]},
    {"id": "deterministic-execution-controls", "title": "Seed, temperature, replay, and deterministic execution policy enforcement", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
    {"id": "tenant-network-egress-controls", "title": "Tenant isolation, network policy, disabled/default-deny egress, and rate limits", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "credential-custody-and-kms", "title": "Runner credential custody, redaction, secret store, and KMS/HSM enforcement", "authority_kinds": ["kms-hsm", "hosted-service", "provider-api"]},
    {"id": "observability-and-alerting", "title": "Runner metrics, health, alerting, and incident response evidence", "authority_kinds": ["hosted-service", "provider-api", "cloud-object-lock"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class ReexecutionRunnerAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_reexecution_runner_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("re-execution runner authority dossier must contain an object")
    return value


def write_reexecution_runner_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_reexecution_runner_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError("authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]")
    requirement_id, authority_kind, evidence_ref, evidence_hash, description = [part.strip() for part in parts]
    description_parts = [part.strip() for part in description.split(";")]
    metadata: dict[str, Any] = {}
    allowed_metadata = {"issuer", "subject", "source_uri", "issued_at", "expires_at"}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("authority evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in allowed_metadata:
            raise ValueError(f"unsupported authority evidence metadata key: {key}")
        metadata[key] = metadata_value
    return {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description_parts[0],
        **metadata,
    }


def build_reexecution_runner_authority_dossier(
    service_attestation: dict[str, Any],
    *,
    worker_receipts: list[dict[str, Any]] | None = None,
    isolation_attestation: dict[str, Any] | None = None,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    mode: str = "runner-service-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in REEXECUTION_RUNNER_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(REEXECUTION_RUNNER_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    source_result = verify_reexecution_runner_service_attestation(
        service_attestation,
        isolation_attestation,
        runner_evidence=runner_evidence,
        policy=policy,
        report=report,
        key=key,
    )
    if not source_result.ok:
        raise ValueError("invalid re-execution runner service source: " + "; ".join(source_result.errors))
    workers = list(worker_receipts or [])
    for receipt in workers:
        worker_result = verify_reexecution_runner_worker_receipt(
            receipt,
            service_attestation=service_attestation,
            isolation_attestation=isolation_attestation,
            runner_evidence=runner_evidence,
            policy=policy,
            report=report,
            key=key,
        )
        if not worker_result.ok:
            raise ValueError("invalid re-execution runner worker source: " + "; ".join(worker_result.errors))

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    binding = _source_binding(service_attestation, workers, isolation_attestation, runner_evidence, policy, report)
    source_context = _authority_evidence_source_context(binding)
    evidence_items = [_build_authority_evidence_item(item, source_context) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": REEXECUTION_RUNNER_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or _binding_environment(binding) or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "source_binding": binding,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, binding, evidence_items, summary),
        "limitations": [
            "This dossier binds verified re-execution runner service and worker evidence to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for production runner isolation.",
            "It does not claim continuously operated production runner isolation unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    signed_value = {"dossier_id": dossier_id, "reexecution_runner_authority": body}
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value(signed_value, key)]}


def verify_reexecution_runner_authority_dossier(
    dossier: dict[str, Any],
    *,
    service_attestation: dict[str, Any] | None = None,
    worker_receipts: list[dict[str, Any]] | None = None,
    isolation_attestation: dict[str, Any] | None = None,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> ReexecutionRunnerAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != REEXECUTION_RUNNER_AUTHORITY_SCHEMA:
        errors.append(f"unsupported re-execution runner authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    expected_id = content_hash(body)
    if dossier.get("dossier_id") != expected_id:
        errors.append("dossier_id does not match canonical re-execution runner authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("re-execution runner authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "reexecution_runner_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("re-execution runner authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in REEXECUTION_RUNNER_AUTHORITY_MODES:
        errors.append("re-execution runner authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"re-execution runner authority mode is {mode}; live production runner isolation is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"re-execution runner authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"re-execution runner authority {field} is required")

    _verify_source_binding(
        dossier.get("source_binding"),
        service_attestation,
        worker_receipts,
        isolation_attestation,
        runner_evidence,
        policy,
        report,
        errors,
        warnings,
        key=key,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("re-execution runner authority authority_evidence must be a list")
        evidence = []
    evidence_source_context = _authority_evidence_source_context(
        dossier.get("source_binding") if isinstance(dossier.get("source_binding"), dict) else {}
    )
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("re-execution runner authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_status = _verify_authority_evidence_item(
            item,
            errors,
            warnings,
            now=freshness_now,
            require_fresh=require_fresh,
            source_context=evidence_source_context,
        )
        freshness_counts[freshness_status] += 1

    evidence_dicts = [item for item in evidence if isinstance(item, dict)]
    expected_summary = _summary(evidence_dicts)
    if dossier.get("summary") != expected_summary:
        errors.append("re-execution runner authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("re-execution runner authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("re-execution runner authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every re-execution runner authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every re-execution runner authority evidence item to be fresh")
    binding_for_controls = dossier.get("source_binding") if isinstance(dossier.get("source_binding"), dict) else {}
    if mode == "production-dossier" and int(binding_for_controls.get("worker_count") or 0) < 1:
        errors.append("production-dossier mode requires at least one verified runner worker receipt")
    if mode == "production-dossier" and not _source_binding_complete(binding_for_controls):
        errors.append("production-dossier mode requires complete runner service, worker, source artifact, scheduler, isolation, custody, and audit bindings")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("re-execution runner authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), binding_for_controls, evidence_dicts, expected_summary):
        errors.append("re-execution runner authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)

    return ReexecutionRunnerAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_reexecution_runner_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    service_attestation: dict[str, Any],
    worker_receipts: list[dict[str, Any]] | None = None,
    isolation_attestation: dict[str, Any] | None = None,
    runner_evidence: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_reexecution_runner_authority_dossier(
        dossier,
        service_attestation=service_attestation,
        worker_receipts=worker_receipts,
        isolation_attestation=isolation_attestation,
        runner_evidence=runner_evidence,
        policy=policy,
        report=report,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid re-execution runner authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "source_binding": dossier.get("source_binding"),
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {
                "requirement_id": item.get("requirement_id"),
                "authority_kind": item.get("authority_kind"),
                "evidence_ref": item.get("evidence_ref"),
                "evidence_hash": item.get("evidence_hash"),
                "evidence_id": item.get("evidence_id"),
                "source_context": item.get("source_context"),
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
            }
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(REEXECUTION_RUNNER_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _source_binding(
    service_attestation: dict[str, Any],
    worker_receipts: list[dict[str, Any]],
    isolation_attestation: dict[str, Any] | None,
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> dict[str, Any]:
    service = service_attestation.get("service", {}) if isinstance(service_attestation.get("service"), dict) else {}
    scheduler = service_attestation.get("scheduler", {}) if isinstance(service_attestation.get("scheduler"), dict) else {}
    controls = service_attestation.get("execution_controls", {}) if isinstance(service_attestation.get("execution_controls"), dict) else {}
    audit_log = service_attestation.get("audit_log", {}) if isinstance(service_attestation.get("audit_log"), dict) else {}
    source = service_attestation.get("source", {}) if isinstance(service_attestation.get("source"), dict) else {}
    worker_records = [_worker_binding(receipt) for receipt in worker_receipts]
    starts = [record.get("started_at") for record in worker_records if record.get("started_at")]
    completions = [record.get("completed_at") for record in worker_records if record.get("completed_at")]
    return {
        "service_attestation_id": service_attestation.get("attestation_id"),
        "service_attestation_hash": content_hash(service_attestation),
        "service_schema": service_attestation.get("schema"),
        "service_mode": service_attestation.get("mode"),
        "environment": service_attestation.get("environment"),
        "attested_at": service_attestation.get("attested_at"),
        "service_ref": service.get("service_ref"),
        "runner_image_digest": service.get("runner_image_digest"),
        "runner_binary_hash": service.get("runner_binary_hash"),
        "replicas_min": service.get("replicas_min"),
        "replicas_max": service.get("replicas_max"),
        "availability_zones": service.get("availability_zones", []),
        "scheduler_ref": scheduler.get("scheduler_ref"),
        "queue_ref": scheduler.get("queue_ref"),
        "dead_letter_queue_ref": scheduler.get("dead_letter_queue_ref"),
        "lease_store_ref": scheduler.get("lease_store_ref"),
        "checkpoint_store_ref": scheduler.get("checkpoint_store_ref"),
        "source_isolation_attestation_id": source.get("isolation_attestation_id"),
        "source_runner_evidence_id": source.get("runner_evidence_id"),
        "source_policy_hash": source.get("policy_hash"),
        "source_report_id": source.get("report_id"),
        "source_network_mode": controls.get("source_network_mode"),
        "source_read_only_rootfs": controls.get("source_read_only_rootfs"),
        "isolation_profile_ref": controls.get("isolation_profile_ref"),
        "admission_policy_ref": controls.get("admission_policy_ref"),
        "tenant_isolation_ref": controls.get("tenant_isolation_ref"),
        "network_policy_ref": controls.get("network_policy_ref"),
        "egress_policy_ref": controls.get("egress_policy_ref"),
        "artifact_store_ref": controls.get("artifact_store_ref"),
        "result_store_ref": controls.get("result_store_ref"),
        "secret_store_ref": controls.get("secret_store_ref"),
        "kms_key_ref": controls.get("kms_key_ref"),
        "audit_log_root": audit_log.get("root"),
        "retention_until": audit_log.get("retention_until"),
        "worker_count": len(worker_records),
        "worker_operation_ids": sorted(str(record.get("worker_operation_id")) for record in worker_records if record.get("worker_operation_id")),
        "worker_operation_hashes": sorted(str(record.get("worker_operation_hash")) for record in worker_records if record.get("worker_operation_hash")),
        "first_worker_started_at": min(starts) if starts else None,
        "last_worker_completed_at": max(completions) if completions else None,
        "worker_operation_records": worker_records,
        "source_artifacts": _source_artifacts(service_attestation, worker_receipts, isolation_attestation, runner_evidence, policy, report),
    }


def _worker_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    scheduler = receipt.get("scheduler", {}) if isinstance(receipt.get("scheduler"), dict) else {}
    execution = receipt.get("execution", {}) if isinstance(receipt.get("execution"), dict) else {}
    observability = receipt.get("observability", {}) if isinstance(receipt.get("observability"), dict) else {}
    return {
        "worker_operation_id": receipt.get("worker_operation_id"),
        "worker_operation_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "worker_ref": worker.get("worker_ref"),
        "run_ref": worker.get("run_ref"),
        "operation_kind": worker.get("operation_kind"),
        "success": worker.get("success"),
        "started_at": worker.get("started_at"),
        "completed_at": worker.get("completed_at"),
        "schedule_ref": scheduler.get("schedule_ref"),
        "lease_ref": scheduler.get("lease_ref"),
        "checkpoint_ref": scheduler.get("checkpoint_ref"),
        "checkpoint_hash": scheduler.get("checkpoint_hash"),
        "queue_ref": execution.get("queue_ref"),
        "queue_message_ref": execution.get("queue_message_ref"),
        "job_ref": execution.get("job_ref"),
        "job_hash": execution.get("job_hash"),
        "artifact_manifest_hash": execution.get("artifact_manifest_hash"),
        "result_bundle_hash": execution.get("result_bundle_hash"),
        "isolation_audit_root": execution.get("isolation_audit_root"),
        "runtime_audit_root": execution.get("runtime_audit_root"),
        "request_hash": execution.get("request_hash"),
        "response_status": execution.get("response_status"),
        "response_hash": execution.get("response_hash"),
        "audit_log_root": observability.get("audit_log_root"),
    }


def _source_artifacts(
    service_attestation: dict[str, Any],
    worker_receipts: list[dict[str, Any]],
    isolation_attestation: dict[str, Any] | None,
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    artifacts = [_artifact("reexecution-runner-service-attestation", service_attestation, "attestation_id")]
    if isolation_attestation is not None:
        artifacts.append(_artifact("reexecution-isolation-attestation", isolation_attestation, "attestation_id"))
    if runner_evidence is not None:
        artifacts.append(_artifact("reexecution-runner-evidence", runner_evidence, "evidence_id"))
    if policy is not None:
        artifacts.append(_artifact("reexecution-policy", policy, "policy_id"))
    if report is not None:
        artifacts.append(_artifact("reexecution-report", report, "report_id"))
    for receipt in worker_receipts:
        artifacts.append(_artifact("reexecution-runner-worker", receipt, "worker_operation_id"))
    return artifacts


def _artifact(kind: str, value: dict[str, Any], id_key: str) -> dict[str, Any]:
    return {"type": kind, "id": value.get(id_key), "hash": content_hash(value)}


def _verify_source_binding(
    binding: Any,
    service_attestation: dict[str, Any] | None,
    worker_receipts: list[dict[str, Any]] | None,
    isolation_attestation: dict[str, Any] | None,
    runner_evidence: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    report: dict[str, Any] | None,
    errors: list[str],
    warnings: list[str],
    *,
    key: str | None,
) -> None:
    if not isinstance(binding, dict):
        errors.append("re-execution runner authority source_binding is required")
        return
    _verify_binding_completeness(binding, errors)
    if service_attestation is None:
        warnings.append("re-execution runner authority service source not supplied; source binding hashes were not replayed")
        return
    service_result = verify_reexecution_runner_service_attestation(
        service_attestation,
        isolation_attestation,
        runner_evidence=runner_evidence,
        policy=policy,
        report=report,
        key=key,
    )
    errors.extend(f"re-execution runner authority service source: {error}" for error in service_result.errors)
    warnings.extend(f"re-execution runner authority service source: {warning}" for warning in service_result.warnings)
    workers = list(worker_receipts or [])
    if worker_receipts is None:
        warnings.append("re-execution runner authority worker receipts not supplied; worker binding hashes were not replayed")
    for receipt in workers:
        worker_result = verify_reexecution_runner_worker_receipt(
            receipt,
            service_attestation=service_attestation,
            isolation_attestation=isolation_attestation,
            runner_evidence=runner_evidence,
            policy=policy,
            report=report,
            key=key,
        )
        errors.extend(f"re-execution runner authority worker source: {error}" for error in worker_result.errors)
        warnings.extend(f"re-execution runner authority worker source: {warning}" for warning in worker_result.warnings)
    expected = _source_binding(service_attestation, workers, isolation_attestation, runner_evidence, policy, report)
    if binding != expected:
        errors.append("re-execution runner authority source_binding does not match supplied source artifacts")


def _verify_binding_completeness(binding: dict[str, Any], errors: list[str]) -> None:
    for field in (
        "service_attestation_id",
        "service_attestation_hash",
        "service_schema",
        "service_mode",
        "environment",
        "attested_at",
        "service_ref",
        "runner_image_digest",
        "runner_binary_hash",
        "scheduler_ref",
        "queue_ref",
        "dead_letter_queue_ref",
        "lease_store_ref",
        "checkpoint_store_ref",
        "source_isolation_attestation_id",
        "source_runner_evidence_id",
        "source_policy_hash",
        "source_report_id",
        "source_network_mode",
        "source_read_only_rootfs",
        "isolation_profile_ref",
        "admission_policy_ref",
        "tenant_isolation_ref",
        "network_policy_ref",
        "egress_policy_ref",
        "artifact_store_ref",
        "result_store_ref",
        "secret_store_ref",
        "kms_key_ref",
        "audit_log_root",
        "retention_until",
    ):
        _require_binding_field(binding, f"source_binding.{field}", errors)
    _require_positive_binding_count(binding, "source_binding.replicas_min", errors)
    _require_positive_binding_count(binding, "source_binding.replicas_max", errors)
    if (
        isinstance(binding.get("replicas_min"), int)
        and isinstance(binding.get("replicas_max"), int)
        and binding["replicas_max"] < binding["replicas_min"]
    ):
        errors.append("re-execution runner authority source_binding.replicas_max must be greater than or equal to replicas_min")
    _require_binding_field(binding, "source_binding.availability_zones", errors)
    _require_nonnegative_binding_count(binding, "source_binding.worker_count", errors)
    worker_count = binding.get("worker_count")
    if isinstance(worker_count, int) and worker_count > 0:
        _require_binding_field(binding, "source_binding.worker_operation_ids", errors)
        _require_binding_field(binding, "source_binding.worker_operation_hashes", errors)
        _require_binding_field(binding, "source_binding.first_worker_started_at", errors)
        _require_binding_field(binding, "source_binding.last_worker_completed_at", errors)

    source_artifacts = binding.get("source_artifacts")
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("re-execution runner authority source_binding.source_artifacts is required")
    else:
        for index, artifact in enumerate(source_artifacts):
            if not isinstance(artifact, dict):
                errors.append(f"re-execution runner authority source_binding.source_artifacts[{index}] must be an object")
                continue
            for field in ("type", "hash"):
                _require_binding_field(artifact, f"source_binding.source_artifacts[{index}].{field}", errors)

    records = binding.get("worker_operation_records")
    if isinstance(worker_count, int) and worker_count > 0:
        if not isinstance(records, list) or not records:
            errors.append("re-execution runner authority source_binding.worker_operation_records is required")
            return
    elif records is None:
        records = []
    elif not isinstance(records, list):
        errors.append("re-execution runner authority source_binding.worker_operation_records must be a list")
        return
    if isinstance(worker_count, int) and len(records) != worker_count:
        errors.append("re-execution runner authority source_binding.worker_operation_records must match worker_count")
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"re-execution runner authority source_binding.worker_operation_records[{index}] must be an object")
            continue
        for field in (
            "worker_operation_id",
            "worker_operation_hash",
            "mode",
            "environment",
            "worker_ref",
            "run_ref",
            "operation_kind",
            "success",
            "started_at",
            "completed_at",
            "schedule_ref",
            "lease_ref",
            "checkpoint_ref",
            "checkpoint_hash",
            "queue_ref",
            "queue_message_ref",
            "job_ref",
            "job_hash",
            "artifact_manifest_hash",
            "result_bundle_hash",
            "isolation_audit_root",
            "runtime_audit_root",
            "request_hash",
            "response_status",
            "response_hash",
            "audit_log_root",
        ):
            _require_binding_field(record, f"source_binding.worker_operation_records[{index}].{field}", errors)


def _require_binding_field(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if value is None or value == "" or value == [] or value == {}:
        errors.append(f"re-execution runner authority {path} is required")


def _require_positive_binding_count(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if not isinstance(value, int) or value <= 0:
        errors.append(f"re-execution runner authority {path} is required")


def _require_nonnegative_binding_count(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if not isinstance(value, int) or value < 0:
        errors.append(f"re-execution runner authority {path} is required")


def _source_binding_complete(binding: dict[str, Any]) -> bool:
    errors: list[str] = []
    _verify_binding_completeness(binding, errors)
    return not errors and int(binding.get("worker_count") or 0) > 0


def _build_authority_evidence_item(item: dict[str, Any], source_context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported re-execution runner authority requirement: {requirement_id}")
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in requirement["authority_kinds"]:
        raise ValueError(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    built = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description,
    }
    for field in ("issuer", "subject", "source_uri", "issued_at", "expires_at"):
        if item.get(field):
            built[field] = str(item[field])
    for field in ("issued_at", "expires_at"):
        if built.get(field):
            parse_rfc3339(str(built[field]))
    if built.get("issued_at") and built.get("expires_at") and parse_rfc3339(str(built["issued_at"])) > parse_rfc3339(str(built["expires_at"])):
        raise ValueError("authority evidence issued_at must not be after expires_at")
    built["source_context"] = source_context
    built["evidence_id"] = content_hash(built)
    return built


def _verify_authority_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now,
    require_fresh: bool,
    source_context: dict[str, Any],
) -> str:
    try:
        expected = _build_authority_evidence_item(item, source_context)
    except ValueError as exc:
        errors.append(f"invalid re-execution runner authority evidence: {exc}")
        return "missing"
    requirement_id = item.get("requirement_id")
    if item != expected:
        errors.append(f"re-execution runner authority evidence_id does not match evidence body: {requirement_id}")
    if not isinstance(item.get("source_context"), dict):
        errors.append(f"re-execution runner authority source_context is required: {requirement_id}")
    elif item.get("source_context") != source_context:
        errors.append(f"re-execution runner authority source_context does not match source binding: {requirement_id}")
    issued_at = item.get("issued_at")
    expires_at = item.get("expires_at")
    if not issued_at or not expires_at:
        if require_fresh:
            errors.append(f"re-execution runner authority evidence {item.get('requirement_id')} freshness metadata missing")
        return "missing"
    issued = parse_rfc3339(str(issued_at))
    expires = parse_rfc3339(str(expires_at))
    if issued > expires:
        errors.append(f"re-execution runner authority evidence {item.get('requirement_id')} issued_at is after expires_at")
        return "stale"
    if now < issued or now > expires:
        message = f"re-execution runner authority evidence {item.get('requirement_id')} is outside its freshness window"
        if require_fresh:
            errors.append(message)
        else:
            warnings.append(message)
        return "stale"
    return "fresh"


def _authority_evidence_source_context(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_binding_hash": content_hash(binding),
        "service_attestation_id": binding.get("service_attestation_id"),
        "service_attestation_hash": binding.get("service_attestation_hash"),
        "service_mode": binding.get("service_mode"),
        "environment": binding.get("environment"),
        "attested_at": binding.get("attested_at"),
        "service_ref": binding.get("service_ref"),
        "runner_image_digest": binding.get("runner_image_digest"),
        "runner_binary_hash": binding.get("runner_binary_hash"),
        "replicas_min": binding.get("replicas_min"),
        "replicas_max": binding.get("replicas_max"),
        "availability_zones": binding.get("availability_zones"),
        "scheduler_ref": binding.get("scheduler_ref"),
        "queue_ref": binding.get("queue_ref"),
        "dead_letter_queue_ref": binding.get("dead_letter_queue_ref"),
        "lease_store_ref": binding.get("lease_store_ref"),
        "checkpoint_store_ref": binding.get("checkpoint_store_ref"),
        "source_isolation_attestation_id": binding.get("source_isolation_attestation_id"),
        "source_runner_evidence_id": binding.get("source_runner_evidence_id"),
        "source_policy_hash": binding.get("source_policy_hash"),
        "source_report_id": binding.get("source_report_id"),
        "source_network_mode": binding.get("source_network_mode"),
        "source_read_only_rootfs": binding.get("source_read_only_rootfs"),
        "isolation_profile_ref": binding.get("isolation_profile_ref"),
        "admission_policy_ref": binding.get("admission_policy_ref"),
        "tenant_isolation_ref": binding.get("tenant_isolation_ref"),
        "network_policy_ref": binding.get("network_policy_ref"),
        "egress_policy_ref": binding.get("egress_policy_ref"),
        "artifact_store_ref": binding.get("artifact_store_ref"),
        "result_store_ref": binding.get("result_store_ref"),
        "secret_store_ref": binding.get("secret_store_ref"),
        "kms_key_ref": binding.get("kms_key_ref"),
        "audit_log_root": binding.get("audit_log_root"),
        "retention_until": binding.get("retention_until"),
        "worker_count": binding.get("worker_count"),
        "worker_operation_ids": binding.get("worker_operation_ids"),
        "worker_operation_hashes": binding.get("worker_operation_hashes"),
        "first_worker_started_at": binding.get("first_worker_started_at"),
        "last_worker_completed_at": binding.get("last_worker_completed_at"),
        "worker_operation_record_root": content_hash(binding.get("worker_operation_records") or []),
        "source_artifact_root": content_hash(binding.get("source_artifacts") or []),
    }


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("re-execution runner authority required_production_authority does not match the required checklist")


def _summary(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({item.get("requirement_id") for item in evidence_items if item.get("requirement_id")})
    missing = [req_id for req_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if req_id not in covered]
    return {
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
        "authority_evidence_count": len(evidence_items),
    }


def _controls(mode: str, binding: dict[str, Any], evidence_items: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    freshness = _freshness_summary(evidence_items)
    missing = summary.get("missing_requirement_count", 0)
    worker_count = int(binding.get("worker_count") or 0)
    service_bound = bool(binding.get("service_attestation_hash") and binding.get("service_ref") and binding.get("runner_image_digest"))
    production_ready = mode == "production-dossier" and _source_binding_complete(binding) and not missing and freshness["missing"] == 0
    return [
        {
            "id": "runner-service-attestation-bound",
            "status": "passed" if service_bound else "failed",
            "detail": "Dossier binds the verified re-execution runner service attestation, runner image digest, binary hash, scheduler, queue, isolation, and audit roots.",
        },
        {
            "id": "runner-worker-operations-bound",
            "status": "passed" if worker_count > 0 and binding.get("worker_operation_hashes") else "deferred",
            "detail": f"{worker_count} runner worker receipts are hash-bound to the service source.",
        },
        {
            "id": "authority-evidence-checklist-covered",
            "status": "passed" if not missing else "deferred",
            "detail": f"{summary.get('covered_requirement_count', 0)}/{summary.get('required_requirement_count', 0)} runner production authority categories are covered.",
        },
        {
            "id": "freshness-windows-tracked",
            "status": "passed" if evidence_items and freshness["missing"] == 0 else "deferred",
            "detail": f"windowed={freshness['windowed']} missing_freshness={freshness['missing']}",
        },
        {
            "id": "production-mode-gated",
            "status": "passed" if production_ready else "deferred",
            "detail": "Production runner isolation is claimed only when service, worker, and every authority category are covered with timestamped evidence windows.",
        },
        {
            "id": "raw-secret-exclusion",
            "status": "passed",
            "detail": "Dossier stores redacted references, hashes, and roots instead of raw runner credentials or provider tokens.",
        },
    ]


def _freshness_summary(evidence_items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"windowed": 0, "missing": 0}
    for item in evidence_items:
        if item.get("issued_at") and item.get("expires_at"):
            counts["windowed"] += 1
        else:
            counts["missing"] += 1
    return counts


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]):
    value = now or dossier.get("generated_at") or utc_now()
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"freshness reference time invalid: {exc}")
        return parse_rfc3339(utc_now())


def _status_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return summary


def _binding_environment(binding: dict[str, Any]) -> str | None:
    value = binding.get("environment") if isinstance(binding, dict) else None
    return str(value) if value else None


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            nested_path = f"{path}.{key_text}"
            if any(marker in key_text.lower() for marker in SECRET_KEY_MARKERS) and not _allowed_secret_reference_key(key_text):
                if isinstance(nested, str) and not _is_redacted_reference(nested):
                    errors.append(f"raw secret-like value is not allowed at {nested_path}")
            _check_no_secret_values(nested, errors, nested_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _check_no_secret_values(nested, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str) -> bool:
    lowered = key.lower()
    return lowered.endswith(("_ref", "_hash", "_root", "_id")) or lowered in {"credential-custody-and-kms"}


def _is_redacted_reference(value: str) -> bool:
    return value.startswith(("env:", "vault:", "kms:", "secret-ref:", "sha256:", "hash:"))


def _require_text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
