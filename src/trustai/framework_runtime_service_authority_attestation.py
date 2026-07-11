from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_service_authority import (
    PRODUCTION_AUTHORITY_REQUIREMENT_IDS,
    verify_framework_runtime_service_authority_dossier,
)
from .framework_runtime_service_authority_provider import verify_framework_runtime_service_authority_provider_receipt

FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_SCHEMA = "trustai.framework-runtime-service-authority-attestation/0.1"
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_ENTRY_TYPE = "framework_runtime.service_authority_attested"
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_MODES = {
    "local-attestation",
    "provider-attestation",
    "production-attestation",
}
AUTHORITY_ATTESTATION_EVIDENCE_KINDS = {
    "authority-review",
    "provider-export",
    "audit-log",
    "operator-approval",
    "external-authority",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
AUTHORITY_PROVIDER_BINDING_EXPECTED_FIELDS = (
    "provider_receipt_id",
    "provider_receipt_hash",
    "provider_schema",
    "provider_mode",
    "provider",
    "environment",
    "exported_at",
    "worker_operation_id",
    "worker_operation_hash",
    "dossier_id",
    "dossier_hash",
    "authority_ref",
    "service_worker_operation_id",
    "run_ref",
    "authority_request_ref",
    "authority_evidence_root",
    "missing_requirement_root",
    "provider_export_hash",
    "scheduler_record_root",
    "queue_record_root",
    "request_record_root",
    "storage_record_root",
    "audit_record_root",
    "audit_log_root",
    "provider_exchange",
)
AUTHORITY_PROVIDER_BINDING_REQUIRED_FIELDS = AUTHORITY_PROVIDER_BINDING_EXPECTED_FIELDS
AUTHORITY_PROVIDER_EXCHANGE_EXPECTED_FIELDS = (
    "endpoint_url",
    "request_hash",
    "response_status",
    "response_hash",
    "success",
    "actor_ref",
)
AUTHORITY_DOSSIER_BINDING_EXPECTED_FIELDS = (
    "dossier_id",
    "dossier_hash",
    "schema",
    "mode",
    "environment",
    "generated_at",
    "dossier_ref",
    "authority_ref",
    "producer_ref",
    "provider_receipt_id",
    "summary",
)
AUTHORITY_DOSSIER_BINDING_REQUIRED_FIELDS = AUTHORITY_DOSSIER_BINDING_EXPECTED_FIELDS
AUTHORITY_DOSSIER_SUMMARY_EXPECTED_FIELDS = (
    "status",
    "required_requirement_count",
    "covered_requirement_count",
    "missing_requirement_count",
    "evidence_count",
    "covered_requirement_ids",
    "missing_requirement_ids",
)
AUTHORITY_DOSSIER_SUMMARY_COUNT_FIELDS = (
    "required_requirement_count",
    "covered_requirement_count",
    "missing_requirement_count",
    "evidence_count",
)
AUTHORITY_DOSSIER_SUMMARY_LIST_FIELDS = ("covered_requirement_ids", "missing_requirement_ids")


@dataclass
class FrameworkRuntimeServiceAuthorityAttestationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    evidence_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_framework_runtime_service_authority_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service authority attestation must contain an object")
    return value


def write_framework_runtime_service_authority_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def load_framework_runtime_service_authority_attestation_evidence(path: str | Path) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(value, dict):
        value = value.get("attestation_evidence") or value.get("evidence")
    if not isinstance(value, list):
        raise ValueError("framework runtime service authority attestation evidence must contain a list")
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("framework runtime service authority attestation evidence items must be objects")
    return value


def parse_framework_runtime_service_authority_attestation_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 3)
    if len(parts) != 4:
        raise ValueError(
            "attestation evidence must be evidence_kind,evidence_ref,evidence_hash,description[;key=value...]"
        )
    evidence_kind, evidence_ref, evidence_hash, description = [part.strip() for part in parts]
    description_parts = [part.strip() for part in description.split(";")]
    metadata: dict[str, Any] = {}
    allowed_metadata = {"issuer", "subject", "source_uri", "issued_at", "expires_at"}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("attestation evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in allowed_metadata:
            raise ValueError(f"unsupported attestation evidence metadata key: {key}")
        metadata[key] = metadata_value
    return {
        "evidence_kind": evidence_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description_parts[0],
        **metadata,
    }


def build_framework_runtime_service_authority_attestation(
    authority_provider_receipt: dict[str, Any],
    *,
    authority_provider_export: dict[str, Any],
    authority_worker: dict[str, Any],
    authority_dossier: dict[str, Any],
    service_provider_receipt: dict[str, Any],
    service_provider_export: dict[str, Any],
    service_worker: dict[str, Any],
    service_attestation: dict[str, Any],
    storage_receipt: dict[str, Any],
    storage_export: dict[str, Any],
    worker: dict[str, Any],
    runtime_audit: dict[str, Any],
    audit_export: dict[str, Any],
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    root: str | Path = ".",
    mode: str = "provider-attestation",
    environment: str = "local",
    issuer: str,
    subject_ref: str,
    attester_ref: str,
    statement_ref: str,
    credential_ref: str,
    attestation_evidence: list[dict[str, Any]] | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_MODES)}")
    for value, field in (
        (environment, "environment"),
        (issuer, "issuer"),
        (subject_ref, "subject_ref"),
        (attester_ref, "attester_ref"),
        (statement_ref, "statement_ref"),
        (credential_ref, "credential_ref"),
    ):
        _require_text(value, field)
    issued = issued_at or utc_now()
    parse_rfc3339(issued)
    if expires_at:
        _validate_expiry(issued, expires_at)

    provider_result = verify_framework_runtime_service_authority_provider_receipt(
        authority_provider_receipt,
        authority_provider_export=authority_provider_export,
        authority_worker=authority_worker,
        authority_dossier=authority_dossier,
        service_provider_receipt=service_provider_receipt,
        service_provider_export=service_provider_export,
        service_worker=service_worker,
        service_attestation=service_attestation,
        storage_receipt=storage_receipt,
        storage_export=storage_export,
        worker=worker,
        runtime_audit=runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
    )
    if not provider_result.ok:
        raise ValueError("invalid framework runtime service authority provider source: " + "; ".join(provider_result.errors))

    dossier_result = verify_framework_runtime_service_authority_dossier(
        authority_dossier,
        provider_receipt=service_provider_receipt,
        provider_export=service_provider_export,
        service_worker=service_worker,
        service_attestation=service_attestation,
        storage_receipt=storage_receipt,
        storage_export=storage_export,
        worker=worker,
        runtime_audit=runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=issued,
    )
    if not dossier_result.ok:
        raise ValueError("invalid framework runtime service authority dossier source: " + "; ".join(dossier_result.errors))

    evidence = [_build_attestation_evidence_item(item) for item in (attestation_evidence or [])]
    evidence_summary = _evidence_summary(evidence)
    authority_summary = authority_dossier.get("summary", {}) if isinstance(authority_dossier.get("summary"), dict) else {}
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_SCHEMA,
        "mode": mode,
        "environment": environment,
        "issued_at": issued,
        "expires_at": expires_at,
        "issuer": issuer,
        "subject_ref": subject_ref,
        "attester": {
            "attester_ref": attester_ref,
            "statement_ref": statement_ref,
            "credential": _redacted_ref(credential_ref),
        },
        "authority_provider_binding": _authority_provider_binding(authority_provider_receipt),
        "authority_dossier_binding": _authority_dossier_binding(authority_dossier),
        "attestation_evidence": evidence,
        "summary": {
            "authority_status": authority_summary.get("status"),
            "required_requirement_count": authority_summary.get("required_requirement_count"),
            "covered_requirement_count": authority_summary.get("covered_requirement_count"),
            "missing_requirement_count": authority_summary.get("missing_requirement_count"),
            "missing_requirement_ids": authority_summary.get("missing_requirement_ids", []),
            "attestation_evidence": evidence_summary,
        },
        "require_complete": require_complete,
        "require_fresh": require_fresh,
        "controls": _controls(mode, authority_provider_receipt, authority_summary, evidence_summary),
        "limitations": [
            "This attestation binds a verified framework runtime service authority provider export receipt to a signed authority statement.",
            "It records authority evidence hashes, freshness windows, provider export roots, and dossier coverage summaries without storing raw provider credentials.",
            "It does not claim continuously operated production infrastructure unless mode is production-attestation, the provider export is production-export, and every production authority requirement is fresh and covered.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [
            sign_value(
                {"attestation_id": attestation_id, "framework_runtime_service_authority_attestation": body},
                key,
            )
        ],
    }


def verify_framework_runtime_service_authority_attestation(
    attestation: dict[str, Any],
    *,
    authority_provider_receipt: dict[str, Any] | None = None,
    authority_provider_export: dict[str, Any] | None = None,
    authority_worker: dict[str, Any] | None = None,
    authority_dossier: dict[str, Any] | None = None,
    service_provider_receipt: dict[str, Any] | None = None,
    service_provider_export: dict[str, Any] | None = None,
    service_worker: dict[str, Any] | None = None,
    service_attestation: dict[str, Any] | None = None,
    storage_receipt: dict[str, Any] | None = None,
    storage_export: dict[str, Any] | None = None,
    worker: dict[str, Any] | None = None,
    runtime_audit: dict[str, Any] | None = None,
    audit_export: dict[str, Any] | None = None,
    operation: dict[str, Any] | None = None,
    trace_payload: dict[str, Any] | None = None,
    release: dict[str, Any] | None = None,
    matrix: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> FrameworkRuntimeServiceAuthorityAttestationVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(attestation, now, errors)

    if attestation.get("schema") != FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_SCHEMA:
        errors.append(f"unsupported framework runtime service authority attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical framework runtime service authority attestation body")
    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service authority attestation must include at least one signature")
    else:
        signed_value = {
            "attestation_id": attestation.get("attestation_id"),
            "framework_runtime_service_authority_attestation": body,
        }
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service authority attestation signature verification failed")

    mode = attestation.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_MODES:
        errors.append("framework runtime service authority attestation mode is unsupported")
    elif mode != "production-attestation":
        warnings.append(f"framework runtime service authority attestation mode is {mode}; live production authority is not claimed")
    _verify_times(attestation, freshness_now, errors)
    for field in ("environment", "issuer", "subject_ref"):
        if not attestation.get(field):
            errors.append(f"framework runtime service authority attestation {field} is required")
    _verify_attester(attestation.get("attester"), errors)
    _verify_provider_binding(
        attestation.get("authority_provider_binding"),
        authority_provider_receipt,
        authority_provider_export,
        authority_worker,
        authority_dossier,
        service_provider_receipt,
        service_provider_export,
        service_worker,
        service_attestation,
        storage_receipt,
        storage_export,
        worker,
        runtime_audit,
        audit_export,
        operation,
        trace_payload,
        release,
        matrix,
        root,
        key,
        errors,
        warnings,
    )
    _verify_dossier_binding(
        attestation.get("authority_dossier_binding"),
        authority_dossier,
        service_provider_receipt,
        service_provider_export,
        service_worker,
        service_attestation,
        storage_receipt,
        storage_export,
        worker,
        runtime_audit,
        audit_export,
        operation,
        trace_payload,
        release,
        matrix,
        root,
        key,
        require_complete or bool(attestation.get("require_complete")),
        require_fresh or bool(attestation.get("require_fresh")),
        freshness_now,
        errors,
        warnings,
    )
    evidence = attestation.get("attestation_evidence", [])
    if not isinstance(evidence, list):
        errors.append("framework runtime service authority attestation_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("framework runtime service authority attestation evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_status = _verify_attestation_evidence_item(
            item,
            errors,
            warnings,
            now=freshness_now,
            require_fresh=require_fresh or bool(attestation.get("require_fresh")),
        )
        freshness_counts[freshness_status] += 1

    expected_summary = _expected_summary(attestation, [item for item in evidence if isinstance(item, dict)])
    if attestation.get("summary") != expected_summary:
        errors.append("framework runtime service authority attestation summary does not match authority or attestation evidence")
    _verify_production_claim(attestation, errors)
    if not isinstance(attestation.get("controls"), list) or not attestation.get("controls"):
        errors.append("framework runtime service authority attestation controls are required")
    _check_no_secret_values(attestation, errors)
    return FrameworkRuntimeServiceAuthorityAttestationVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        evidence_count=len(evidence),
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_framework_runtime_service_authority_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    *,
    authority_provider_receipt: dict[str, Any],
    authority_provider_export: dict[str, Any],
    authority_worker: dict[str, Any],
    authority_dossier: dict[str, Any],
    service_provider_receipt: dict[str, Any],
    service_provider_export: dict[str, Any],
    service_worker: dict[str, Any],
    service_attestation: dict[str, Any],
    storage_receipt: dict[str, Any],
    storage_export: dict[str, Any],
    worker: dict[str, Any],
    runtime_audit: dict[str, Any],
    audit_export: dict[str, Any],
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_runtime_service_authority_attestation(
        attestation,
        authority_provider_receipt=authority_provider_receipt,
        authority_provider_export=authority_provider_export,
        authority_worker=authority_worker,
        authority_dossier=authority_dossier,
        service_provider_receipt=service_provider_receipt,
        service_provider_export=service_provider_export,
        service_worker=service_worker,
        service_attestation=service_attestation,
        storage_receipt=storage_receipt,
        storage_export=storage_export,
        worker=worker,
        runtime_audit=runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid framework runtime service authority attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "issued_at": attestation.get("issued_at"),
        "expires_at": attestation.get("expires_at"),
        "issuer": attestation.get("issuer"),
        "subject_ref": attestation.get("subject_ref"),
        "attester": attestation.get("attester"),
        "authority_provider_binding": attestation.get("authority_provider_binding"),
        "authority_dossier_binding": attestation.get("authority_dossier_binding"),
        "summary": attestation.get("summary"),
        "attestation_evidence": [
            {
                "evidence_kind": item.get("evidence_kind"),
                "evidence_ref": item.get("evidence_ref"),
                "evidence_hash": item.get("evidence_hash"),
                "evidence_id": item.get("evidence_id"),
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
            }
            for item in attestation.get("attestation_evidence", [])
            if isinstance(item, dict)
        ],
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(
        FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=attestation.get("issued_at"),
    )


def _authority_provider_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    worker = receipt.get("authority_worker_binding", {}) if isinstance(receipt.get("authority_worker_binding"), dict) else {}
    provider_export = receipt.get("provider_export", {}) if isinstance(receipt.get("provider_export"), dict) else {}
    return {
        "provider_receipt_id": receipt.get("provider_receipt_id"),
        "provider_receipt_hash": content_hash(receipt),
        "provider_schema": receipt.get("schema"),
        "provider_mode": receipt.get("mode"),
        "provider": receipt.get("provider"),
        "environment": receipt.get("environment"),
        "exported_at": receipt.get("exported_at"),
        "worker_operation_id": worker.get("worker_operation_id"),
        "worker_operation_hash": worker.get("worker_operation_hash"),
        "dossier_id": worker.get("dossier_id"),
        "dossier_hash": worker.get("dossier_hash"),
        "authority_ref": worker.get("authority_ref"),
        "service_worker_operation_id": worker.get("service_worker_operation_id"),
        "run_ref": worker.get("run_ref"),
        "authority_request_ref": worker.get("authority_request_ref"),
        "authority_evidence_root": worker.get("authority_evidence_root"),
        "missing_requirement_root": worker.get("missing_requirement_root"),
        "provider_export_hash": provider_export.get("hash"),
        "scheduler_record_root": provider_export.get("scheduler_record_root"),
        "queue_record_root": provider_export.get("queue_record_root"),
        "request_record_root": provider_export.get("request_record_root"),
        "storage_record_root": provider_export.get("storage_record_root"),
        "audit_record_root": provider_export.get("audit_record_root"),
        "audit_log_root": provider_export.get("audit_log_root"),
        "provider_exchange": receipt.get("provider_exchange"),
    }


def _authority_dossier_binding(dossier: dict[str, Any]) -> dict[str, Any]:
    summary = dossier.get("summary", {}) if isinstance(dossier.get("summary"), dict) else {}
    return {
        "dossier_id": dossier.get("dossier_id"),
        "dossier_hash": content_hash(dossier),
        "schema": dossier.get("schema"),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "provider_receipt_id": (dossier.get("provider_receipt_binding") or {}).get("provider_receipt_id")
        if isinstance(dossier.get("provider_receipt_binding"), dict)
        else None,
        "summary": {
            "status": summary.get("status"),
            "required_requirement_count": summary.get("required_requirement_count"),
            "covered_requirement_count": summary.get("covered_requirement_count"),
            "missing_requirement_count": summary.get("missing_requirement_count"),
            "evidence_count": summary.get("evidence_count"),
            "covered_requirement_ids": summary.get("covered_requirement_ids", []),
            "missing_requirement_ids": summary.get("missing_requirement_ids", []),
        },
    }


def _require_binding_fields(
    binding: dict[str, Any],
    expected_fields: tuple[str, ...],
    required_fields: tuple[str, ...],
    prefix: str,
    errors: list[str],
) -> None:
    for field in expected_fields:
        if field not in binding:
            errors.append(f"{prefix}.{field} is required")
    for field in required_fields:
        if binding.get(field) in (None, "", []):
            errors.append(f"{prefix}.{field} is required")


def _verify_provider_exchange_binding(value: Any, errors: list[str]) -> None:
    prefix = "framework runtime service authority attestation authority_provider_binding.provider_exchange"
    if not isinstance(value, dict):
        errors.append(f"{prefix} is required")
        return
    for field in AUTHORITY_PROVIDER_EXCHANGE_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"{prefix}.{field} is required")
    for field in ("endpoint_url", "request_hash", "response_hash", "actor_ref"):
        if value.get(field) in (None, "", []):
            errors.append(f"{prefix}.{field} is required")
    status = value.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append(f"{prefix}.response_status must be an HTTP status code")
    if not isinstance(value.get("success"), bool):
        errors.append(f"{prefix}.success is required")


def _verify_dossier_summary_binding(value: Any, errors: list[str]) -> None:
    prefix = "framework runtime service authority attestation authority_dossier_binding.summary"
    if not isinstance(value, dict):
        errors.append(f"{prefix} must be an object")
        return
    for field in AUTHORITY_DOSSIER_SUMMARY_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"{prefix}.{field} is required")
    if value.get("status") in (None, "", []):
        errors.append(f"{prefix}.status is required")
    for field in AUTHORITY_DOSSIER_SUMMARY_COUNT_FIELDS:
        if not isinstance(value.get(field), int) or value.get(field) < 0:
            errors.append(f"{prefix}.{field} must be a nonnegative integer")
    for field in AUTHORITY_DOSSIER_SUMMARY_LIST_FIELDS:
        if field not in value:
            continue
        if not isinstance(value.get(field), list):
            errors.append(f"{prefix}.{field} must be a list")


def _verify_provider_binding(
    binding: Any,
    authority_provider_receipt: dict[str, Any] | None,
    authority_provider_export: dict[str, Any] | None,
    authority_worker: dict[str, Any] | None,
    authority_dossier: dict[str, Any] | None,
    service_provider_receipt: dict[str, Any] | None,
    service_provider_export: dict[str, Any] | None,
    service_worker: dict[str, Any] | None,
    service_attestation: dict[str, Any] | None,
    storage_receipt: dict[str, Any] | None,
    storage_export: dict[str, Any] | None,
    worker: dict[str, Any] | None,
    runtime_audit: dict[str, Any] | None,
    audit_export: dict[str, Any] | None,
    operation: dict[str, Any] | None,
    trace_payload: dict[str, Any] | None,
    release: dict[str, Any] | None,
    matrix: dict[str, Any] | None,
    root: str | Path,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(binding, dict):
        errors.append("framework runtime service authority attestation authority_provider_binding must be an object")
        return
    _require_binding_fields(
        binding,
        AUTHORITY_PROVIDER_BINDING_EXPECTED_FIELDS,
        AUTHORITY_PROVIDER_BINDING_REQUIRED_FIELDS,
        "framework runtime service authority attestation authority_provider_binding",
        errors,
    )
    _verify_provider_exchange_binding(binding.get("provider_exchange"), errors)
    if authority_provider_receipt is None:
        errors.append("framework runtime service authority attestation authority provider receipt is required for verification")
        return
    expected = _authority_provider_binding(authority_provider_receipt)
    if binding != expected:
        errors.append("framework runtime service authority attestation authority_provider_binding does not match supplied authority provider receipt")
    result = verify_framework_runtime_service_authority_provider_receipt(
        authority_provider_receipt,
        authority_provider_export=authority_provider_export,
        authority_worker=authority_worker,
        authority_dossier=authority_dossier,
        service_provider_receipt=service_provider_receipt,
        service_provider_export=service_provider_export,
        service_worker=service_worker,
        service_attestation=service_attestation,
        storage_receipt=storage_receipt,
        storage_export=storage_export,
        worker=worker,
        runtime_audit=runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
    )
    if not result.ok:
        errors.extend(f"framework runtime service authority attestation provider source: {error}" for error in result.errors)
    warnings.extend(f"framework runtime service authority attestation provider source: {warning}" for warning in result.warnings)


def _verify_dossier_binding(
    binding: Any,
    authority_dossier: dict[str, Any] | None,
    service_provider_receipt: dict[str, Any] | None,
    service_provider_export: dict[str, Any] | None,
    service_worker: dict[str, Any] | None,
    service_attestation: dict[str, Any] | None,
    storage_receipt: dict[str, Any] | None,
    storage_export: dict[str, Any] | None,
    worker: dict[str, Any] | None,
    runtime_audit: dict[str, Any] | None,
    audit_export: dict[str, Any] | None,
    operation: dict[str, Any] | None,
    trace_payload: dict[str, Any] | None,
    release: dict[str, Any] | None,
    matrix: dict[str, Any] | None,
    root: str | Path,
    key: str | None,
    require_complete: bool,
    require_fresh: bool,
    now: Any,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(binding, dict):
        errors.append("framework runtime service authority attestation authority_dossier_binding must be an object")
        return
    _require_binding_fields(
        binding,
        AUTHORITY_DOSSIER_BINDING_EXPECTED_FIELDS,
        AUTHORITY_DOSSIER_BINDING_REQUIRED_FIELDS,
        "framework runtime service authority attestation authority_dossier_binding",
        errors,
    )
    _verify_dossier_summary_binding(binding.get("summary"), errors)
    if authority_dossier is None:
        errors.append("framework runtime service authority attestation authority dossier is required for verification")
        return
    expected = _authority_dossier_binding(authority_dossier)
    if binding != expected:
        errors.append("framework runtime service authority attestation authority_dossier_binding does not match supplied authority dossier")
    result = verify_framework_runtime_service_authority_dossier(
        authority_dossier,
        provider_receipt=service_provider_receipt,
        provider_export=service_provider_export,
        service_worker=service_worker,
        service_attestation=service_attestation,
        storage_receipt=storage_receipt,
        storage_export=storage_export,
        worker=worker,
        runtime_audit=runtime_audit,
        audit_export=audit_export,
        operation=operation,
        trace_payload=trace_payload,
        release=release,
        matrix=matrix,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now.isoformat().replace("+00:00", "Z") if hasattr(now, "isoformat") else None,
    )
    if not result.ok:
        errors.extend(f"framework runtime service authority attestation dossier source: {error}" for error in result.errors)
    warnings.extend(f"framework runtime service authority attestation dossier source: {warning}" for warning in result.warnings)


def _build_attestation_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("attestation evidence item must be an object")
    evidence_kind = str(item.get("evidence_kind") or item.get("kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if evidence_kind not in AUTHORITY_ATTESTATION_EVIDENCE_KINDS:
        raise ValueError(f"unsupported authority attestation evidence kind: {evidence_kind}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    _require_hash_ref(evidence_hash, "evidence_hash")
    for field in ("issued_at", "expires_at"):
        if item.get(field):
            parse_rfc3339(str(item[field]))
    body = {
        "evidence_kind": evidence_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description,
        "issuer": item.get("issuer"),
        "subject": item.get("subject"),
        "source_uri": item.get("source_uri"),
        "issued_at": item.get("issued_at"),
        "expires_at": item.get("expires_at"),
    }
    return {**body, "evidence_id": content_hash(body)}


def _verify_attestation_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now: Any,
    require_fresh: bool,
) -> str:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"framework runtime service authority attestation evidence_id does not match evidence body: {item.get('evidence_ref')}")
    if item.get("evidence_kind") not in AUTHORITY_ATTESTATION_EVIDENCE_KINDS:
        errors.append(f"unsupported authority attestation evidence kind: {item.get('evidence_kind')}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"framework runtime service authority attestation {field} is required")
    if item.get("evidence_hash") and not _is_sha256_ref(str(item.get("evidence_hash"))):
        errors.append("framework runtime service authority attestation evidence_hash must be a sha256 reference")
    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(
            f"framework runtime service authority attestation freshness metadata missing for {item.get('evidence_ref')}: {', '.join(missing_fields)}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"framework runtime service authority attestation expires_at must be after issued_at: {item.get('evidence_ref')}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(
            f"framework runtime service authority attestation evidence is not yet issued for {item.get('evidence_ref')}: {item.get('issued_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(
            f"framework runtime service authority attestation evidence expired for {item.get('evidence_ref')}: {item.get('expires_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    return freshness_status


def _evidence_summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    kinds = sorted({str(item.get("evidence_kind")) for item in evidence if item.get("evidence_kind")})
    return {
        "evidence_count": len(evidence),
        "evidence_kinds": kinds,
        "issued_at_count": sum(1 for item in evidence if item.get("issued_at")),
        "expires_at_count": sum(1 for item in evidence if item.get("expires_at")),
        "freshness_window_count": sum(1 for item in evidence if item.get("issued_at") and item.get("expires_at")),
        "evidence_root": content_hash(evidence),
    }


def _expected_summary(attestation: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    dossier_binding = attestation.get("authority_dossier_binding", {})
    dossier_summary = dossier_binding.get("summary", {}) if isinstance(dossier_binding, dict) and isinstance(dossier_binding.get("summary"), dict) else {}
    return {
        "authority_status": dossier_summary.get("status"),
        "required_requirement_count": dossier_summary.get("required_requirement_count"),
        "covered_requirement_count": dossier_summary.get("covered_requirement_count"),
        "missing_requirement_count": dossier_summary.get("missing_requirement_count"),
        "missing_requirement_ids": dossier_summary.get("missing_requirement_ids", []),
        "attestation_evidence": _evidence_summary(evidence),
    }


def _controls(
    mode: str,
    authority_provider_receipt: dict[str, Any],
    authority_summary: dict[str, Any],
    evidence_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    provider_exchange = authority_provider_receipt.get("provider_exchange", {}) if isinstance(authority_provider_receipt, dict) else {}
    missing_count = authority_summary.get("missing_requirement_count")
    evidence_count = evidence_summary.get("evidence_count", 0)
    freshness_count = evidence_summary.get("freshness_window_count", 0)
    return [
        {
            "name": "authority_provider_source_replayed",
            "status": "passed" if authority_provider_receipt.get("provider_receipt_id") else "failed",
            "detail": "The attestation builder replayed the authority provider export receipt and source chain.",
        },
        {
            "name": "authority_dossier_bound",
            "status": "passed" if authority_summary.get("required_requirement_count") == len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS) else "failed",
            "detail": "The attestation binds the authority dossier summary and production-authority requirement set.",
        },
        {
            "name": "authority_claims_reviewed",
            "status": "passed" if authority_summary.get("covered_requirement_count", 0) > 0 else "deferred",
            "detail": "The authority dossier contains at least one hash-bound production authority evidence claim.",
        },
        {
            "name": "attestation_evidence_bound",
            "status": "passed" if evidence_count else "deferred",
            "detail": "Attestation review, provider-export, audit-log, or operator-approval evidence is hash-bound.",
        },
        {
            "name": "attestation_freshness_tracked",
            "status": "passed" if evidence_count and evidence_count == freshness_count else "deferred",
            "detail": "Issued/expires freshness windows are tracked for every attestation evidence item when available.",
        },
        {
            "name": "production_attestation_claim_limited",
            "status": "passed"
            if mode != "production-attestation"
            or (
                authority_provider_receipt.get("mode") == "production-export"
                and provider_exchange.get("success") is True
                and missing_count == 0
                and evidence_count
                and evidence_count == freshness_count
            )
            else "failed",
            "detail": "Production-attestation mode requires production provider export, successful provider exchange, complete authority coverage, and fresh attestation evidence.",
        },
    ]


def _verify_production_claim(attestation: dict[str, Any], errors: list[str]) -> None:
    if attestation.get("mode") != "production-attestation":
        return
    provider_binding = attestation.get("authority_provider_binding", {}) if isinstance(attestation.get("authority_provider_binding"), dict) else {}
    dossier_binding = attestation.get("authority_dossier_binding", {}) if isinstance(attestation.get("authority_dossier_binding"), dict) else {}
    summary = dossier_binding.get("summary", {}) if isinstance(dossier_binding.get("summary"), dict) else {}
    evidence_summary = (attestation.get("summary") or {}).get("attestation_evidence", {}) if isinstance(attestation.get("summary"), dict) else {}
    provider_exchange = provider_binding.get("provider_exchange", {}) if isinstance(provider_binding.get("provider_exchange"), dict) else {}
    if provider_binding.get("provider_mode") != "production-export":
        errors.append("production-attestation mode requires a production-export authority provider receipt")
    if provider_exchange.get("success") is not True:
        errors.append("production-attestation mode requires successful provider exchange evidence")
    if summary.get("missing_requirement_count") != 0:
        errors.append("production-attestation mode requires complete production authority coverage")
    if not evidence_summary.get("evidence_count") or evidence_summary.get("evidence_count") != evidence_summary.get("freshness_window_count"):
        errors.append("production-attestation mode requires fresh attestation evidence windows")


def _verify_attester(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority attestation attester must be an object")
        return
    for field in ("attester_ref", "statement_ref", "credential"):
        if not value.get(field):
            errors.append(f"framework runtime service authority attestation attester.{field} is required")
    _verify_redacted_ref(value.get("credential"), "framework runtime service authority attestation credential", errors)


def _verify_times(attestation: dict[str, Any], now: Any, errors: list[str]) -> None:
    issued = _parse_attestation_time(attestation, "issued_at", errors)
    expires = _parse_attestation_time(attestation, "expires_at", errors)
    if issued is not None and expires is not None and expires <= issued:
        errors.append("framework runtime service authority attestation expires_at must be after issued_at")
    if now is not None and issued is not None and issued > now:
        errors.append("framework runtime service authority attestation issued_at is in the future")
    if now is not None and expires is not None and expires <= now:
        errors.append("framework runtime service authority attestation is expired")


def _freshness_reference(attestation: dict[str, Any], now: str | None, errors: list[str]) -> Any:
    reference = now or attestation.get("issued_at")
    if not reference:
        return None
    try:
        return parse_rfc3339(str(reference))
    except ValueError as exc:
        label = "now" if now else "issued_at"
        errors.append(f"framework runtime service authority attestation freshness {label} invalid: {exc}")
        return None


def _parse_attestation_time(attestation: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = attestation.get(field)
    if not value:
        if field == "issued_at":
            errors.append("framework runtime service authority attestation issued_at is required")
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"framework runtime service authority attestation {field} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"framework runtime service authority attestation {field} invalid: {exc}")
        return None


def _validate_expiry(issued_at: str, expires_at: str) -> None:
    if parse_rfc3339(expires_at) <= parse_rfc3339(issued_at):
        raise ValueError("framework runtime service authority attestation expires_at must be after issued_at")


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _status_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime service authority attestation {field} is required")
    return value


def _require_hash_ref(value: str, field: str) -> None:
    if not _is_sha256_ref(value):
        raise ValueError(f"framework runtime service authority attestation {field} must be a sha256 reference")


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
                    errors.append(f"framework runtime service authority attestation secret-like field must be redacted reference: {child_path}")
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
