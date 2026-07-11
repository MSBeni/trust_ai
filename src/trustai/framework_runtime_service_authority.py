from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .framework_runtime_service_provider import verify_framework_runtime_service_provider_receipt

FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_SCHEMA = "trustai.framework-runtime-service-authority-dossier/0.1"
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ENTRY_TYPE = "framework_runtime.service_authority_dossiered"
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")
PROVIDER_RECEIPT_BINDING_EXPECTED_FIELDS = (
    "provider_receipt_id",
    "provider_receipt_hash",
    "provider_schema",
    "provider_mode",
    "provider",
    "environment",
    "exported_at",
    "service_worker_operation_id",
    "service_worker_operation_hash",
    "service_attestation_id",
    "storage_receipt_id",
    "run_ref",
    "queue_message_ref",
    "stream_message_ref",
    "provider_export_hash",
    "scheduler_record_root",
    "queue_record_root",
    "kms_record_root",
    "stream_record_root",
    "storage_record_root",
    "audit_record_root",
    "audit_log_root",
    "provider_exchange",
)
PROVIDER_RECEIPT_BINDING_REQUIRED_FIELDS = PROVIDER_RECEIPT_BINDING_EXPECTED_FIELDS
PROVIDER_EXCHANGE_BINDING_EXPECTED_FIELDS = (
    "endpoint_url",
    "request_hash",
    "response_status",
    "response_hash",
    "success",
    "actor_ref",
)

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {
        "id": "collector-fleet",
        "title": "Continuously operated collector fleets",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "framework-hooks",
        "title": "Production-native framework hooks and runtime-owned audit exports",
        "authority_kinds": ["provider-api", "hosted-service"],
    },
    {
        "id": "runtime-service-fleet",
        "title": "Continuously operated framework runtime service fleets",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "scheduler-queue-lease",
        "title": "Live scheduler, queue, lease, checkpoint, and cursor provider APIs",
        "authority_kinds": ["provider-api", "hosted-service"],
    },
    {
        "id": "kms-hsm",
        "title": "Live KMS/HSM provider requests, responses, and audit exports",
        "authority_kinds": ["kms-hsm", "provider-api"],
    },
    {
        "id": "stream-storage-database",
        "title": "Live stream, WORM, ClickHouse, Postgres, and control-index exports",
        "authority_kinds": ["provider-api", "cloud-object-lock", "hosted-service"],
    },
    {
        "id": "mcp-proxy-workers",
        "title": "Production MCP proxy workers",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "immutable-audit-logs",
        "title": "Immutable production and provider-owned audit logs",
        "authority_kinds": ["provider-api", "cloud-object-lock", "customer"],
    },
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class FrameworkRuntimeServiceAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_framework_runtime_service_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service authority dossier must contain an object")
    return value


def write_framework_runtime_service_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_framework_runtime_service_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError(
            "authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]"
        )
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


def build_framework_runtime_service_authority_dossier(
    provider_receipt: dict[str, Any],
    *,
    provider_export: dict[str, Any],
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
    mode: str = "provider-dossier",
    environment: str = "local",
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_MODES)}")
    for value, field in (
        (environment, "environment"),
        (dossier_ref, "dossier_ref"),
        (authority_ref, "authority_ref"),
        (producer_ref, "producer_ref"),
    ):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    provider_result = verify_framework_runtime_service_provider_receipt(
        provider_receipt,
        provider_export=provider_export,
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
        raise ValueError("invalid framework runtime service provider source: " + "; ".join(provider_result.errors))

    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment,
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "provider_receipt_binding": _provider_receipt_binding(provider_receipt),
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, provider_receipt, evidence_items, summary),
        "limitations": [
            "This dossier binds a verified framework runtime service provider export receipt to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories; it does not fetch provider APIs itself.",
            "It does not claim continuously operated production infrastructure unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {
        **body,
        "dossier_id": dossier_id,
        "signatures": [sign_value({"dossier_id": dossier_id, "framework_runtime_service_authority": body}, key)],
    }


def verify_framework_runtime_service_authority_dossier(
    dossier: dict[str, Any],
    *,
    provider_receipt: dict[str, Any] | None = None,
    provider_export: dict[str, Any] | None = None,
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
) -> FrameworkRuntimeServiceAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_SCHEMA:
        errors.append(f"unsupported framework runtime service authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    expected_id = content_hash(body)
    if dossier.get("dossier_id") != expected_id:
        errors.append("dossier_id does not match canonical framework runtime service authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "framework_runtime_service_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_MODES:
        errors.append("framework runtime service authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"framework runtime service authority mode is {mode}; live production authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime service authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"framework runtime service authority {field} is required")

    _verify_provider_receipt_binding(
        dossier.get("provider_receipt_binding"),
        provider_receipt,
        provider_export,
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
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("framework runtime service authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("framework runtime service authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_status = _verify_authority_evidence_item(
            item,
            errors,
            warnings,
            now=freshness_now,
            require_fresh=require_fresh,
        )
        freshness_counts[freshness_status] += 1

    expected_summary = _summary([item for item in evidence if isinstance(item, dict)])
    if dossier.get("summary") != expected_summary:
        errors.append("framework runtime service authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("framework runtime service authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("framework runtime service authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every production authority requirement to be covered")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("framework runtime service authority controls are required")
    _check_no_secret_values(dossier, errors)
    return FrameworkRuntimeServiceAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_framework_runtime_service_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    provider_receipt: dict[str, Any],
    provider_export: dict[str, Any],
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
    result = verify_framework_runtime_service_authority_dossier(
        dossier,
        provider_receipt=provider_receipt,
        provider_export=provider_export,
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
        raise ValueError("invalid framework runtime service authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "provider_receipt_binding": dossier.get("provider_receipt_binding"),
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {
                "requirement_id": item.get("requirement_id"),
                "authority_kind": item.get("authority_kind"),
                "evidence_ref": item.get("evidence_ref"),
                "evidence_hash": item.get("evidence_hash"),
                "evidence_id": item.get("evidence_id"),
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
            }
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(
        FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=dossier.get("generated_at"),
    )


def _provider_receipt_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    service = receipt.get("service_worker_binding", {}) if isinstance(receipt.get("service_worker_binding"), dict) else {}
    provider_export = receipt.get("provider_export", {}) if isinstance(receipt.get("provider_export"), dict) else {}
    return {
        "provider_receipt_id": receipt.get("provider_receipt_id"),
        "provider_receipt_hash": content_hash(receipt),
        "provider_schema": receipt.get("schema"),
        "provider_mode": receipt.get("mode"),
        "provider": receipt.get("provider"),
        "environment": receipt.get("environment"),
        "exported_at": receipt.get("exported_at"),
        "service_worker_operation_id": service.get("worker_operation_id"),
        "service_worker_operation_hash": service.get("worker_operation_hash"),
        "service_attestation_id": service.get("service_attestation_id"),
        "storage_receipt_id": service.get("storage_receipt_id"),
        "run_ref": service.get("run_ref"),
        "queue_message_ref": service.get("queue_message_ref"),
        "stream_message_ref": service.get("stream_message_ref"),
        "provider_export_hash": provider_export.get("hash"),
        "scheduler_record_root": provider_export.get("scheduler_record_root"),
        "queue_record_root": provider_export.get("queue_record_root"),
        "kms_record_root": provider_export.get("kms_record_root"),
        "stream_record_root": provider_export.get("stream_record_root"),
        "storage_record_root": provider_export.get("storage_record_root"),
        "audit_record_root": provider_export.get("audit_record_root"),
        "audit_log_root": provider_export.get("audit_log_root"),
        "provider_exchange": receipt.get("provider_exchange"),
    }


def _verify_provider_receipt_binding(
    binding: Any,
    provider_receipt: dict[str, Any] | None,
    provider_export: dict[str, Any] | None,
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
        errors.append("framework runtime service authority provider_receipt_binding must be an object")
        return
    for field in PROVIDER_RECEIPT_BINDING_EXPECTED_FIELDS:
        if field not in binding:
            errors.append(f"framework runtime service authority provider_receipt_binding.{field} is required")
    for field in PROVIDER_RECEIPT_BINDING_REQUIRED_FIELDS:
        if binding.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime service authority provider_receipt_binding.{field} is required")
    _verify_provider_exchange_binding(binding.get("provider_exchange"), errors)
    if provider_receipt is None:
        warnings.append("framework runtime service authority provider receipt was not supplied; provider source was not replayed")
        return
    expected = _provider_receipt_binding(provider_receipt)
    if binding != expected:
        errors.append("framework runtime service authority provider_receipt_binding does not match supplied provider receipt")
    result = verify_framework_runtime_service_provider_receipt(
        provider_receipt,
        provider_export=provider_export,
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
        errors.extend(f"framework runtime service authority provider source: {error}" for error in result.errors)
    warnings.extend(f"framework runtime service authority provider source: {warning}" for warning in result.warnings)


def _verify_provider_exchange_binding(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority provider_receipt_binding.provider_exchange must be an object")
        return
    for field in PROVIDER_EXCHANGE_BINDING_EXPECTED_FIELDS:
        if field not in value:
            errors.append(f"framework runtime service authority provider_receipt_binding.provider_exchange.{field} is required")
        elif value.get(field) in (None, "", [], {}):
            errors.append(f"framework runtime service authority provider_receipt_binding.provider_exchange.{field} is required")
    status = value.get("response_status")
    if not isinstance(status, int) or status < 100 or status > 599:
        errors.append("framework runtime service authority provider_receipt_binding.provider_exchange.response_status must be an HTTP status code")
    for field in ("request_hash", "response_hash"):
        field_value = value.get(field)
        if field_value and not str(field_value).startswith("sha256:"):
            errors.append(f"framework runtime service authority provider_receipt_binding.provider_exchange.{field} must be a sha256 reference")
    if not isinstance(value.get("success"), bool):
        errors.append("framework runtime service authority provider_receipt_binding.provider_exchange.success must be boolean")



def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unknown framework runtime production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in _requirement_authority_kinds(requirement_id):
        raise ValueError(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    _require_hash_ref(evidence_hash, "evidence_hash")
    for field in ("issued_at", "expires_at"):
        if item.get(field):
            parse_rfc3339(str(item[field]))
    body = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
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


def _verify_authority_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now: Any,
    require_fresh: bool,
) -> str:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"framework runtime service authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unknown framework runtime production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS and authority_kind not in _requirement_authority_kinds(str(requirement_id)):
        errors.append(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"framework runtime service authority {field} is required: {requirement_id}")
    if item.get("evidence_hash") and not str(item.get("evidence_hash")).startswith("sha256:"):
        errors.append(f"framework runtime service authority evidence_hash must start with sha256: {requirement_id}")

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(
            f"framework runtime service authority freshness metadata missing for {requirement_id}: {', '.join(missing_fields)}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"framework runtime service authority expires_at must be after issued_at: {requirement_id}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(
            f"framework runtime service authority evidence is not yet issued for {requirement_id}: {item.get('issued_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(
            f"framework runtime service authority evidence expired for {requirement_id}: {item.get('expires_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    return freshness_status


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("framework runtime service authority required_production_authority does not match v0.1 requirements")


def _summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted(
        {
            str(item.get("requirement_id"))
            for item in evidence
            if item.get("requirement_id") in set(PRODUCTION_AUTHORITY_REQUIREMENT_IDS)
        }
    )
    missing = [requirement_id for requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if requirement_id not in covered]
    return {
        "status": "complete" if not missing else "partial",
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "evidence_count": len(evidence),
        "issued_at_count": sum(1 for item in evidence if item.get("issued_at")),
        "expires_at_count": sum(1 for item in evidence if item.get("expires_at")),
        "freshness_window_count": sum(1 for item in evidence if item.get("issued_at") and item.get("expires_at")),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
    }


def _controls(mode: str, provider_receipt: dict[str, Any], evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": "provider_source_replayed",
            "status": "passed",
            "detail": "The dossier builder replayed the framework runtime service provider receipt and its source chain.",
        },
        {
            "name": "provider_receipt_bound",
            "status": "passed" if provider_receipt.get("provider_receipt_id") else "failed",
            "detail": "The dossier binds the provider receipt ID, receipt hash, provider export hash, and record roots.",
        },
        {
            "name": "authority_evidence_manifested",
            "status": "passed" if evidence else "deferred",
            "detail": "External authority evidence references are hash-bound when supplied.",
        },
        {
            "name": "freshness_windows_tracked",
            "status": "passed" if evidence and summary["freshness_window_count"] == len(evidence) else "deferred",
            "detail": "Issued/expires freshness windows are tracked for every supplied authority item when available.",
        },
        {
            "name": "complete_live_authority",
            "status": "passed" if summary["missing_requirement_count"] == 0 else "deferred",
            "detail": "Every production authority requirement must be covered before this can claim production authority.",
        },
        {
            "name": "production_claim_limited",
            "status": "passed" if mode != "production-dossier" or summary["missing_requirement_count"] == 0 else "failed",
            "detail": "Non-production dossier modes explicitly avoid claiming live production operation.",
        },
    ]


def _status_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return summary


def _requirement_authority_kinds(requirement_id: str) -> set[str]:
    for requirement in PRODUCTION_AUTHORITY_REQUIREMENTS:
        if requirement["id"] == requirement_id:
            return set(requirement["authority_kinds"])
    return set()


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]) -> Any:
    reference = now or dossier.get("generated_at")
    if not reference:
        return None
    try:
        return parse_rfc3339(str(reference))
    except ValueError as exc:
        label = "now" if now else "generated_at"
        errors.append(f"framework runtime service authority freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"framework runtime service authority {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework runtime service authority {field} is required")
    return value


def _require_hash_ref(value: str, field: str) -> None:
    if not value.startswith("sha256:"):
        raise ValueError(f"framework runtime service authority {field} must start with sha256:")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "receipt") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            child_path = f"{path}.{key}"
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                errors.append(f"framework runtime service authority contains secret-like field {child_path}; store only redacted refs")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")
