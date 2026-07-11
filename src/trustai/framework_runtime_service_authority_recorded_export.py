from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_service_authority_attestation import verify_framework_runtime_service_authority_attestation

FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_SCHEMA = "trustai.framework-runtime-service-authority-recorded-export/0.1"
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_ENTRY_TYPE = "framework_runtime.service_authority_recorded_exported"
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_MODES = {
    "local-recorded-export",
    "provider-recorded-export",
    "production-recorded-export",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")

RECORDED_EXPORT_ARTIFACTS: tuple[tuple[str, str, str], ...] = (
    ("authority_attestation", "trustai.framework-runtime-service-authority-attestation", "authority_attestation"),
    ("authority_provider_receipt", "trustai.framework-runtime-service-authority-provider-receipt", "authority_provider_receipt"),
    ("authority_provider_export", "trustai.framework-runtime-service-authority-provider-export", "authority_provider_export"),
    ("authority_worker", "trustai.framework-runtime-service-authority-worker", "authority_worker"),
    ("authority_dossier", "trustai.framework-runtime-service-authority-dossier", "authority_dossier"),
    ("service_provider_receipt", "trustai.framework-runtime-service-provider-receipt", "service_provider_receipt"),
    ("service_provider_export", "trustai.framework-runtime-service-provider-export", "service_provider_export"),
    ("service_worker", "trustai.framework-runtime-service-worker", "service_worker"),
    ("service_attestation", "trustai.framework-runtime-service-attestation", "service_attestation"),
    ("storage_receipt", "trustai.framework-runtime-storage-receipt", "storage_receipt"),
    ("storage_export", "trustai.framework-runtime-storage-export", "storage_export"),
    ("runtime_worker", "trustai.framework-runtime-worker", "worker"),
    ("runtime_audit", "trustai.framework-runtime-audit-receipt", "runtime_audit"),
    ("audit_export", "trustai.framework-runtime-audit-export", "audit_export"),
    ("hook_operation", "trustai.framework-hook-operation", "operation"),
    ("trace_payload", "trustai.framework-trace-payload", "trace_payload"),
    ("hook_release", "trustai.framework-hook-release", "release"),
    ("adapter_matrix", "trustai.framework-adapter-matrix", "matrix"),
)


@dataclass
class FrameworkRuntimeServiceAuthorityRecordedExportVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_service_authority_recorded_export(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service authority recorded export receipt must contain an object")
    return value


def write_framework_runtime_service_authority_recorded_export(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_service_authority_recorded_export(
    authority_attestation: dict[str, Any],
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
    artifact_paths: dict[str, str | Path],
    root: str | Path = ".",
    mode: str = "provider-recorded-export",
    environment: str = "local",
    recorder_ref: str,
    storage_backend: str,
    retention_ref: str,
    retention_until: str,
    credential_ref: str,
    recorded_at: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_MODES)}")
    for value, field in (
        (environment, "environment"),
        (recorder_ref, "recorder_ref"),
        (storage_backend, "storage_backend"),
        (retention_ref, "retention_ref"),
        (retention_until, "retention_until"),
        (credential_ref, "credential_ref"),
    ):
        _require_text(value, field)
    timestamp = recorded_at or utc_now()
    parse_rfc3339(timestamp)
    if parse_rfc3339(retention_until) <= parse_rfc3339(timestamp):
        raise ValueError("framework runtime service authority recorded export retention_until must be after recorded_at")

    source_objects = _source_objects(
        authority_attestation,
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
    )
    attestation_result = verify_framework_runtime_service_authority_attestation(
        authority_attestation,
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
        now=timestamp,
    )
    if not attestation_result.ok:
        raise ValueError("invalid framework runtime service authority attestation source: " + "; ".join(attestation_result.errors))

    records = _artifact_records(artifact_paths, source_objects)
    artifact_summary = _artifact_summary(records)
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_SCHEMA,
        "mode": mode,
        "environment": environment,
        "recorded_at": timestamp,
        "source": _source_binding(authority_attestation),
        "recorder": {
            "recorder_ref": recorder_ref,
            "credential": _redacted_ref(credential_ref),
        },
        "retention": {
            "storage_backend": storage_backend,
            "retention_ref": retention_ref,
            "retention_until": retention_until,
        },
        "recorded_artifacts": {
            "artifact_count": len(records),
            "artifact_root": content_hash(records),
            "items": records,
            "summary": artifact_summary,
        },
        "require_complete": require_complete,
        "require_fresh": require_fresh,
        "controls": _controls(mode, authority_attestation, records, timestamp, retention_until),
        "limitations": [
            "This receipt binds a verified framework runtime service authority attestation to retained raw source and provider export artifacts.",
            "It records byte hashes, sizes, media types, and canonical JSON content hashes for disclosed artifacts so offline reviewers can detect file swaps.",
            "It does not prove continuously operated production infrastructure unless mode is production-recorded-export and the source attestation is production-attestation with live provider-owned evidence.",
        ],
    }
    recorded_export_id = content_hash(body)
    return {
        **body,
        "recorded_export_id": recorded_export_id,
        "signatures": [
            sign_value(
                {"recorded_export_id": recorded_export_id, "framework_runtime_service_authority_recorded_export": body},
                key,
            )
        ],
    }


def verify_framework_runtime_service_authority_recorded_export(
    receipt: dict[str, Any],
    *,
    authority_attestation: dict[str, Any] | None = None,
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
    artifact_paths: dict[str, str | Path] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> FrameworkRuntimeServiceAuthorityRecordedExportVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_SCHEMA:
        errors.append(f"unsupported framework runtime service authority recorded export schema: {receipt.get('schema')}")
    body = without_keys(receipt, "recorded_export_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("recorded_export_id") != expected_id:
        errors.append("recorded_export_id does not match canonical framework runtime service authority recorded export body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service authority recorded export must include at least one signature")
    else:
        signed_value = {
            "recorded_export_id": receipt.get("recorded_export_id"),
            "framework_runtime_service_authority_recorded_export": body,
        }
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service authority recorded export signature verification failed")

    recorded_reference = _recorded_reference(receipt, now, errors)
    mode = receipt.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_MODES:
        errors.append("framework runtime service authority recorded export mode is unsupported")
    elif mode != "production-recorded-export":
        warnings.append(f"framework runtime service authority recorded export mode is {mode}; live production operation is not claimed")
    for field in ("environment",):
        if not receipt.get(field):
            errors.append(f"framework runtime service authority recorded export {field} is required")
    _verify_recorder(receipt.get("recorder"), errors)
    _verify_retention(receipt.get("retention"), recorded_reference, errors)
    _verify_source_binding(receipt.get("source"), authority_attestation, errors, warnings)

    if authority_attestation is None:
        warnings.append("framework runtime service authority attestation source was not supplied; attestation source was not replayed")
    else:
        result = verify_framework_runtime_service_authority_attestation(
            authority_attestation,
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
            require_complete=require_complete or bool(receipt.get("require_complete")),
            require_fresh=require_fresh or bool(receipt.get("require_fresh")),
            now=now or receipt.get("recorded_at"),
        )
        if not result.ok:
            errors.extend(f"framework runtime service authority recorded export attestation source: {error}" for error in result.errors)
        warnings.extend(f"framework runtime service authority recorded export attestation source: {warning}" for warning in result.warnings)

    _verify_recorded_artifacts(
        receipt.get("recorded_artifacts"),
        artifact_paths,
        _optional_source_objects(
            authority_attestation,
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
        ),
        errors,
        warnings,
    )
    _verify_production_claim(receipt, errors)
    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("framework runtime service authority recorded export controls are required")
    _check_no_secret_values(receipt, errors)
    return FrameworkRuntimeServiceAuthorityRecordedExportVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_service_authority_recorded_export(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    authority_attestation: dict[str, Any],
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
    artifact_paths: dict[str, str | Path],
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_runtime_service_authority_recorded_export(
        receipt,
        authority_attestation=authority_attestation,
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
        artifact_paths=artifact_paths,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid framework runtime service authority recorded export: " + "; ".join(result.errors))
    payload = {
        "recorded_export_id": receipt["recorded_export_id"],
        "recorded_export_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "recorded_at": receipt.get("recorded_at"),
        "source": receipt.get("source"),
        "recorder": receipt.get("recorder"),
        "retention": receipt.get("retention"),
        "recorded_artifacts": {
            "artifact_count": (receipt.get("recorded_artifacts") or {}).get("artifact_count")
            if isinstance(receipt.get("recorded_artifacts"), dict)
            else None,
            "artifact_root": (receipt.get("recorded_artifacts") or {}).get("artifact_root")
            if isinstance(receipt.get("recorded_artifacts"), dict)
            else None,
            "summary": (receipt.get("recorded_artifacts") or {}).get("summary")
            if isinstance(receipt.get("recorded_artifacts"), dict)
            else None,
        },
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(
        FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=receipt.get("recorded_at"),
    )


def _source_objects(
    authority_attestation: dict[str, Any],
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
) -> dict[str, dict[str, Any]]:
    return {
        "authority_attestation": authority_attestation,
        "authority_provider_receipt": authority_provider_receipt,
        "authority_provider_export": authority_provider_export,
        "authority_worker": authority_worker,
        "authority_dossier": authority_dossier,
        "service_provider_receipt": service_provider_receipt,
        "service_provider_export": service_provider_export,
        "service_worker": service_worker,
        "service_attestation": service_attestation,
        "storage_receipt": storage_receipt,
        "storage_export": storage_export,
        "worker": worker,
        "runtime_audit": runtime_audit,
        "audit_export": audit_export,
        "operation": operation,
        "trace_payload": trace_payload,
        "release": release,
        "matrix": matrix,
    }


def _optional_source_objects(*values: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    names = [
        "authority_attestation",
        "authority_provider_receipt",
        "authority_provider_export",
        "authority_worker",
        "authority_dossier",
        "service_provider_receipt",
        "service_provider_export",
        "service_worker",
        "service_attestation",
        "storage_receipt",
        "storage_export",
        "worker",
        "runtime_audit",
        "audit_export",
        "operation",
        "trace_payload",
        "release",
        "matrix",
    ]
    return {name: value for name, value in zip(names, values) if isinstance(value, dict)}


def _source_binding(attestation: dict[str, Any]) -> dict[str, Any]:
    provider = attestation.get("authority_provider_binding", {}) if isinstance(attestation.get("authority_provider_binding"), dict) else {}
    dossier = attestation.get("authority_dossier_binding", {}) if isinstance(attestation.get("authority_dossier_binding"), dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_hash": content_hash(attestation),
        "schema": attestation.get("schema"),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "issuer": attestation.get("issuer"),
        "subject_ref": attestation.get("subject_ref"),
        "issued_at": attestation.get("issued_at"),
        "expires_at": attestation.get("expires_at"),
        "authority_provider_receipt_id": provider.get("provider_receipt_id"),
        "authority_provider_receipt_hash": provider.get("provider_receipt_hash"),
        "authority_provider_export_hash": provider.get("provider_export_hash"),
        "authority_evidence_root": provider.get("authority_evidence_root"),
        "missing_requirement_root": provider.get("missing_requirement_root"),
        "dossier_id": dossier.get("dossier_id"),
        "dossier_hash": dossier.get("dossier_hash"),
        "authority_ref": dossier.get("authority_ref"),
        "dossier_summary": dossier.get("summary"),
    }


def _verify_source_binding(binding: Any, authority_attestation: dict[str, Any] | None, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(binding, dict):
        errors.append("framework runtime service authority recorded export source must be an object")
        return
    _verify_source_binding_completeness(binding, errors)
    if authority_attestation is None:
        warnings.append("framework runtime service authority recorded export source attestation was not supplied; source hash was not replayed")
        return
    if binding != _source_binding(authority_attestation):
        errors.append("framework runtime service authority recorded export source binding does not match supplied authority attestation")


def _verify_source_binding_completeness(binding: dict[str, Any], errors: list[str]) -> None:
    for field in (
        "attestation_id",
        "attestation_hash",
        "schema",
        "mode",
        "environment",
        "issuer",
        "subject_ref",
        "issued_at",
        "expires_at",
        "authority_provider_receipt_id",
        "authority_provider_receipt_hash",
        "authority_provider_export_hash",
        "authority_evidence_root",
        "missing_requirement_root",
        "dossier_id",
        "dossier_hash",
        "authority_ref",
    ):
        _require_binding_field(binding, f"source.{field}", errors)
    _verify_dossier_summary_binding(binding.get("dossier_summary"), errors)


def _verify_dossier_summary_binding(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded export source.dossier_summary is required")
        return
    for field in (
        "required_requirement_count",
        "covered_requirement_count",
        "missing_requirement_count",
        "covered_requirement_ids",
        "missing_requirement_ids",
        "evidence_count",
        "status",
    ):
        _require_binding_field(value, f"source.dossier_summary.{field}", errors)


def _require_binding_field(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if value is None or value == "" or value == {}:
        errors.append(f"framework runtime service authority recorded export {path} is required")


def _artifact_records(artifact_paths: dict[str, str | Path], source_objects: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, artifact_type, source_key in RECORDED_EXPORT_ARTIFACTS:
        path = artifact_paths.get(name)
        if path is None:
            raise ValueError(f"framework runtime service authority recorded export artifact path is required: {name}")
        expected = source_objects.get(source_key)
        if expected is None:
            raise ValueError(f"framework runtime service authority recorded export source object is required: {source_key}")
        records.append(_artifact_record(name, artifact_type, path, expected))
    return records


def _artifact_record(name: str, artifact_type: str, path: str | Path, expected: dict[str, Any]) -> dict[str, Any]:
    source = Path(path)
    data = source.read_bytes()
    parsed = _parse_json_artifact(data, source)
    expected_hash = content_hash(expected)
    content = content_hash(parsed)
    if content != expected_hash:
        raise ValueError(f"framework runtime service authority recorded export {name} content hash does not match supplied source object")
    return {
        "name": name,
        "artifact_type": artifact_type,
        "path": str(path).replace("\\", "/"),
        "media_type": _media_type(source),
        "size_bytes": len(data),
        "sha256": _sha256_ref(data),
        "content_hash": content,
        "expected_content_hash": expected_hash,
    }


def _verify_recorded_artifacts(
    value: Any,
    artifact_paths: dict[str, str | Path] | None,
    source_objects: dict[str, dict[str, Any]],
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded_artifacts must be an object")
        return
    items = value.get("items", [])
    if not isinstance(items, list) or not items:
        errors.append("framework runtime service authority recorded_artifacts.items are required")
        items = []
    for item in items:
        if not isinstance(item, dict):
            errors.append("framework runtime service authority recorded_artifacts items must be objects")
            continue
        for field in ("name", "artifact_type", "path", "media_type", "size_bytes", "sha256", "content_hash", "expected_content_hash"):
            if item.get(field) in (None, ""):
                errors.append(f"framework runtime service authority recorded_artifacts item.{field} is required")
        if item.get("sha256") and not _is_sha256_ref(str(item.get("sha256"))):
            errors.append(f"framework runtime service authority recorded_artifacts {item.get('name')} sha256 must be a sha256 reference")
        if item.get("content_hash") != item.get("expected_content_hash"):
            errors.append(f"framework runtime service authority recorded_artifacts {item.get('name')} content_hash must match expected_content_hash")
    if value.get("artifact_count") != len(items):
        errors.append("framework runtime service authority recorded_artifacts artifact_count does not match items")
    if value.get("artifact_root") != content_hash(items):
        errors.append("framework runtime service authority recorded_artifacts artifact_root does not match items")
    if value.get("summary") != _artifact_summary([item for item in items if isinstance(item, dict)]):
        errors.append("framework runtime service authority recorded_artifacts summary does not match items")
    if artifact_paths is None:
        warnings.append("framework runtime service authority recorded export artifact paths were not supplied; raw files were not replayed")
        return
    try:
        expected_records = _artifact_records(artifact_paths, source_objects)
    except (OSError, ValueError) as exc:
        errors.append(f"framework runtime service authority recorded export artifact replay failed: {exc}")
        return
    if items != expected_records:
        errors.append("framework runtime service authority recorded artifacts do not match supplied artifact paths")
        by_name = {item.get("name"): item for item in items if isinstance(item, dict)}
        for expected in expected_records:
            actual = by_name.get(expected["name"])
            if actual != expected:
                errors.append(f"framework runtime service authority recorded artifact mismatch: {expected['name']}")


def _artifact_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "artifact_names": [record.get("name") for record in records],
        "artifact_types": [record.get("artifact_type") for record in records],
        "total_size_bytes": sum(int(record.get("size_bytes", 0)) for record in records if isinstance(record.get("size_bytes"), int)),
        "sha256_root": content_hash([record.get("sha256") for record in records]),
        "content_root": content_hash([record.get("content_hash") for record in records]),
    }


def _controls(mode: str, authority_attestation: dict[str, Any], records: list[dict[str, Any]], recorded_at: str, retention_until: str) -> list[dict[str, Any]]:
    all_have_hashes = all(record.get("sha256") and record.get("size_bytes", -1) >= 0 for record in records)
    all_have_content_hashes = all(record.get("content_hash") and record.get("content_hash") == record.get("expected_content_hash") for record in records)
    retention_ok = parse_rfc3339(retention_until) > parse_rfc3339(recorded_at)
    return [
        {
            "name": "authority_attestation_source_replayed",
            "status": "passed" if authority_attestation.get("attestation_id") else "failed",
            "detail": "The recorded export builder replayed the framework runtime service authority attestation and source chain.",
        },
        {
            "name": "retained_artifacts_bound",
            "status": "passed" if len(records) == len(RECORDED_EXPORT_ARTIFACTS) else "failed",
            "detail": "Every required authority export source artifact is represented in the recorded export receipt.",
        },
        {
            "name": "artifact_byte_hashes_bound",
            "status": "passed" if all_have_hashes else "failed",
            "detail": "Each retained artifact is bound by byte hash and size.",
        },
        {
            "name": "artifact_content_hashes_bound",
            "status": "passed" if all_have_content_hashes else "failed",
            "detail": "Each JSON artifact is bound to the canonical content hash of the verified source object.",
        },
        {
            "name": "retention_window_recorded",
            "status": "passed" if retention_ok else "failed",
            "detail": "The recorded export receipt includes retention metadata beyond the recording timestamp.",
        },
        {
            "name": "production_recorded_export_claim_limited",
            "status": "passed" if mode != "production-recorded-export" or authority_attestation.get("mode") == "production-attestation" else "failed",
            "detail": "Production-recorded-export mode requires a production authority attestation source.",
        },
    ]


def _verify_production_claim(receipt: dict[str, Any], errors: list[str]) -> None:
    if receipt.get("mode") != "production-recorded-export":
        return
    source = receipt.get("source", {}) if isinstance(receipt.get("source"), dict) else {}
    if source.get("mode") != "production-attestation":
        errors.append("production-recorded-export mode requires a production-attestation source")


def _verify_recorder(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded export recorder must be an object")
        return
    if not value.get("recorder_ref"):
        errors.append("framework runtime service authority recorded export recorder.recorder_ref is required")
    _verify_redacted_ref(value.get("credential"), "framework runtime service authority recorded export credential", errors)


def _verify_retention(value: Any, recorded_at: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("framework runtime service authority recorded export retention must be an object")
        return
    for field in ("storage_backend", "retention_ref", "retention_until"):
        if not value.get(field):
            errors.append(f"framework runtime service authority recorded export retention.{field} is required")
    try:
        retention_until = parse_rfc3339(str(value.get("retention_until") or ""))
        if recorded_at is not None and retention_until <= recorded_at:
            errors.append("framework runtime service authority recorded export retention_until must be after recorded_at")
    except ValueError as exc:
        errors.append(f"framework runtime service authority recorded export retention_until invalid: {exc}")


def _recorded_reference(receipt: dict[str, Any], now: str | None, errors: list[str]) -> Any:
    try:
        recorded_at = parse_rfc3339(str(receipt.get("recorded_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime service authority recorded_at invalid: {exc}")
        recorded_at = None
    if now:
        try:
            return parse_rfc3339(now)
        except ValueError as exc:
            errors.append(f"framework runtime service authority recorded export now invalid: {exc}")
    return recorded_at


def _parse_json_artifact(data: bytes, path: Path) -> dict[str, Any]:
    value = json.loads(data.decode("utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"recorded export artifact must contain a JSON object: {path}")
    return value


def _media_type(path: Path) -> str:
    return "application/json" if path.suffix.lower() == ".json" else "application/octet-stream"


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
        raise ValueError(f"framework runtime service authority recorded export {field} is required")
    return value


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
                    errors.append(f"framework runtime service authority recorded export secret-like field must be redacted reference: {child_path}")
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
