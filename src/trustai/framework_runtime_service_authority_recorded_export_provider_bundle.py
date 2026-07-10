from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_runtime_service_authority_recorded_export import RECORDED_EXPORT_ARTIFACTS
from .framework_runtime_service_authority_recorded_export_provider import (
    verify_framework_runtime_service_authority_recorded_export_provider_receipt,
)

FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_SCHEMA = (
    "trustai.framework-runtime-service-authority-recorded-export-provider-bundle/0.1"
)
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_ENTRY_TYPE = (
    "framework_runtime.service_authority_recorded_export_provider_bundle_exported"
)
FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_MODES = {
    "offline-review",
    "auditor-review",
    "regulator-review",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")

SOURCE_OBJECTS: tuple[tuple[str, str], ...] = (
    ("provider_receipt", "provider_receipt"),
    ("provider_export", "provider_export"),
    ("recorded_export_worker", "recorded_export_worker"),
    ("recorded_export", "recorded_export"),
    ("authority_attestation", "authority_attestation"),
    ("authority_provider_receipt", "authority_provider_receipt"),
    ("authority_provider_export", "authority_provider_export"),
    ("authority_worker", "authority_worker"),
    ("authority_dossier", "authority_dossier"),
    ("service_provider_receipt", "service_provider_receipt"),
    ("service_provider_export", "service_provider_export"),
    ("service_worker", "service_worker"),
    ("service_attestation", "service_attestation"),
    ("storage_receipt", "storage_receipt"),
    ("storage_export", "storage_export"),
    ("runtime_worker", "worker"),
    ("runtime_audit", "runtime_audit"),
    ("audit_export", "audit_export"),
    ("hook_operation", "operation"),
    ("trace_payload", "trace_payload"),
    ("hook_release", "release"),
    ("adapter_matrix", "matrix"),
)


@dataclass
class FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_runtime_service_authority_recorded_export_provider_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework runtime service authority recorded export provider bundle must contain an object")
    return value


def write_framework_runtime_service_authority_recorded_export_provider_bundle(
    path: str | Path, bundle: dict[str, Any]
) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_runtime_service_authority_recorded_export_provider_bundle(
    provider_receipt: dict[str, Any],
    provider_export: dict[str, Any],
    recorded_export_worker: dict[str, Any],
    recorded_export: dict[str, Any],
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
    mode: str = "offline-review",
    environment: str | None = None,
    reviewer_ref: str,
    bundle_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_MODES:
        raise ValueError(
            "mode must be one of "
            f"{sorted(FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_MODES)}"
        )
    if not isinstance(reviewer_ref, str) or not reviewer_ref.strip():
        raise ValueError("framework runtime service authority recorded export provider bundle reviewer_ref is required")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    provider_result = verify_framework_runtime_service_authority_recorded_export_provider_receipt(
        provider_receipt,
        provider_export=provider_export,
        recorded_export_worker=recorded_export_worker,
        recorded_export=recorded_export,
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
    )
    if not provider_result.ok:
        raise ValueError(
            "invalid framework runtime service authority recorded export provider source: "
            + "; ".join(provider_result.errors)
        )

    sources = _source_objects(
        provider_receipt=provider_receipt,
        provider_export=provider_export,
        recorded_export_worker=recorded_export_worker,
        recorded_export=recorded_export,
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
    )
    source_artifacts = _build_source_artifacts(artifact_paths, sources)
    body: dict[str, Any] = {
        "schema": FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment or provider_receipt.get("environment"),
        "generated_at": timestamp,
        "reviewer_ref": reviewer_ref,
        "bundle_ref": bundle_ref or _default_bundle_ref(provider_receipt),
        "source": _source_summary(provider_receipt, provider_export, recorded_export_worker, recorded_export),
        "verification_options": {
            "require_complete": bool(provider_receipt.get("require_complete")),
            "require_fresh": bool(provider_receipt.get("require_fresh")),
        },
        "sources": sources,
        "source_artifacts": source_artifacts,
        "summary": _bundle_summary(provider_receipt, provider_export, recorded_export_worker, recorded_export, source_artifacts),
        "controls": _controls(mode, provider_receipt, source_artifacts),
        "limitations": [
            "This bundle is self-contained for offline review of one framework runtime service authority recorded-export provider receipt path.",
            "It embeds parsed source receipts/exports and raw JSON source artifact bytes so reviewers can detect source swaps without original local file paths.",
            "It does not make live production infrastructure claims beyond the provider receipt mode and the provider-owned export evidence embedded in the bundle.",
        ],
    }
    bundle_id = content_hash(body)
    return {
        **body,
        "bundle_id": bundle_id,
        "signatures": [
            sign_value(
                {
                    "bundle_id": bundle_id,
                    "framework_runtime_service_authority_recorded_export_provider_bundle": body,
                },
                key,
            )
        ],
    }


def verify_framework_runtime_service_authority_recorded_export_provider_bundle(
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if bundle.get("schema") != FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_SCHEMA:
        errors.append(
            "unsupported framework runtime service authority recorded export provider bundle schema: "
            f"{bundle.get('schema')}"
        )
    body = without_keys(bundle, "bundle_id", "signatures")
    expected_id = content_hash(body)
    if bundle.get("bundle_id") != expected_id:
        errors.append(
            "bundle_id does not match canonical framework runtime service authority recorded export provider bundle body"
        )
    signatures = bundle.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework runtime service authority recorded export provider bundle must include at least one signature")
    else:
        signed_value = {
            "bundle_id": bundle.get("bundle_id"),
            "framework_runtime_service_authority_recorded_export_provider_bundle": body,
        }
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework runtime service authority recorded export provider bundle signature verification failed")

    mode = bundle.get("mode")
    if mode not in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_MODES:
        errors.append("framework runtime service authority recorded export provider bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"framework runtime service authority recorded export provider bundle generated_at invalid: {exc}")
    if not isinstance(bundle.get("reviewer_ref"), str) or not bundle.get("reviewer_ref", "").strip():
        errors.append("framework runtime service authority recorded export provider bundle reviewer_ref is required")

    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        errors.append("framework runtime service authority recorded export provider bundle sources must be an object")
        sources = {}
    source_objects = _required_source_objects(sources, errors)
    if source_objects:
        provider_result = verify_framework_runtime_service_authority_recorded_export_provider_receipt(
            source_objects["provider_receipt"],
            provider_export=source_objects["provider_export"],
            recorded_export_worker=source_objects["recorded_export_worker"],
            recorded_export=source_objects["recorded_export"],
            authority_attestation=source_objects["authority_attestation"],
            authority_provider_receipt=source_objects["authority_provider_receipt"],
            authority_provider_export=source_objects["authority_provider_export"],
            authority_worker=source_objects["authority_worker"],
            authority_dossier=source_objects["authority_dossier"],
            service_provider_receipt=source_objects["service_provider_receipt"],
            service_provider_export=source_objects["service_provider_export"],
            service_worker=source_objects["service_worker"],
            service_attestation=source_objects["service_attestation"],
            storage_receipt=source_objects["storage_receipt"],
            storage_export=source_objects["storage_export"],
            worker=source_objects["worker"],
            runtime_audit=source_objects["runtime_audit"],
            audit_export=source_objects["audit_export"],
            operation=source_objects["operation"],
            trace_payload=source_objects["trace_payload"],
            release=source_objects["release"],
            matrix=source_objects["matrix"],
            artifact_paths=None,
            key=key,
        )
        if not provider_result.ok:
            errors.extend(
                "framework runtime service authority recorded export provider bundle source replay: " + error
                for error in provider_result.errors
            )
        warnings.extend(
            warning for warning in provider_result.warnings if "artifact paths were not supplied" not in warning
        )
        _verify_source_artifacts(bundle.get("source_artifacts"), source_objects, errors)
        expected_source = _source_summary(
            source_objects["provider_receipt"],
            source_objects["provider_export"],
            source_objects["recorded_export_worker"],
            source_objects["recorded_export"],
        )
        if bundle.get("source") != expected_source:
            errors.append("framework runtime service authority recorded export provider bundle source summary does not match embedded sources")
        source_artifacts = bundle.get("source_artifacts") if isinstance(bundle.get("source_artifacts"), list) else []
        expected_summary = _bundle_summary(
            source_objects["provider_receipt"],
            source_objects["provider_export"],
            source_objects["recorded_export_worker"],
            source_objects["recorded_export"],
            source_artifacts,
        )
        if bundle.get("summary") != expected_summary:
            errors.append("framework runtime service authority recorded export provider bundle summary does not match embedded sources")
        if bundle.get("controls") != _controls(str(mode), source_objects["provider_receipt"], source_artifacts):
            errors.append("framework runtime service authority recorded export provider bundle controls do not match embedded sources")

    _check_no_secret_values(bundle, errors)
    return FrameworkRuntimeServiceAuthorityRecordedExportProviderBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_runtime_service_authority_recorded_export_provider_bundle(
    chain: EvidenceChain,
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_runtime_service_authority_recorded_export_provider_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError(
            "invalid framework runtime service authority recorded export provider bundle: "
            + "; ".join(result.errors)
        )
    payload = {
        "bundle_id": bundle["bundle_id"],
        "bundle_hash": content_hash(bundle),
        "mode": bundle.get("mode"),
        "environment": bundle.get("environment"),
        "generated_at": bundle.get("generated_at"),
        "reviewer_ref": bundle.get("reviewer_ref"),
        "bundle_ref": bundle.get("bundle_ref"),
        "source": bundle.get("source"),
        "summary": bundle.get("summary"),
        "control_summary": _status_summary(bundle.get("controls", [])),
    }
    return chain.append(
        FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=bundle.get("generated_at"),
    )


def _source_objects(**objects: dict[str, Any]) -> dict[str, Any]:
    source_by_keyword = {keyword: _clone(value) for keyword, value in objects.items()}
    return {
        name: source_by_keyword[keyword]
        for name, keyword in SOURCE_OBJECTS
        if keyword in source_by_keyword
    }


def _required_source_objects(sources: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for name, keyword in SOURCE_OBJECTS:
        value = sources.get(name)
        if not isinstance(value, dict):
            errors.append(f"framework runtime service authority recorded export provider bundle sources.{name} is required")
            continue
        values[keyword] = value
    return values if len(values) == len(SOURCE_OBJECTS) else {}


def _build_source_artifacts(
    artifact_paths: dict[str, str | Path], sources: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for name, artifact_type, source_key in RECORDED_EXPORT_ARTIFACTS:
        path = artifact_paths.get(name)
        if path is None:
            raise ValueError(f"framework runtime service authority recorded export provider bundle artifact path is required: {name}")
        source = Path(path)
        data = source.read_bytes()
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"framework runtime service authority recorded export provider bundle artifact JSON invalid: {name}: {exc}"
            ) from exc
        expected = sources.get(_bundle_source_name(source_key))
        if not isinstance(parsed, dict) or not isinstance(expected, dict):
            raise ValueError(
                f"framework runtime service authority recorded export provider bundle artifact source object is required: {name}"
            )
        parsed_hash = content_hash(parsed)
        expected_hash = content_hash(expected)
        if parsed_hash != expected_hash:
            raise ValueError(
                f"framework runtime service authority recorded export provider bundle artifact content hash mismatch: {name}"
            )
        body = {
            "name": name,
            "artifact_type": artifact_type,
            "path": str(path).replace("\\", "/"),
            "media_type": "application/json" if source.suffix.lower() == ".json" else "application/octet-stream",
            "size_bytes": len(data),
            "sha256": _sha256_ref(data),
            "content_hash": parsed_hash,
            "expected_content_hash": expected_hash,
            "content_b64": base64.b64encode(data).decode("ascii"),
        }
        artifacts.append({**body, "artifact_id": content_hash(body)})
    return artifacts


def _verify_source_artifacts(
    value: Any,
    source_objects: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    if not isinstance(value, list):
        errors.append("framework runtime service authority recorded export provider bundle source_artifacts must be a list")
        return
    recorded_export = source_objects.get("recorded_export", {})
    recorded_artifacts = recorded_export.get("recorded_artifacts", {}) if isinstance(recorded_export, dict) else {}
    recorded_items = recorded_artifacts.get("items", []) if isinstance(recorded_artifacts, dict) else []
    expected_by_name = {item.get("name"): item for item in recorded_items if isinstance(item, dict)}
    actual_by_name: dict[str, dict[str, Any]] = {}
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("framework runtime service authority recorded export provider bundle source artifact must be an object")
            continue
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact id mismatch: {artifact.get('name')}")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            errors.append("framework runtime service authority recorded export provider bundle source artifact name is required")
            continue
        actual_by_name[name] = artifact
        expected_record = expected_by_name.get(name)
        if not expected_record:
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact is not recorded: {name}")
            continue
        public_artifact = without_keys(artifact, "artifact_id", "content_b64")
        if public_artifact != expected_record:
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact metadata mismatch: {name}")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (ValueError, TypeError) as exc:
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact content_b64 invalid: {name}: {exc}")
            continue
        actual_sha = _sha256_ref(data)
        if artifact.get("sha256") != actual_sha:
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact sha256 mismatch: {name}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact size mismatch: {name}")
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact JSON invalid: {name}: {exc}")
            continue
        if not isinstance(parsed, dict):
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact JSON must be an object: {name}")
            continue
        parsed_hash = content_hash(parsed)
        if artifact.get("content_hash") != parsed_hash:
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact content hash mismatch: {name}")
        source_key = _recorded_export_source_key(name)
        source_object = source_objects.get(source_key)
        if isinstance(source_object, dict) and content_hash(source_object) != parsed_hash:
            errors.append(f"framework runtime service authority recorded export provider bundle source artifact does not match embedded source: {name}")
    expected_names = {name for name, _, _ in RECORDED_EXPORT_ARTIFACTS}
    if set(actual_by_name) != expected_names:
        missing = sorted(expected_names - set(actual_by_name))
        extra = sorted(set(actual_by_name) - expected_names)
        if missing:
            errors.append("framework runtime service authority recorded export provider bundle source artifacts missing: " + ", ".join(missing))
        if extra:
            errors.append("framework runtime service authority recorded export provider bundle source artifacts unsupported: " + ", ".join(extra))


def _source_summary(
    provider_receipt: dict[str, Any],
    provider_export: dict[str, Any],
    recorded_export_worker: dict[str, Any],
    recorded_export: dict[str, Any],
) -> dict[str, Any]:
    provider_export_summary = provider_receipt.get("provider_export", {}) if isinstance(provider_receipt.get("provider_export"), dict) else {}
    worker = recorded_export_worker.get("worker", {}) if isinstance(recorded_export_worker.get("worker"), dict) else {}
    return {
        "provider_receipt_id": provider_receipt.get("provider_receipt_id"),
        "provider_receipt_hash": content_hash(provider_receipt),
        "provider": provider_receipt.get("provider"),
        "provider_export_ref": provider_export.get("export_ref"),
        "provider_export_hash": content_hash(provider_export),
        "recorded_export_worker_operation_id": recorded_export_worker.get("worker_operation_id"),
        "recorded_export_worker_hash": content_hash(recorded_export_worker),
        "recorded_export_id": recorded_export.get("recorded_export_id"),
        "recorded_export_hash": content_hash(recorded_export),
        "run_ref": worker.get("run_ref"),
        "storage_record_root": provider_export_summary.get("storage_record_root"),
        "audit_record_root": provider_export_summary.get("audit_record_root"),
    }


def _bundle_summary(
    provider_receipt: dict[str, Any],
    provider_export: dict[str, Any],
    recorded_export_worker: dict[str, Any],
    recorded_export: dict[str, Any],
    source_artifacts: list[Any],
) -> dict[str, Any]:
    source_hashes = {
        "provider_receipt": content_hash(provider_receipt),
        "provider_export": content_hash(provider_export),
        "recorded_export_worker": content_hash(recorded_export_worker),
        "recorded_export": content_hash(recorded_export),
    }
    artifact_hashes = [artifact.get("sha256") for artifact in source_artifacts if isinstance(artifact, dict)]
    return {
        "provider_receipt_id": provider_receipt.get("provider_receipt_id"),
        "provider_export_hash": content_hash(provider_export),
        "recorded_export_worker_operation_id": recorded_export_worker.get("worker_operation_id"),
        "recorded_export_id": recorded_export.get("recorded_export_id"),
        "source_object_hashes": source_hashes,
        "source_artifact_count": len(source_artifacts),
        "source_artifact_sha256_root": content_hash(artifact_hashes),
        "source_artifact_content_root": content_hash(
            [artifact.get("content_hash") for artifact in source_artifacts if isinstance(artifact, dict)]
        ),
    }


def _controls(mode: str, provider_receipt: dict[str, Any], source_artifacts: list[Any]) -> list[dict[str, Any]]:
    valid_artifact_count = len([artifact for artifact in source_artifacts if isinstance(artifact, dict)])
    return [
        {
            "name": "provider_receipt_replayed",
            "status": "passed" if provider_receipt.get("provider_receipt_id") else "failed",
            "detail": "The bundle verifier replays the signed recorded-export provider receipt and its nested source chain.",
        },
        {
            "name": "source_artifact_bytes_embedded",
            "status": "passed" if valid_artifact_count == len(RECORDED_EXPORT_ARTIFACTS) else "failed",
            "detail": "Every recorded-export source artifact is embedded with byte hash, size, and canonical content hash.",
        },
        {
            "name": "offline_review_mode_bound",
            "status": "passed" if mode in FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_RECORDED_EXPORT_PROVIDER_BUNDLE_MODES else "failed",
            "detail": "The bundle mode identifies the intended offline review surface.",
        },
    ]


def _default_bundle_ref(provider_receipt: dict[str, Any]) -> str:
    provider_export = provider_receipt.get("provider_export", {}) if isinstance(provider_receipt.get("provider_export"), dict) else {}
    export_ref = provider_export.get("export_ref") or provider_receipt.get("provider_receipt_id") or "unknown"
    return f"bundle:framework-runtime-service-authority-recorded-export-provider/{export_ref}"


def _recorded_export_source_key(artifact_name: str) -> str:
    for name, _, source_key in RECORDED_EXPORT_ARTIFACTS:
        if name == artifact_name:
            return source_key
    return artifact_name


def _bundle_source_name(source_key: str) -> str:
    if source_key == "worker":
        return "runtime_worker"
    if source_key == "operation":
        return "hook_operation"
    if source_key == "release":
        return "hook_release"
    if source_key == "matrix":
        return "adapter_matrix"
    return source_key


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _status_summary(controls: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(lowered, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(
                        "framework runtime service authority recorded export provider bundle secret-like field must be redacted reference: "
                        f"{child_path}"
                    )
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
