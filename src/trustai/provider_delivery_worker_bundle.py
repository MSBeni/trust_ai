from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .provider_delivery_worker import verify_provider_delivery_worker_receipt

PROVIDER_DELIVERY_WORKER_BUNDLE_SCHEMA = "trustai.provider-delivery-worker-bundle/0.1"
PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE = "provider.delivery_worker_bundle_exported"
PROVIDER_DELIVERY_WORKER_BUNDLE_MODES = {"offline-review", "auditor-review", "regulator-review"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

SOURCE_TYPES: tuple[tuple[str, str], ...] = (
    ("worker_receipt", "provider-delivery-worker-receipt"),
    ("service_attestation", "provider-delivery-service-attestation"),
    ("delivery", "provider-delivery"),
    ("payload", "provider-payload"),
    ("provider_operations_service", "provider-operations-service-attestation"),
    ("provider_response", "provider-response"),
    ("provider_audit_correlation", "provider-audit-correlation"),
    ("provider_audit_log", "provider-audit-log"),
)
REQUIRED_SOURCES = {"worker_receipt", "service_attestation", "delivery"}


@dataclass
class ProviderDeliveryWorkerBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_delivery_worker_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider delivery worker bundle must contain an object")
    return value


def write_provider_delivery_worker_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_delivery_worker_bundle(
    receipt: dict[str, Any],
    service_attestation: dict[str, Any],
    delivery: dict[str, Any],
    *,
    payload: dict[str, Any] | None = None,
    provider_operations_service: dict[str, Any] | None = None,
    provider_response: dict[str, Any] | None = None,
    provider_audit_correlation: dict[str, Any] | None = None,
    provider_audit_log: Any | None = None,
    artifact_paths: dict[str, str | Path],
    mode: str = "offline-review",
    environment: str | None = None,
    reviewer_ref: str,
    bundle_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PROVIDER_DELIVERY_WORKER_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(PROVIDER_DELIVERY_WORKER_BUNDLE_MODES)}")
    if not isinstance(reviewer_ref, str) or not reviewer_ref.strip():
        raise ValueError("provider delivery worker bundle reviewer_ref is required")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    payload_artifact_path, payload_artifact_bytes = _payload_artifact_replay_from_paths(delivery, payload, artifact_paths)

    replay = verify_provider_delivery_worker_receipt(
        receipt,
        service_attestation=service_attestation,
        delivery=delivery,
        payload=payload,
        payload_artifact_path=payload_artifact_path,
        payload_artifact_bytes=payload_artifact_bytes,
        provider_operations_service=provider_operations_service,
        provider_response=provider_response,
        provider_audit_correlation=provider_audit_correlation,
        provider_audit_log=provider_audit_log,
        key=key,
    )
    if not replay.ok:
        raise ValueError("invalid provider delivery worker source: " + "; ".join(replay.errors))

    sources = _source_objects(
        worker_receipt=receipt,
        service_attestation=service_attestation,
        delivery=delivery,
        payload=payload,
        provider_operations_service=provider_operations_service,
        provider_response=provider_response,
        provider_audit_correlation=provider_audit_correlation,
        provider_audit_log=provider_audit_log,
    )
    secret_errors: list[str] = []
    _check_no_secret_values(sources, secret_errors)
    if secret_errors:
        raise ValueError("provider delivery worker bundle source contains secret-like values: " + "; ".join(secret_errors))

    source_artifacts = _build_source_artifacts(artifact_paths, sources)
    body: dict[str, Any] = {
        "schema": PROVIDER_DELIVERY_WORKER_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment or receipt.get("environment"),
        "generated_at": timestamp,
        "reviewer_ref": reviewer_ref,
        "bundle_ref": bundle_ref or _default_bundle_ref(receipt),
        "source": _source_summary(receipt, service_attestation, delivery),
        "sources": sources,
        "source_artifacts": source_artifacts,
        "summary": _bundle_summary(receipt, sources, source_artifacts),
        "controls": _controls(receipt, sources, source_artifacts),
        "limitations": [
            "This bundle is self-contained for offline review of one provider delivery worker receipt and its replay sources.",
            "It embeds parsed source receipts/artifacts and raw JSON source bytes so reviewers can detect source swaps without original local file paths.",
            "When a delivery receipt records a retained payload artifact, the embedded payload bytes replay the recorded path, byte SHA-256, size, content hash, and payload hash.",
            "It proves replay against supplied provider response and audit-log exports when embedded; it does not claim live provider API retrieval or continuously operated worker fleets.",
        ],
    }
    bundle_id = content_hash(body)
    return {
        **body,
        "bundle_id": bundle_id,
        "signatures": [sign_value({"bundle_id": bundle_id, "provider_delivery_worker_bundle": body}, key)],
    }


def verify_provider_delivery_worker_bundle(
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> ProviderDeliveryWorkerBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if bundle.get("schema") != PROVIDER_DELIVERY_WORKER_BUNDLE_SCHEMA:
        errors.append(f"unsupported provider delivery worker bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    expected_id = content_hash(body)
    if bundle.get("bundle_id") != expected_id:
        errors.append("bundle_id does not match canonical provider delivery worker bundle body")

    signatures = bundle.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider delivery worker bundle must include at least one signature")
    else:
        signed_value = {"bundle_id": bundle.get("bundle_id"), "provider_delivery_worker_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider delivery worker bundle signature verification failed")

    mode = bundle.get("mode")
    if mode not in PROVIDER_DELIVERY_WORKER_BUNDLE_MODES:
        errors.append("provider delivery worker bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider delivery worker bundle generated_at invalid: {exc}")
    if not isinstance(bundle.get("reviewer_ref"), str) or not bundle.get("reviewer_ref", "").strip():
        errors.append("provider delivery worker bundle reviewer_ref is required")

    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        errors.append("provider delivery worker bundle sources must be an object")
        sources = {}
    source_values = _required_source_objects(sources, errors)
    if source_values:
        payload_artifact_path, payload_artifact_bytes = _payload_artifact_replay_from_artifacts(
            bundle.get("source_artifacts"),
            source_values,
            errors,
        )
        replay = verify_provider_delivery_worker_receipt(
            source_values["worker_receipt"],
            service_attestation=source_values["service_attestation"],
            delivery=source_values["delivery"],
            payload=source_values.get("payload"),
            payload_artifact_path=payload_artifact_path,
            payload_artifact_bytes=payload_artifact_bytes,
            provider_operations_service=source_values.get("provider_operations_service"),
            provider_response=source_values.get("provider_response"),
            provider_audit_correlation=source_values.get("provider_audit_correlation"),
            provider_audit_log=source_values.get("provider_audit_log"),
            key=key,
        )
        if not replay.ok:
            errors.extend("provider delivery worker bundle source replay: " + error for error in replay.errors)
        warnings.extend(replay.warnings)
        _verify_source_artifacts(bundle.get("source_artifacts"), source_values, errors)
        expected_source = _source_summary(
            source_values["worker_receipt"],
            source_values["service_attestation"],
            source_values["delivery"],
        )
        if bundle.get("source") != expected_source:
            errors.append("provider delivery worker bundle source summary does not match embedded sources")
        source_artifacts = bundle.get("source_artifacts") if isinstance(bundle.get("source_artifacts"), list) else []
        expected_summary = _bundle_summary(source_values["worker_receipt"], source_values, source_artifacts)
        if bundle.get("summary") != expected_summary:
            errors.append("provider delivery worker bundle summary does not match embedded sources")
        if bundle.get("controls") != _controls(source_values["worker_receipt"], source_values, source_artifacts):
            errors.append("provider delivery worker bundle controls do not match embedded sources")

    _check_no_secret_values(bundle, errors)
    return ProviderDeliveryWorkerBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def write_provider_delivery_worker_bundle_markdown(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_provider_delivery_worker_bundle_markdown(bundle), encoding="utf-8")


def render_provider_delivery_worker_bundle_markdown(bundle: dict[str, Any]) -> str:
    source = bundle.get("source", {}) if isinstance(bundle.get("source"), dict) else {}
    summary = bundle.get("summary", {}) if isinstance(bundle.get("summary"), dict) else {}
    controls = bundle.get("controls", []) if isinstance(bundle.get("controls"), list) else []
    artifacts = bundle.get("source_artifacts", []) if isinstance(bundle.get("source_artifacts"), list) else []
    control_rows = "\n".join(
        "| {name} | {status} | {detail} |".format(
            name=_markdown_cell(control.get("name", "")),
            status=_markdown_cell(control.get("status", "")),
            detail=_markdown_cell(control.get("detail", "")),
        )
        for control in controls
        if isinstance(control, dict)
    )
    artifact_rows = "\n".join(
        "| {name} | {artifact_type} | {size} | `{sha}` | `{content_hash}` |".format(
            name=_markdown_cell(artifact.get("name", "")),
            artifact_type=_markdown_cell(artifact.get("artifact_type", "")),
            size=artifact.get("size_bytes", 0),
            sha=artifact.get("sha256", ""),
            content_hash=artifact.get("content_hash", ""),
        )
        for artifact in artifacts
        if isinstance(artifact, dict)
    )
    limitations = "\n".join(f"- {limitation}" for limitation in bundle.get("limitations", []))
    source_hashes = summary.get("source_object_hashes", {}) if isinstance(summary.get("source_object_hashes"), dict) else {}
    source_hash_lines = "\n".join(f"- {name}: `{value}`" for name, value in sorted(source_hashes.items()))
    return f"""# TrustAI Provider Delivery Worker Bundle

Bundle ID: `{bundle.get('bundle_id', '')}`

Bundle ref: `{bundle.get('bundle_ref', '')}`

Mode: `{bundle.get('mode', '')}`

Environment: `{bundle.get('environment', '')}`

Generated at: `{bundle.get('generated_at', '')}`

Reviewer: `{bundle.get('reviewer_ref', '')}`

## Source

- Worker operation ID: `{source.get('worker_operation_id', '')}`
- Provider: `{source.get('provider', '')}`
- Delivery ID: `{source.get('delivery_id', '')}`
- Service attestation ID: `{source.get('service_attestation_id', '')}`
- Run ref: `{source.get('run_ref', '')}`
- Operation kind: `{source.get('operation_kind', '')}`
- Destination: `{source.get('destination_ref', '')}`
- Response status: `{source.get('response_status', '')}`
- Provider audit correlation ID: `{source.get('provider_audit_correlation_id', '')}`
- Provider audit-log hash: `{source.get('provider_audit_log_hash', '')}`

## Embedded Source Summary

- Embedded source artifacts: {summary.get('source_artifact_count', 0)}
- Provider response replayed: {summary.get('provider_response_replayed', False)}
- Provider audit replayed: {summary.get('provider_audit_replayed', False)}
- Retained payload artifact replayed: {summary.get('retained_payload_artifact_replayed', False)}
- Source artifact sha256 root: `{summary.get('source_artifact_sha256_root', '')}`
- Source artifact content root: `{summary.get('source_artifact_content_root', '')}`

{source_hash_lines or '- No source hashes recorded.'}

## Controls

| Control | Status | Detail |
|---|---|---|
{control_rows or '| None | unknown | No controls recorded. |'}

## Source Artifacts

| Name | Type | Bytes | SHA-256 | Content Hash |
|---|---|---:|---|---|
{artifact_rows or '| None | none | 0 | `` | `` |'}

## Limitations

{limitations or '- None'}
"""


def extract_provider_delivery_worker_bundle_sources(
    bundle: dict[str, Any],
    out_dir: str | Path,
    *,
    key: str | None = None,
    overwrite: bool = False,
) -> list[dict[str, Any]]:
    result = verify_provider_delivery_worker_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid provider delivery worker bundle: " + "; ".join(result.errors))
    source_artifacts = bundle.get("source_artifacts", [])
    if not isinstance(source_artifacts, list):
        raise ValueError("provider delivery worker bundle source_artifacts must be a list")
    output_root = Path(out_dir)
    extracted: list[dict[str, Any]] = []
    for artifact in source_artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("provider delivery worker bundle source artifact must be an object")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("provider delivery worker bundle source artifact name is required")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ValueError(f"provider delivery worker bundle source artifact content_b64 invalid: {name}") from exc
        actual_sha = _sha256_ref(data)
        if artifact.get("sha256") != actual_sha:
            raise ValueError(f"provider delivery worker bundle source artifact sha256 mismatch: {name}")
        target = output_root / _artifact_extract_filename(name)
        if target.exists():
            if target.is_dir():
                raise ValueError(f"provider delivery worker bundle output path is a directory: {target}")
            if not overwrite:
                raise ValueError(f"provider delivery worker bundle output already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append(
            {
                "name": name,
                "artifact_type": artifact.get("artifact_type"),
                "path": artifact.get("path"),
                "sha256": actual_sha,
                "bytes": len(data),
                "artifact_id": artifact.get("artifact_id"),
                "extracted_to": str(target),
            }
        )
    return extracted


def append_provider_delivery_worker_bundle(
    chain: EvidenceChain,
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_delivery_worker_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid provider delivery worker bundle: " + "; ".join(result.errors))
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
    return chain.append(PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def _payload_artifact_replay_from_paths(
    delivery: dict[str, Any],
    payload: dict[str, Any] | None,
    artifact_paths: dict[str, str | Path],
) -> tuple[str | Path | None, bytes | None]:
    payload_artifact = delivery.get("payload_artifact")
    if payload_artifact is None:
        return None, None
    if not isinstance(payload_artifact, dict):
        return None, None
    if payload is None:
        raise ValueError("provider delivery worker bundle payload source is required to replay retained delivery payload artifact")
    payload_path = artifact_paths.get("payload")
    if payload_path is None:
        raise ValueError("provider delivery worker bundle payload artifact path is required to replay retained delivery payload artifact")
    replay_path = payload_artifact.get("path") or payload_path
    return replay_path, Path(payload_path).read_bytes()


def _payload_artifact_replay_from_artifacts(
    source_artifacts: Any,
    source_values: dict[str, Any],
    errors: list[str],
) -> tuple[str | None, bytes | None]:
    delivery = source_values.get("delivery")
    payload_artifact = delivery.get("payload_artifact") if isinstance(delivery, dict) else None
    if payload_artifact is None:
        return None, None
    if not isinstance(payload_artifact, dict):
        return None, None
    if "payload" not in source_values:
        errors.append("provider delivery worker bundle payload source is required to replay retained delivery payload artifact")
        return None, None
    if not isinstance(source_artifacts, list):
        return None, None
    payload_artifacts = [artifact for artifact in source_artifacts if isinstance(artifact, dict) and artifact.get("name") == "payload"]
    if not payload_artifacts:
        errors.append("provider delivery worker bundle source artifact payload is required to replay retained delivery payload artifact")
        return None, None
    replay_path = payload_artifact.get("path")
    if not isinstance(replay_path, str) or not replay_path.strip():
        errors.append("provider delivery worker bundle delivery payload_artifact.path is required for retained payload artifact replay")
        return None, None
    try:
        data = base64.b64decode(str(payload_artifacts[0].get("content_b64") or ""), validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        errors.append(f"provider delivery worker bundle source artifact content_b64 invalid: payload: {exc}")
        return None, None
    return replay_path, data


def _source_objects(**objects: Any) -> dict[str, Any]:
    return {name: _clone(value) for name, value in objects.items() if value is not None}


def _required_source_objects(sources: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    supported = {name for name, _ in SOURCE_TYPES}
    for name in sources:
        if name not in supported:
            errors.append(f"provider delivery worker bundle sources.{name} is unsupported")
    for name in REQUIRED_SOURCES:
        value = sources.get(name)
        if not isinstance(value, dict):
            errors.append(f"provider delivery worker bundle sources.{name} is required")
        else:
            values[name] = value
    for name, _ in SOURCE_TYPES:
        if name in REQUIRED_SOURCES or name not in sources:
            continue
        value = sources.get(name)
        if name == "provider_audit_log":
            if not isinstance(value, (dict, list)):
                errors.append("provider delivery worker bundle sources.provider_audit_log must be an object or array")
            else:
                values[name] = value
        elif not isinstance(value, dict):
            errors.append(f"provider delivery worker bundle sources.{name} must be an object")
        else:
            values[name] = value
    return values if REQUIRED_SOURCES <= set(values) else {}


def _build_source_artifacts(artifact_paths: dict[str, str | Path], sources: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    artifact_types = dict(SOURCE_TYPES)
    for name in [source_name for source_name, _ in SOURCE_TYPES if source_name in sources]:
        path = artifact_paths.get(name)
        if path is None:
            raise ValueError(f"provider delivery worker bundle artifact path is required: {name}")
        source = Path(path)
        data = source.read_bytes()
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"provider delivery worker bundle artifact JSON invalid: {name}: {exc}") from exc
        parsed_hash = content_hash(parsed)
        expected_hash = content_hash(sources[name])
        if parsed_hash != expected_hash:
            raise ValueError(f"provider delivery worker bundle artifact content hash mismatch: {name}")
        body = {
            "name": name,
            "artifact_type": artifact_types[name],
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


def _verify_source_artifacts(value: Any, source_objects: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append("provider delivery worker bundle source_artifacts must be a list")
        return
    expected_names = set(source_objects)
    actual_names: set[str] = set()
    supported = dict(SOURCE_TYPES)
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("provider delivery worker bundle source artifact must be an object")
            continue
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"provider delivery worker bundle source artifact id mismatch: {artifact.get('name')}")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            errors.append("provider delivery worker bundle source artifact name is required")
            continue
        actual_names.add(name)
        if name not in supported:
            errors.append(f"provider delivery worker bundle source artifact unsupported: {name}")
            continue
        if artifact.get("artifact_type") != supported[name]:
            errors.append(f"provider delivery worker bundle source artifact type mismatch: {name}")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (ValueError, TypeError) as exc:
            errors.append(f"provider delivery worker bundle source artifact content_b64 invalid: {name}: {exc}")
            continue
        actual_sha = _sha256_ref(data)
        if artifact.get("sha256") != actual_sha:
            errors.append(f"provider delivery worker bundle source artifact sha256 mismatch: {name}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"provider delivery worker bundle source artifact size mismatch: {name}")
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"provider delivery worker bundle source artifact JSON invalid: {name}: {exc}")
            continue
        parsed_hash = content_hash(parsed)
        if artifact.get("content_hash") != parsed_hash:
            errors.append(f"provider delivery worker bundle source artifact content hash mismatch: {name}")
        source_object = source_objects.get(name)
        if source_object is None:
            errors.append(f"provider delivery worker bundle source artifact has no embedded source: {name}")
        elif content_hash(source_object) != parsed_hash:
            errors.append(f"provider delivery worker bundle source artifact does not match embedded source: {name}")
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing:
        errors.append("provider delivery worker bundle source artifacts missing: " + ", ".join(missing))
    if extra:
        errors.append("provider delivery worker bundle source artifacts unsupported for embedded sources: " + ", ".join(extra))


def _source_summary(receipt: dict[str, Any], service_attestation: dict[str, Any], delivery: dict[str, Any]) -> dict[str, Any]:
    worker = receipt.get("worker", {}) if isinstance(receipt.get("worker"), dict) else {}
    dispatch = receipt.get("dispatch", {}) if isinstance(receipt.get("dispatch"), dict) else {}
    source_delivery = receipt.get("source_delivery", {}) if isinstance(receipt.get("source_delivery"), dict) else {}
    provider_audit = receipt.get("provider_audit", {}) if isinstance(receipt.get("provider_audit"), dict) else {}
    provider_response = receipt.get("provider_response", {}) if isinstance(receipt.get("provider_response"), dict) else {}
    body = {
        "worker_operation_id": receipt.get("worker_operation_id"),
        "worker_receipt_hash": content_hash(receipt),
        "service_attestation_id": service_attestation.get("attestation_id"),
        "service_attestation_hash": content_hash(service_attestation),
        "delivery_id": delivery.get("delivery_id"),
        "delivery_hash": content_hash(delivery),
        "provider": delivery.get("provider") or source_delivery.get("provider"),
        "run_ref": worker.get("run_ref"),
        "operation_kind": worker.get("operation_kind"),
        "destination_ref": dispatch.get("destination_ref"),
        "response_status": dispatch.get("response_status"),
        "provider_response_artifact_hash": provider_response.get("artifact_hash"),
        "provider_audit_correlation_id": provider_audit.get("correlation_id"),
        "provider_audit_log_hash": provider_audit.get("audit_log_hash"),
    }
    return {key: value for key, value in body.items() if value is not None}


def _bundle_summary(receipt: dict[str, Any], sources: dict[str, Any], source_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    provider_response = receipt.get("provider_response") if isinstance(receipt.get("provider_response"), dict) else None
    provider_audit = receipt.get("provider_audit") if isinstance(receipt.get("provider_audit"), dict) else None
    artifact_names = {artifact.get("name") for artifact in source_artifacts if isinstance(artifact, dict)}
    delivery = sources.get("delivery") if isinstance(sources.get("delivery"), dict) else {}
    payload_artifact = delivery.get("payload_artifact") if isinstance(delivery, dict) else None
    return {
        "source_artifact_count": len(source_artifacts),
        "source_artifact_sha256_root": content_hash([artifact.get("sha256") for artifact in source_artifacts]),
        "source_artifact_content_root": content_hash([artifact.get("content_hash") for artifact in source_artifacts]),
        "source_object_hashes": {name: content_hash(value) for name, value in sorted(sources.items())},
        "provider_response_replayed": provider_response is not None and "provider_response" in sources,
        "provider_audit_replayed": provider_audit is not None and "provider_audit_correlation" in sources and "provider_audit_log" in sources,
        "retained_payload_artifact_replayed": isinstance(payload_artifact, dict) and "payload" in sources and "payload" in artifact_names,
        "worker_control_summary": _status_summary(receipt.get("controls", [])),
    }


def _controls(receipt: dict[str, Any], sources: dict[str, Any], source_artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    artifact_names = {artifact.get("name") for artifact in source_artifacts if isinstance(artifact, dict)}
    provider_response = receipt.get("provider_response") if isinstance(receipt.get("provider_response"), dict) else None
    provider_audit = receipt.get("provider_audit") if isinstance(receipt.get("provider_audit"), dict) else None
    delivery = sources.get("delivery") if isinstance(sources.get("delivery"), dict) else {}
    payload_artifact = delivery.get("payload_artifact") if isinstance(delivery, dict) else None
    retained_payload_replayed = isinstance(payload_artifact, dict) and "payload" in sources and "payload" in artifact_names
    return [
        {
            "name": "worker-receipt-offline-replay",
            "status": "passed" if REQUIRED_SOURCES <= set(sources) else "failed",
            "detail": "Embedded worker receipt, service attestation, and delivery receipt replay through the provider delivery worker verifier.",
        },
        {
            "name": "source-artifact-byte-binding",
            "status": "passed" if set(sources) == artifact_names else "failed",
            "detail": "Embedded raw JSON source bytes match the parsed source objects by SHA-256 and canonical content hash.",
        },
        {
            "name": "retained-payload-artifact-replay",
            "status": "passed" if retained_payload_replayed else "not-applicable",
            "detail": "Embedded payload bytes replay the retained delivery payload artifact recorded by the signed delivery receipt when present.",
        },
        {
            "name": "provider-response-artifact-replay",
            "status": "passed" if provider_response and "provider_response" in sources else "not-applicable",
            "detail": "Provider response bytes are embedded and replayed when the worker receipt records a provider response artifact.",
        },
        {
            "name": "provider-audit-log-replay",
            "status": "passed" if provider_audit and "provider_audit_correlation" in sources and "provider_audit_log" in sources else "not-applicable",
            "detail": "Provider audit correlation and provider-owned audit-log export are embedded and replayed when the worker receipt records provider audit evidence.",
        },
        {
            "name": "raw-secret-scan",
            "status": "passed",
            "detail": "Secret-like source fields must be redacted references or hash/root/ref metadata before bundle verification succeeds.",
        },
    ]


def _default_bundle_ref(receipt: dict[str, Any]) -> str:
    return f"provider-delivery-worker-bundle:{receipt.get('worker_operation_id', 'unknown')}"


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            status = str(item.get("status", "unknown"))
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _artifact_extract_filename(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_") + ".json"


def _markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"provider delivery worker bundle secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if value is None:
        return True
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and value.startswith("sha256:"):
        return True
    return False