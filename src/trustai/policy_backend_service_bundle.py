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
from .policy_backend_service import verify_policy_backend_service_attestation

POLICY_BACKEND_SERVICE_BUNDLE_SCHEMA = "trustai.policy-backend-service-bundle/0.1"
POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE = "policy_backend.service_bundle_exported"
POLICY_BACKEND_SERVICE_BUNDLE_MODES = {"offline-review", "auditor-review", "regulator-review"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

SOURCE_TYPES: tuple[tuple[str, str], ...] = (
    ("service_attestation", "policy-backend-service-attestation"),
    ("enforcement", "policy-backend-enforcement"),
    ("policy_pack", "policy-pack"),
    ("runtime_action", "runtime-action"),
    ("proof_pack", "proof-pack"),
    ("policy_decision", "policy-decision"),
    ("policy_export", "policy-export"),
    ("policy_engine_receipt", "policy-engine-receipt"),
)
REQUIRED_SOURCES = {
    "service_attestation",
    "enforcement",
    "policy_pack",
    "runtime_action",
    "proof_pack",
    "policy_decision",
    "policy_export",
}


@dataclass
class PolicyBackendServiceBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_policy_backend_service_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("policy backend service bundle must contain an object")
    return value


def write_policy_backend_service_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_policy_backend_service_bundle(
    service_attestation: dict[str, Any],
    enforcement: dict[str, Any],
    policy_pack: dict[str, Any],
    runtime_action: dict[str, Any],
    proof_pack: dict[str, Any],
    policy_decision: dict[str, Any],
    policy_export: dict[str, Any],
    *,
    policy_engine_receipt: dict[str, Any] | None = None,
    artifact_paths: dict[str, str | Path],
    mode: str = "offline-review",
    environment: str | None = None,
    reviewer_ref: str,
    bundle_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in POLICY_BACKEND_SERVICE_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(POLICY_BACKEND_SERVICE_BUNDLE_MODES)}")
    if not isinstance(reviewer_ref, str) or not reviewer_ref.strip():
        raise ValueError("policy backend service bundle reviewer_ref is required")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    replay = verify_policy_backend_service_attestation(
        service_attestation,
        enforcement,
        policy_pack=policy_pack,
        action=runtime_action,
        proof_pack=proof_pack,
        decision=policy_decision,
        policy_export=policy_export,
        policy_engine_receipt=policy_engine_receipt,
        key=key,
    )
    if not replay.ok:
        raise ValueError("invalid policy backend service source: " + "; ".join(replay.errors))

    sources = _source_objects(
        service_attestation=service_attestation,
        enforcement=enforcement,
        policy_pack=policy_pack,
        runtime_action=runtime_action,
        proof_pack=proof_pack,
        policy_decision=policy_decision,
        policy_export=policy_export,
        policy_engine_receipt=policy_engine_receipt,
    )
    secret_errors: list[str] = []
    _check_no_secret_values(sources, secret_errors)
    if secret_errors:
        raise ValueError("policy backend service bundle source contains secret-like values: " + "; ".join(secret_errors))

    source_artifacts = _build_source_artifacts(artifact_paths, sources)
    body: dict[str, Any] = {
        "schema": POLICY_BACKEND_SERVICE_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment or service_attestation.get("environment") or enforcement.get("environment"),
        "generated_at": timestamp,
        "reviewer_ref": reviewer_ref,
        "bundle_ref": bundle_ref or _default_bundle_ref(service_attestation),
        "source": _source_summary(service_attestation, enforcement, policy_pack, runtime_action),
        "sources": sources,
        "source_artifacts": source_artifacts,
        "summary": _bundle_summary(service_attestation, enforcement, sources, source_artifacts),
        "controls": _controls(service_attestation, enforcement, sources, source_artifacts),
        "limitations": [
            "This bundle is self-contained for offline review of one policy backend service attestation and its replay sources.",
            "It embeds parsed source objects and raw JSON bytes so reviewers can detect source swaps without original local file paths.",
            "It proves replay against supplied OPA/Cedar service, enforcement, policy, proof-pack, export, and decision evidence; it does not claim continuously operated live backend fleets beyond the embedded receipts.",
        ],
    }
    bundle_id = content_hash(body)
    return {
        **body,
        "bundle_id": bundle_id,
        "signatures": [sign_value({"bundle_id": bundle_id, "policy_backend_service_bundle": body}, key)],
    }


def verify_policy_backend_service_bundle(
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> PolicyBackendServiceBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if bundle.get("schema") != POLICY_BACKEND_SERVICE_BUNDLE_SCHEMA:
        errors.append(f"unsupported policy backend service bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    if bundle.get("bundle_id") != content_hash(body):
        errors.append("bundle_id does not match canonical policy backend service bundle body")

    signatures = bundle.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("policy backend service bundle must include at least one signature")
    else:
        signed = {"bundle_id": bundle.get("bundle_id"), "policy_backend_service_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed, signature, key) for signature in signatures):
            errors.append("policy backend service bundle signature verification failed")

    if bundle.get("mode") not in POLICY_BACKEND_SERVICE_BUNDLE_MODES:
        errors.append("policy backend service bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"policy backend service bundle generated_at invalid: {exc}")
    if not isinstance(bundle.get("reviewer_ref"), str) or not bundle.get("reviewer_ref", "").strip():
        errors.append("policy backend service bundle reviewer_ref is required")

    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        errors.append("policy backend service bundle sources must be an object")
        sources = {}
    source_values = _required_source_objects(sources, errors)
    if source_values:
        replay = verify_policy_backend_service_attestation(
            source_values["service_attestation"],
            source_values["enforcement"],
            policy_pack=source_values["policy_pack"],
            action=source_values["runtime_action"],
            proof_pack=source_values["proof_pack"],
            decision=source_values["policy_decision"],
            policy_export=source_values["policy_export"],
            policy_engine_receipt=source_values.get("policy_engine_receipt"),
            key=key,
        )
        errors.extend("policy backend service bundle source replay: " + error for error in replay.errors)
        warnings.extend(replay.warnings)
        _verify_source_artifacts(bundle.get("source_artifacts"), source_values, errors)
        if bundle.get("source") != _source_summary(
            source_values["service_attestation"],
            source_values["enforcement"],
            source_values["policy_pack"],
            source_values["runtime_action"],
        ):
            errors.append("policy backend service bundle source summary does not match embedded sources")
        artifacts = bundle.get("source_artifacts") if isinstance(bundle.get("source_artifacts"), list) else []
        if bundle.get("summary") != _bundle_summary(
            source_values["service_attestation"],
            source_values["enforcement"],
            source_values,
            artifacts,
        ):
            errors.append("policy backend service bundle summary does not match embedded sources")
        if bundle.get("controls") != _controls(source_values["service_attestation"], source_values["enforcement"], source_values, artifacts):
            errors.append("policy backend service bundle controls do not match embedded sources")

    _check_no_secret_values(bundle, errors)
    return PolicyBackendServiceBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def write_policy_backend_service_bundle_markdown(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_policy_backend_service_bundle_markdown(bundle), encoding="utf-8")


def render_policy_backend_service_bundle_markdown(bundle: dict[str, Any]) -> str:
    source = bundle.get("source", {}) if isinstance(bundle.get("source"), dict) else {}
    summary = bundle.get("summary", {}) if isinstance(bundle.get("summary"), dict) else {}
    controls = bundle.get("controls", []) if isinstance(bundle.get("controls"), list) else []
    artifacts = bundle.get("source_artifacts", []) if isinstance(bundle.get("source_artifacts"), list) else []
    control_rows = "\n".join(
        "| {name} | {status} | {detail} |".format(
            name=_cell(control.get("name", "")),
            status=_cell(control.get("status", "")),
            detail=_cell(control.get("detail", "")),
        )
        for control in controls
        if isinstance(control, dict)
    )
    artifact_rows = "\n".join(
        "| {name} | {artifact_type} | {size} | `{sha}` | `{content_hash}` |".format(
            name=_cell(artifact.get("name", "")),
            artifact_type=_cell(artifact.get("artifact_type", "")),
            size=artifact.get("size_bytes", 0),
            sha=artifact.get("sha256", ""),
            content_hash=artifact.get("content_hash", ""),
        )
        for artifact in artifacts
        if isinstance(artifact, dict)
    )
    source_hashes = summary.get("source_object_hashes", {}) if isinstance(summary.get("source_object_hashes"), dict) else {}
    source_hash_lines = "\n".join(f"- {name}: `{value}`" for name, value in sorted(source_hashes.items()))
    limitations = "\n".join(f"- {limitation}" for limitation in bundle.get("limitations", []))
    return f"""# TrustAI Policy Backend Service Bundle

Bundle ID: `{bundle.get('bundle_id', '')}`

Bundle ref: `{bundle.get('bundle_ref', '')}`

Mode: `{bundle.get('mode', '')}`

Environment: `{bundle.get('environment', '')}`

Generated at: `{bundle.get('generated_at', '')}`

Reviewer: `{bundle.get('reviewer_ref', '')}`

## Source

- Service attestation ID: `{source.get('service_attestation_id', '')}`
- Service ref: `{source.get('service_ref', '')}`
- Enforcement ID: `{source.get('enforcement_id', '')}`
- Backend ref: `{source.get('backend_ref', '')}`
- Engine: `{source.get('engine', '')}`
- Endpoint: `{source.get('endpoint_url', '')}`
- Policy pack: `{source.get('policy_pack_id', '')}`
- Runtime action: `{source.get('runtime_action_id', '')}`
- Decision outcome: `{source.get('decision_outcome', '')}`
- Decision log root: `{source.get('decision_log_root', '')}`
- Audit log root: `{source.get('audit_log_root', '')}`

## Embedded Source Summary

- Embedded source artifacts: {summary.get('source_artifact_count', 0)}
- Policy engine receipt replayed: {summary.get('policy_engine_receipt_replayed', False)}
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


def extract_policy_backend_service_bundle_sources(
    bundle: dict[str, Any],
    out_dir: str | Path,
    *,
    key: str | None = None,
    overwrite: bool = False,
) -> list[dict[str, Any]]:
    result = verify_policy_backend_service_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid policy backend service bundle: " + "; ".join(result.errors))
    artifacts = bundle.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("policy backend service bundle source_artifacts must be a list")
    output_root = Path(out_dir)
    extracted: list[dict[str, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("policy backend service bundle source artifact must be an object")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("policy backend service bundle source artifact name is required")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ValueError(f"policy backend service bundle source artifact content_b64 invalid: {name}") from exc
        if artifact.get("sha256") != _sha256_ref(data):
            raise ValueError(f"policy backend service bundle source artifact sha256 mismatch: {name}")
        target = output_root / _extract_name(name)
        if target.exists():
            if target.is_dir():
                raise ValueError(f"policy backend service bundle output path is a directory: {target}")
            if not overwrite:
                raise ValueError(f"policy backend service bundle output already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append(
            {
                "name": name,
                "artifact_type": artifact.get("artifact_type"),
                "path": artifact.get("path"),
                "sha256": artifact.get("sha256"),
                "bytes": len(data),
                "artifact_id": artifact.get("artifact_id"),
                "extracted_to": str(target),
            }
        )
    return extracted


def append_policy_backend_service_bundle(
    chain: EvidenceChain,
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_policy_backend_service_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid policy backend service bundle: " + "; ".join(result.errors))
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
    return chain.append(POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def _source_objects(**objects: Any) -> dict[str, Any]:
    return {name: _clone(value) for name, value in objects.items() if value is not None}


def _required_source_objects(sources: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    supported = {name for name, _ in SOURCE_TYPES}
    for name in sources:
        if name not in supported:
            errors.append(f"policy backend service bundle sources.{name} is unsupported")
    for name in REQUIRED_SOURCES:
        value = sources.get(name)
        if not isinstance(value, dict):
            errors.append(f"policy backend service bundle sources.{name} is required")
        else:
            values[name] = value
    if "policy_engine_receipt" in sources:
        if not isinstance(sources.get("policy_engine_receipt"), dict):
            errors.append("policy backend service bundle sources.policy_engine_receipt must be an object")
        else:
            values["policy_engine_receipt"] = sources["policy_engine_receipt"]
    return values if REQUIRED_SOURCES <= set(values) else {}


def _build_source_artifacts(artifact_paths: dict[str, str | Path], sources: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    types = dict(SOURCE_TYPES)
    for name in [source_name for source_name, _ in SOURCE_TYPES if source_name in sources]:
        path = artifact_paths.get(name)
        if path is None:
            raise ValueError(f"policy backend service bundle artifact path is required: {name}")
        artifacts.append(_json_artifact(name, types[name], path, sources[name]))
    return artifacts


def _json_artifact(name: str, artifact_type: str, path: str | Path, expected: Any) -> dict[str, Any]:
    data = Path(path).read_bytes()
    try:
        parsed = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"policy backend service bundle artifact JSON invalid: {name}: {exc}") from exc
    parsed_hash = content_hash(parsed)
    expected_hash = content_hash(expected)
    if parsed_hash != expected_hash:
        raise ValueError(f"policy backend service bundle artifact content hash mismatch: {name}")
    body = {
        "name": name,
        "artifact_type": artifact_type,
        "path": str(path).replace("\\", "/"),
        "media_type": "application/json" if Path(path).suffix.lower() == ".json" else "application/octet-stream",
        "size_bytes": len(data),
        "sha256": _sha256_ref(data),
        "content_hash": parsed_hash,
        "expected_content_hash": expected_hash,
        "content_b64": base64.b64encode(data).decode("ascii"),
    }
    return {**body, "artifact_id": content_hash(body)}


def _verify_source_artifacts(value: Any, source_objects: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append("policy backend service bundle source_artifacts must be a list")
        return
    expected_names = set(source_objects)
    actual_names: set[str] = set()
    types = dict(SOURCE_TYPES)
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("policy backend service bundle source artifact must be an object")
            continue
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"policy backend service bundle source artifact id mismatch: {artifact.get('name')}")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            errors.append("policy backend service bundle source artifact name is required")
            continue
        actual_names.add(name)
        if name not in types:
            errors.append(f"policy backend service bundle source artifact unsupported: {name}")
            continue
        if artifact.get("artifact_type") != types[name]:
            errors.append(f"policy backend service bundle source artifact type mismatch: {name}")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            errors.append(f"policy backend service bundle source artifact content_b64 invalid: {name}: {exc}")
            continue
        if artifact.get("sha256") != _sha256_ref(data):
            errors.append(f"policy backend service bundle source artifact sha256 mismatch: {name}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"policy backend service bundle source artifact size mismatch: {name}")
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"policy backend service bundle source artifact JSON invalid: {name}: {exc}")
            continue
        parsed_hash = content_hash(parsed)
        if artifact.get("content_hash") != parsed_hash:
            errors.append(f"policy backend service bundle source artifact content hash mismatch: {name}")
        source_object = source_objects.get(name)
        if source_object is None:
            errors.append(f"policy backend service bundle source artifact has no embedded source: {name}")
        elif content_hash(source_object) != parsed_hash:
            errors.append(f"policy backend service bundle source artifact does not match embedded source: {name}")
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing:
        errors.append("policy backend service bundle source artifacts missing: " + ", ".join(missing))
    if extra:
        errors.append("policy backend service bundle source artifacts unsupported for embedded sources: " + ", ".join(extra))


def _source_summary(
    service_attestation: dict[str, Any],
    enforcement: dict[str, Any],
    policy_pack: dict[str, Any],
    runtime_action: dict[str, Any],
) -> dict[str, Any]:
    service = service_attestation.get("service", {}) if isinstance(service_attestation.get("service"), dict) else {}
    operation = service_attestation.get("operation", {}) if isinstance(service_attestation.get("operation"), dict) else {}
    audit_log = service_attestation.get("audit_log", {}) if isinstance(service_attestation.get("audit_log"), dict) else {}
    backend = enforcement.get("backend", {}) if isinstance(enforcement.get("backend"), dict) else {}
    decision = enforcement.get("decision", {}) if isinstance(enforcement.get("decision"), dict) else {}
    body = {
        "service_attestation_id": service_attestation.get("attestation_id"),
        "service_attestation_hash": content_hash(service_attestation),
        "service_ref": service.get("service_ref"),
        "service_version": service.get("version"),
        "enforcement_id": enforcement.get("enforcement_id"),
        "enforcement_hash": content_hash(enforcement),
        "engine": service.get("engine") or backend.get("engine"),
        "backend_ref": service.get("backend_ref") or backend.get("backend_ref"),
        "endpoint_url": service.get("endpoint_url") or backend.get("endpoint_url"),
        "bundle_ref": service.get("bundle_ref") or backend.get("bundle_ref"),
        "bundle_hash": service.get("bundle_hash") or backend.get("bundle_hash"),
        "policy_pack_id": policy_pack.get("id"),
        "policy_pack_version": policy_pack.get("version"),
        "runtime_action_id": runtime_action.get("id"),
        "runtime_action_type": runtime_action.get("type"),
        "decision_hash": decision.get("hash"),
        "decision_outcome": decision.get("outcome"),
        "decision_passed": decision.get("passed"),
        "decision_log_root": operation.get("decision_log_root"),
        "audit_log_root": audit_log.get("root"),
    }
    return {key: value for key, value in body.items() if value is not None}


def _bundle_summary(
    service_attestation: dict[str, Any],
    enforcement: dict[str, Any],
    sources: dict[str, Any],
    source_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "source_artifact_count": len(source_artifacts),
        "source_artifact_sha256_root": content_hash([artifact.get("sha256") for artifact in source_artifacts]),
        "source_artifact_content_root": content_hash([artifact.get("content_hash") for artifact in source_artifacts]),
        "source_object_hashes": {name: content_hash(value) for name, value in sorted(sources.items())},
        "policy_engine_receipt_replayed": "policy_engine_receipt" in sources,
        "service_control_summary": _status_summary(service_attestation.get("controls", [])),
        "enforcement_control_summary": _status_summary(enforcement.get("controls", [])),
    }


def _controls(
    service_attestation: dict[str, Any],
    enforcement: dict[str, Any],
    sources: dict[str, Any],
    source_artifacts: list[dict[str, Any]],
) -> list[dict[str, str]]:
    artifact_names = {artifact.get("name") for artifact in source_artifacts if isinstance(artifact, dict)}
    service = service_attestation.get("service", {}) if isinstance(service_attestation.get("service"), dict) else {}
    operation = service_attestation.get("operation", {}) if isinstance(service_attestation.get("operation"), dict) else {}
    audit_log = service_attestation.get("audit_log", {}) if isinstance(service_attestation.get("audit_log"), dict) else {}
    backend = enforcement.get("backend", {}) if isinstance(enforcement.get("backend"), dict) else {}
    return [
        {
            "name": "service-attestation-offline-replay",
            "status": "passed" if REQUIRED_SOURCES <= set(sources) else "failed",
            "detail": "Embedded service attestation replays through the policy backend service verifier with embedded enforcement, policy, action, proof-pack, decision, and export sources.",
        },
        {
            "name": "source-artifact-byte-binding",
            "status": "passed" if artifact_names == set(sources) else "failed",
            "detail": "Embedded raw JSON source bytes match parsed source objects by SHA-256 and canonical content hash.",
        },
        {
            "name": "policy-engine-receipt-replay",
            "status": "passed" if "policy_engine_receipt" in sources else "not-applicable",
            "detail": "Policy engine decision receipt is embedded and replayed when the service attestation was built with one.",
        },
        {
            "name": "hosted-backend-endpoint-binding",
            "status": "passed" if service.get("endpoint_url") == backend.get("endpoint_url") and str(service.get("endpoint_url", "")).startswith("https://") else "failed",
            "detail": "Service endpoint, backend endpoint, OPA/Cedar engine, and bundle hash are visible for offline review.",
        },
        {
            "name": "decision-and-audit-root-review",
            "status": "passed" if operation.get("decision_log_root") and audit_log.get("root") else "failed",
            "detail": "Decision-log and audit-log roots are exposed in the signed bundle summary.",
        },
        {
            "name": "raw-secret-scan",
            "status": "passed",
            "detail": "Secret-like source fields must be redacted references or hash/root/ref metadata before bundle verification succeeds.",
        },
    ]


def _default_bundle_ref(service_attestation: dict[str, Any]) -> str:
    return f"policy-backend-service-bundle:{service_attestation.get('attestation_id', 'unknown')}"


def _status_summary(items: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _extract_name(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_") + ".json"


def _cell(value: Any) -> str:
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
                    errors.append(f"policy backend service bundle secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str, value: Any) -> bool:
    if value is None:
        return True
    if key in {"timestamp_token", "timestamp_tokens"}:
        return True
    if key.endswith("_ref") and isinstance(value, str) and bool(value.strip()):
        return True
    if key.endswith("_refs") and isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        return True
    if (key.endswith("_root") or key.endswith("_hash")) and isinstance(value, str) and value.startswith("sha256:"):
        return True
    return False
