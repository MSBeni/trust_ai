from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .framework_adapter_matrix import verify_framework_adapter_matrix
from .framework_hook_release import verify_framework_hook_release
from .framework_runtime_service_authority import FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_SCHEMA

FRAMEWORK_ADAPTER_AUTHORITY_SCHEMA = "trustai.framework-adapter-production-authority-dossier/0.1"
FRAMEWORK_ADAPTER_AUTHORITY_ENTRY_TYPE = "framework_adapter.production_authority_recorded"
FRAMEWORK_ADAPTER_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "exact-runtime-release-matrix", "title": "Exact framework runtime package/version coverage matrix for supported native hooks", "authority_kinds": ["provider-api", "hosted-service", "ci-run"]},
    {"id": "native-hook-package-provenance", "title": "Native hook package build provenance, source artifacts, and release signatures", "authority_kinds": ["ci-run", "provider-api", "cloud-object-lock"]},
    {"id": "maintained-adapter-release-cadence", "title": "Maintained adapter release cadence and compatibility refresh schedule", "authority_kinds": ["hosted-service", "ci-run", "customer"]},
    {"id": "fixture-regression-replay", "title": "Regression replay of framework fixtures and adapter event hash chains", "authority_kinds": ["ci-run", "hosted-service"]},
    {"id": "production-runtime-provider-certification", "title": "Production runtime provider certification or managed runtime export for native hooks", "authority_kinds": ["provider-api", "hosted-service", "customer"]},
    {"id": "collector-schema-compatibility", "title": "Collector schema compatibility for OTel GenAI and TrustAI adapter event attributes", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "immutable-release-artifacts", "title": "Immutable retention for hook releases, matrices, source artifacts, and generated receipts", "authority_kinds": ["cloud-object-lock", "provider-api", "customer"]},
    {"id": "supply-chain-vulnerability-attestation", "title": "Supply-chain vulnerability, dependency, and SBOM attestation for adapter packages", "authority_kinds": ["ci-run", "provider-api", "customer"]},
    {"id": "deprecation-and-upgrade-sla", "title": "Deprecation, upgrade, and framework release-tracking SLA for supported adapters", "authority_kinds": ["customer", "hosted-service"]},
    {"id": "runtime-service-authority-binding", "title": "Framework runtime service production authority binding for live collector/runtime operations", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "tenant-rollout-and-rollback-controls", "title": "Tenant rollout, canary, rollback, and compatibility-break response controls", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class FrameworkAdapterAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_framework_adapter_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework adapter authority dossier must contain an object")
    return value


def write_framework_adapter_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_framework_adapter_authority_evidence_arg(value: str) -> dict[str, Any]:
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


def build_framework_adapter_authority_dossier(
    matrix: dict[str, Any],
    release: dict[str, Any],
    *,
    runtime_service_authority: dict[str, Any] | None = None,
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
    if mode not in FRAMEWORK_ADAPTER_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(FRAMEWORK_ADAPTER_AUTHORITY_MODES)}")
    for value, field in ((environment, "environment"), (dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)

    matrix_result = verify_framework_adapter_matrix(matrix, root=root, key=key)
    if not matrix_result.ok:
        raise ValueError("invalid framework adapter matrix source: " + "; ".join(matrix_result.errors))
    release_result = verify_framework_hook_release(release, matrix, root=root, key=key)
    if not release_result.ok:
        raise ValueError("invalid framework hook release source: " + "; ".join(release_result.errors))
    if runtime_service_authority is not None:
        runtime_errors: list[str] = []
        _verify_runtime_service_authority_reference(runtime_service_authority, runtime_errors, [], key=key)
        if runtime_errors:
            raise ValueError("invalid framework runtime service authority source: " + "; ".join(runtime_errors))

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    binding = _source_binding(matrix, release, runtime_service_authority)
    source_context = _authority_evidence_source_context(binding)
    evidence_items = [_build_authority_evidence_item(item, source_context) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": FRAMEWORK_ADAPTER_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment,
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
            "This dossier binds a signed framework adapter matrix and hook release receipt to a production-authority evidence checklist for maintained native runtime hooks.",
            "It records hashes, authority references, freshness windows, and missing live-evidence categories for production framework adapter claims.",
            "It does not claim production-certified framework adapters unless mode is production-dossier and every required authority category has fresh external evidence plus runtime service authority binding.",
        ],
    }
    dossier_id = content_hash(body)
    signed_value = {"dossier_id": dossier_id, "framework_adapter_authority": body}
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value(signed_value, key)]}


def verify_framework_adapter_authority_dossier(
    dossier: dict[str, Any],
    *,
    matrix: dict[str, Any] | None = None,
    release: dict[str, Any] | None = None,
    runtime_service_authority: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> FrameworkAdapterAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != FRAMEWORK_ADAPTER_AUTHORITY_SCHEMA:
        errors.append(f"unsupported framework adapter authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical framework adapter authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework adapter authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "framework_adapter_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework adapter authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in FRAMEWORK_ADAPTER_AUTHORITY_MODES:
        errors.append("framework adapter authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"framework adapter authority mode is {mode}; live production adapter authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"framework adapter authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"framework adapter authority {field} is required")

    _verify_source_binding(dossier.get("source_binding"), matrix, release, runtime_service_authority, errors, warnings, root=root, key=key)
    _verify_required_authority(dossier.get("required_production_authority"), errors)

    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("framework adapter authority authority_evidence must be a list")
        evidence = []
    evidence_source_context = _authority_evidence_source_context(
        dossier.get("source_binding") if isinstance(dossier.get("source_binding"), dict) else {}
    )
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("framework adapter authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_counts[
            _verify_authority_evidence_item(
                item,
                errors,
                warnings,
                now=freshness_now,
                require_fresh=require_fresh,
                source_context=evidence_source_context,
            )
        ] += 1

    evidence_dicts = [item for item in evidence if isinstance(item, dict)]
    expected_summary = _summary(evidence_dicts)
    if dossier.get("summary") != expected_summary:
        errors.append("framework adapter authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("framework adapter authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("framework adapter authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every framework adapter authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every framework adapter authority evidence item to be fresh")
    binding_for_controls = dossier.get("source_binding") if isinstance(dossier.get("source_binding"), dict) else {}
    if mode == "production-dossier" and not _source_binding_complete(binding_for_controls):
        errors.append("production-dossier mode requires matrix, hook release, and runtime service authority bindings")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("framework adapter authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), binding_for_controls, evidence_dicts, expected_summary):
        errors.append("framework adapter authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)

    return FrameworkAdapterAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_framework_adapter_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    matrix: dict[str, Any],
    release: dict[str, Any],
    runtime_service_authority: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_adapter_authority_dossier(
        dossier,
        matrix=matrix,
        release=release,
        runtime_service_authority=runtime_service_authority,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid framework adapter authority dossier: " + "; ".join(result.errors))
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
    return chain.append(FRAMEWORK_ADAPTER_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _source_binding(matrix: dict[str, Any], release: dict[str, Any], runtime_service_authority: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "adapter_matrix": _matrix_binding(matrix),
        "hook_release": _release_binding(release),
        "runtime_service_authority": _authority_dossier_binding(runtime_service_authority) if runtime_service_authority else None,
        "frameworks": sorted({str(entry.get("framework")) for entry in matrix.get("entries", []) if isinstance(entry, dict) and entry.get("framework")}),
        "runtime_versions": _runtime_versions(matrix),
    }


def _matrix_binding(matrix: dict[str, Any]) -> dict[str, Any]:
    return {
        "matrix_id": matrix.get("matrix_id"),
        "matrix_hash": content_hash(matrix),
        "schema": matrix.get("schema"),
        "matrix_ref": matrix.get("matrix_ref"),
        "issued_at": matrix.get("issued_at"),
        "adapter_package_version": matrix.get("adapter_package_version"),
        "summary": matrix.get("summary"),
    }


def _release_binding(release: dict[str, Any]) -> dict[str, Any]:
    return {
        "release_id": release.get("release_id"),
        "release_hash": content_hash(release),
        "schema": release.get("schema"),
        "release_ref": release.get("release_ref"),
        "released_at": release.get("released_at"),
        "adapter_matrix": release.get("adapter_matrix"),
        "summary": release.get("summary"),
        "status_counts": _status_counts(release.get("entries", [])),
    }


def _verify_runtime_service_authority_reference(dossier: dict[str, Any], errors: list[str], warnings: list[str], *, key: str | None) -> None:
    if not isinstance(dossier, dict):
        errors.append("framework adapter authority runtime service source must be an object")
        return
    if dossier.get("schema") != FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_SCHEMA:
        errors.append(f"framework adapter authority runtime service source schema is unsupported: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("framework adapter authority runtime service source dossier_id does not match body")
    signatures = dossier.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework adapter authority runtime service source must include a signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "framework_runtime_service_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework adapter authority runtime service source signature verification failed")
    if not isinstance(dossier.get("provider_receipt_binding"), dict):
        errors.append("framework adapter authority runtime service source provider_receipt_binding is required")
    if not isinstance(dossier.get("summary"), dict):
        errors.append("framework adapter authority runtime service source summary is required")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("framework adapter authority runtime service source controls are required")
    warnings.append("framework adapter authority runtime service source was verified as a signed dossier reference; provider receipt replay remains the runtime authority verifier's responsibility")


def _authority_dossier_binding(dossier: dict[str, Any]) -> dict[str, Any]:
    return {
        "dossier_id": dossier.get("dossier_id"),
        "dossier_hash": content_hash(dossier),
        "schema": dossier.get("schema"),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "summary": dossier.get("summary"),
        "authority_ref": dossier.get("authority_ref"),
    }


def _runtime_versions(matrix: dict[str, Any]) -> list[dict[str, str]]:
    versions: list[dict[str, str]] = []
    for entry in matrix.get("entries", []):
        if not isinstance(entry, dict):
            continue
        runtime = entry.get("runtime", {}) if isinstance(entry.get("runtime"), dict) else {}
        versions.append(
            {
                "framework": str(entry.get("framework") or ""),
                "package": str(runtime.get("package") or ""),
                "version": str(runtime.get("version") or ""),
                "status": str(entry.get("status") or ""),
            }
        )
    return sorted(versions, key=lambda item: (item["framework"], item["package"], item["version"]))


def _verify_source_binding(
    binding: Any,
    matrix: dict[str, Any] | None,
    release: dict[str, Any] | None,
    runtime_service_authority: dict[str, Any] | None,
    errors: list[str],
    warnings: list[str],
    *,
    root: str | Path,
    key: str | None,
) -> None:
    if not isinstance(binding, dict):
        errors.append("framework adapter authority source_binding is required")
        return
    _verify_binding_completeness(binding, errors)
    if matrix is None:
        warnings.append("framework adapter authority matrix source was not supplied; matrix binding hashes were not replayed")
        return
    matrix_result = verify_framework_adapter_matrix(matrix, root=root, key=key)
    errors.extend(f"framework adapter authority matrix source: {error}" for error in matrix_result.errors)
    warnings.extend(f"framework adapter authority matrix source: {warning}" for warning in matrix_result.warnings)
    if release is None:
        warnings.append("framework adapter authority hook release source was not supplied; release binding hashes were not replayed")
        return
    release_result = verify_framework_hook_release(release, matrix, root=root, key=key)
    errors.extend(f"framework adapter authority release source: {error}" for error in release_result.errors)
    warnings.extend(f"framework adapter authority release source: {warning}" for warning in release_result.warnings)
    if runtime_service_authority is not None:
        _verify_runtime_service_authority_reference(runtime_service_authority, errors, warnings, key=key)
    expected = _source_binding(matrix, release, runtime_service_authority)
    if binding != expected:
        errors.append("framework adapter authority source_binding does not match supplied source artifacts")


def _verify_binding_completeness(binding: dict[str, Any], errors: list[str]) -> None:
    matrix = _binding_section(binding, "adapter_matrix", errors)
    for field in ("matrix_id", "matrix_hash", "schema", "matrix_ref", "issued_at", "adapter_package_version"):
        _require_binding_field(matrix, f"source_binding.adapter_matrix.{field}", errors)
    _verify_summary_binding(matrix.get("summary"), "source_binding.adapter_matrix.summary", errors)

    release = _binding_section(binding, "hook_release", errors)
    for field in ("release_id", "release_hash", "schema", "release_ref", "released_at"):
        _require_binding_field(release, f"source_binding.hook_release.{field}", errors)
    _verify_summary_binding(release.get("summary"), "source_binding.hook_release.summary", errors)
    _require_binding_field(release, "source_binding.hook_release.status_counts", errors)
    release_matrix = release.get("adapter_matrix")
    if not isinstance(release_matrix, dict):
        errors.append("framework adapter authority source_binding.hook_release.adapter_matrix is required")
        release_matrix = {}
    for field in ("matrix_id", "matrix_hash", "matrix_ref", "issued_at"):
        _require_binding_field(release_matrix, f"source_binding.hook_release.adapter_matrix.{field}", errors)

    _require_binding_field(binding, "source_binding.frameworks", errors)
    runtime_versions = binding.get("runtime_versions")
    if not isinstance(runtime_versions, list) or not runtime_versions:
        errors.append("framework adapter authority source_binding.runtime_versions is required")
    else:
        for index, runtime in enumerate(runtime_versions):
            if not isinstance(runtime, dict):
                errors.append(f"framework adapter authority source_binding.runtime_versions[{index}] must be an object")
                continue
            for field in ("framework", "package", "version", "status"):
                _require_binding_field(runtime, f"source_binding.runtime_versions[{index}].{field}", errors)

    runtime_authority = binding.get("runtime_service_authority")
    if runtime_authority is not None:
        if not isinstance(runtime_authority, dict):
            errors.append("framework adapter authority source_binding.runtime_service_authority must be an object")
        else:
            for field in ("dossier_id", "dossier_hash", "schema", "mode", "environment", "generated_at", "summary", "authority_ref"):
                _require_binding_field(runtime_authority, f"source_binding.runtime_service_authority.{field}", errors)


def _binding_section(binding: dict[str, Any], section: str, errors: list[str]) -> dict[str, Any]:
    value = binding.get(section)
    if not isinstance(value, dict):
        errors.append(f"framework adapter authority source_binding.{section} is required")
        return {}
    return value


def _verify_summary_binding(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"framework adapter authority {path} is required")
        return
    for field in ("row_count", "framework_count", "frameworks", "by_status", "by_hook_mode"):
        _require_binding_field(value, f"{path}.{field}", errors)


def _require_binding_field(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if value is None or value == "" or value == [] or value == {}:
        errors.append(f"framework adapter authority {path} is required")


def _source_binding_complete(binding: dict[str, Any]) -> bool:
    errors: list[str] = []
    _verify_binding_completeness(binding, errors)
    return not errors and isinstance(binding.get("runtime_service_authority"), dict)


def _build_authority_evidence_item(item: dict[str, Any], source_context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported framework adapter authority requirement: {requirement_id}")
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in requirement["authority_kinds"]:
        raise ValueError(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    if not evidence_hash.startswith("sha256:"):
        raise ValueError("evidence_hash must start with sha256:")
    built = {"requirement_id": requirement_id, "authority_kind": authority_kind, "evidence_ref": evidence_ref, "evidence_hash": evidence_hash, "description": description}
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
        errors.append(f"invalid framework adapter authority evidence: {exc}")
        return "missing"
    requirement_id = item.get("requirement_id")
    if item != expected:
        errors.append(f"framework adapter authority evidence_id does not match evidence body: {requirement_id}")
    if not isinstance(item.get("source_context"), dict):
        errors.append(f"framework adapter authority source_context is required: {requirement_id}")
    elif item.get("source_context") != source_context:
        errors.append(f"framework adapter authority source_context does not match source binding: {requirement_id}")
    issued_at = item.get("issued_at")
    expires_at = item.get("expires_at")
    if not issued_at or not expires_at:
        if require_fresh:
            errors.append(f"framework adapter authority evidence {item.get('requirement_id')} freshness metadata missing")
        return "missing"
    issued = parse_rfc3339(str(issued_at))
    expires = parse_rfc3339(str(expires_at))
    if issued > expires:
        errors.append(f"framework adapter authority evidence {item.get('requirement_id')} issued_at is after expires_at")
        return "stale"
    if now < issued or now > expires:
        message = f"framework adapter authority evidence {item.get('requirement_id')} is outside its freshness window"
        if require_fresh:
            errors.append(message)
        else:
            warnings.append(message)
        return "stale"
    return "fresh"


def _authority_evidence_source_context(binding: dict[str, Any]) -> dict[str, Any]:
    matrix = binding.get("adapter_matrix") if isinstance(binding.get("adapter_matrix"), dict) else {}
    release = binding.get("hook_release") if isinstance(binding.get("hook_release"), dict) else {}
    release_matrix = release.get("adapter_matrix") if isinstance(release.get("adapter_matrix"), dict) else {}
    runtime_authority = binding.get("runtime_service_authority") if isinstance(binding.get("runtime_service_authority"), dict) else {}
    return {
        "source_binding_hash": content_hash(binding),
        "adapter_matrix_id": matrix.get("matrix_id"),
        "adapter_matrix_hash": matrix.get("matrix_hash"),
        "adapter_matrix_ref": matrix.get("matrix_ref"),
        "adapter_matrix_issued_at": matrix.get("issued_at"),
        "adapter_package_version": matrix.get("adapter_package_version"),
        "adapter_matrix_summary": matrix.get("summary"),
        "hook_release_id": release.get("release_id"),
        "hook_release_hash": release.get("release_hash"),
        "hook_release_ref": release.get("release_ref"),
        "hook_release_released_at": release.get("released_at"),
        "hook_release_status_counts": release.get("status_counts"),
        "hook_release_matrix_id": release_matrix.get("matrix_id"),
        "hook_release_matrix_hash": release_matrix.get("matrix_hash"),
        "frameworks": binding.get("frameworks"),
        "runtime_version_root": content_hash(binding.get("runtime_versions") or []),
        "runtime_service_authority_dossier_id": runtime_authority.get("dossier_id"),
        "runtime_service_authority_dossier_hash": runtime_authority.get("dossier_hash"),
        "runtime_service_authority_mode": runtime_authority.get("mode"),
        "runtime_service_authority_environment": runtime_authority.get("environment"),
        "runtime_service_authority_ref": runtime_authority.get("authority_ref"),
        "runtime_service_authority_summary": runtime_authority.get("summary"),
    }


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("framework adapter authority required_production_authority does not match the required checklist")


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
    matrix_bound = isinstance(binding.get("adapter_matrix"), dict) and bool(binding.get("adapter_matrix", {}).get("matrix_id"))
    release_bound = isinstance(binding.get("hook_release"), dict) and bool(binding.get("hook_release", {}).get("release_id"))
    runtime_bound = isinstance(binding.get("runtime_service_authority"), dict) and bool(binding.get("runtime_service_authority", {}).get("dossier_id"))
    matrix_rows = _summary_count(binding.get("adapter_matrix"), "row_count")
    release_rows = _summary_count(binding.get("hook_release"), "row_count")
    row_parity = matrix_rows is not None and release_rows is not None and matrix_rows == release_rows
    production_ready = mode == "production-dossier" and _source_binding_complete(binding) and not missing and freshness["missing"] == 0
    return [
        {"id": "adapter-matrix-bound", "status": "passed" if matrix_bound else "failed", "detail": "Dossier binds the signed framework adapter compatibility matrix, matrix hash, issued_at, and runtime version rows."},
        {"id": "hook-release-bound", "status": "passed" if release_bound else "failed", "detail": "Dossier binds the signed framework hook release receipt, source artifact hashes, fixture replay roots, and status counts."},
        {"id": "matrix-release-row-parity", "status": "passed" if row_parity else "deferred", "detail": f"matrix_rows={matrix_rows} release_rows={release_rows}"},
        {"id": "runtime-service-authority-bound", "status": "passed" if runtime_bound else "deferred", "detail": "Framework runtime service production authority is hash-bound when supplied."},
        {"id": "authority-evidence-checklist-covered", "status": "passed" if not missing else "deferred", "detail": f"{summary.get('covered_requirement_count', 0)}/{summary.get('required_requirement_count', 0)} framework adapter production authority categories are covered."},
        {"id": "freshness-windows-tracked", "status": "passed" if evidence_items and freshness["missing"] == 0 else "deferred", "detail": f"windowed={freshness['windowed']} missing_freshness={freshness['missing']}"},
        {"id": "production-mode-gated", "status": "passed" if production_ready else "deferred", "detail": "Production framework adapter authority is claimed only when matrix, hook release, runtime service authority, and every authority category are covered with timestamped evidence windows."},
        {"id": "raw-secret-exclusion", "status": "passed", "detail": "Dossier stores hashes and redacted references instead of raw framework-provider, repository, package, or service credentials."},
    ]


def _summary_count(binding: Any, key: str) -> int | None:
    if not isinstance(binding, dict):
        return None
    summary = binding.get("summary")
    if not isinstance(summary, dict):
        return None
    value = summary.get(key)
    return int(value) if isinstance(value, int) else None


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


def _status_counts(entries: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not isinstance(entries, list):
        return counts
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _status_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return summary


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
    return lowered.endswith(("_ref", "_hash", "_root", "_id"))


def _is_redacted_reference(value: str) -> bool:
    return value.startswith(("env:", "vault:", "kms:", "secret-ref:", "sha256:", "hash:"))


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework adapter authority {field} is required")
