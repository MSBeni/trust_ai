from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .adapters import (
    ADAPTER_SCHEMA_URL,
    SUPPORTED_FRAMEWORKS,
    load_framework_events,
    verify_framework_event_chains,
)
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

FRAMEWORK_ADAPTER_MATRIX_SCHEMA = "trustai.framework-adapter-matrix/0.1"
FRAMEWORK_ADAPTER_MATRIX_ENTRY_TYPE = "framework_adapter.matrix_attested"

ADAPTER_HOOK_MODES = {
    "json-export-reference",
    "native-hook",
    "otel-bridge",
    "mcp-observed",
}
ADAPTER_COMPATIBILITY_STATUSES = {
    "verified-reference",
    "native-hook-tested",
    "production-certified",
}


@dataclass
class FrameworkAdapterMatrixVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_adapter_matrix_source(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework adapter matrix source must contain an object")
    return value


def load_framework_adapter_matrix(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework adapter matrix must contain an object")
    return value


def write_framework_adapter_matrix(path: str | Path, matrix: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_adapter_matrix(
    source: dict[str, Any],
    *,
    root: str | Path = ".",
    issued_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if not isinstance(source, dict):
        raise ValueError("framework adapter matrix source must be an object")
    entries = source.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("framework adapter matrix source requires a non-empty entries list")

    root_path = Path(root)
    issued = issued_at or source.get("issued_at") or utc_now()
    parse_rfc3339(str(issued))
    spec_path = str(source.get("spec_path") or "docs/specs/framework-adapters-v0.1.md")
    built_entries = [_build_matrix_entry(row, root_path=root_path, issued_at=str(issued)) for row in entries]
    built_entries.sort(key=lambda item: (item["framework"], item["runtime"]["package"], item["runtime"]["version"]))
    summary = _summary(built_entries)
    body = {
        "schema": FRAMEWORK_ADAPTER_MATRIX_SCHEMA,
        "matrix_ref": str(source.get("matrix_ref") or "framework-adapter-matrix"),
        "issued_at": str(issued),
        "adapter_schema_url": ADAPTER_SCHEMA_URL,
        "adapter_package_version": str(source.get("adapter_package_version") or "0.1.0-local"),
        "source_spec": _file_ref(root_path, spec_path),
        "entries": built_entries,
        "summary": summary,
        "limitations": [
            "This matrix proves local adapter compatibility against checked-in fixtures and declared runtime versions.",
            "Rows marked verified-reference do not claim live native hooks in a production runtime.",
            "Production-certified rows require provider-owned runtime release, deployment, and audit-log evidence.",
        ],
    }
    matrix_id = content_hash(body)
    return {
        **body,
        "matrix_id": matrix_id,
        "signatures": [sign_value({"matrix_id": matrix_id, "framework_adapter_matrix": body}, key)],
    }


def verify_framework_adapter_matrix(
    matrix: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> FrameworkAdapterMatrixVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if matrix.get("schema") != FRAMEWORK_ADAPTER_MATRIX_SCHEMA:
        errors.append(f"unsupported framework adapter matrix schema: {matrix.get('schema')}")
    body = without_keys(matrix, "matrix_id", "signatures")
    expected_id = content_hash(body)
    if matrix.get("matrix_id") != expected_id:
        errors.append("matrix_id does not match canonical framework adapter matrix body")

    signatures = matrix.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework adapter matrix must include at least one signature")
    else:
        signed_value = {"matrix_id": matrix.get("matrix_id"), "framework_adapter_matrix": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework adapter matrix signature verification failed")

    try:
        parse_rfc3339(str(matrix.get("issued_at") or ""))
    except ValueError as exc:
        errors.append(f"framework adapter matrix issued_at invalid: {exc}")

    source_spec = matrix.get("source_spec", {})
    if isinstance(source_spec, dict):
        _verify_file_ref(root_path, source_spec, "source_spec", errors)
    else:
        errors.append("framework adapter matrix source_spec must be an object")

    entries = matrix.get("entries", [])
    if not isinstance(entries, list) or not entries:
        errors.append("framework adapter matrix requires entries")
        entries = []

    seen: set[tuple[str, str, str]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"framework adapter matrix entry {index + 1} must be an object")
            continue
        _verify_matrix_entry(root_path, entry, errors, warnings)
        key_tuple = (
            str(entry.get("framework") or ""),
            str(entry.get("runtime", {}).get("package") if isinstance(entry.get("runtime"), dict) else ""),
            str(entry.get("runtime", {}).get("version") if isinstance(entry.get("runtime"), dict) else ""),
        )
        if key_tuple in seen:
            errors.append(f"duplicate framework adapter matrix entry: {'/'.join(key_tuple)}")
        seen.add(key_tuple)

    expected_summary = _summary([entry for entry in entries if isinstance(entry, dict)])
    if matrix.get("summary") != expected_summary:
        errors.append("framework adapter matrix summary does not match entries")
    if not any(isinstance(entry, dict) and entry.get("status") == "production-certified" for entry in entries):
        warnings.append("framework adapter matrix has no production-certified rows")
    return FrameworkAdapterMatrixVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_adapter_matrix(
    chain: EvidenceChain,
    matrix: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_adapter_matrix(matrix, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid framework adapter matrix: " + "; ".join(result.errors))
    payload = {
        "matrix_id": matrix["matrix_id"],
        "matrix_hash": content_hash(matrix),
        "matrix_ref": matrix.get("matrix_ref"),
        "issued_at": matrix.get("issued_at"),
        "adapter_schema_url": matrix.get("adapter_schema_url"),
        "adapter_package_version": matrix.get("adapter_package_version"),
        "summary": matrix.get("summary"),
        "frameworks": [entry.get("framework") for entry in matrix.get("entries", []) if isinstance(entry, dict)],
        "compatibility_hashes": [entry.get("compatibility_hash") for entry in matrix.get("entries", []) if isinstance(entry, dict)],
    }
    return chain.append(FRAMEWORK_ADAPTER_MATRIX_ENTRY_TYPE, payload, key=key, timestamp=matrix.get("issued_at"))


def _build_matrix_entry(row: Any, *, root_path: Path, issued_at: str) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError("framework adapter matrix entries must be objects")
    framework = _normalize_framework(row.get("framework"))
    runtime_package = _require_text(row.get("runtime_package"), "runtime_package")
    runtime_version = _require_text(row.get("runtime_version"), "runtime_version")
    adapter_version = _require_text(row.get("adapter_version"), "adapter_version")
    hook_mode = str(row.get("hook_mode") or "json-export-reference")
    if hook_mode not in ADAPTER_HOOK_MODES:
        raise ValueError(f"unsupported framework adapter hook_mode: {hook_mode}")
    status = str(row.get("status") or "verified-reference")
    if status not in ADAPTER_COMPATIBILITY_STATUSES:
        raise ValueError(f"unsupported framework adapter status: {status}")
    tested_at = str(row.get("tested_at") or issued_at)
    parse_rfc3339(tested_at)

    trace_fixture_path = _require_text(row.get("trace_fixture"), "trace_fixture")
    trace_fixture = _file_ref(root_path, trace_fixture_path)
    if not trace_fixture["present"]:
        raise ValueError(f"framework adapter trace fixture missing: {trace_fixture_path}")
    matching_events = _events_for_framework(root_path / trace_fixture["path"], framework)
    required_event_names = _normalized_list(row.get("required_event_names") or row.get("expected_event_names"))
    event_names = sorted({event["event_name"] for event in matching_events})
    missing_events = sorted(set(required_event_names) - set(event_names))
    if missing_events:
        raise ValueError(f"framework adapter {framework} fixture missing required events: {', '.join(missing_events)}")

    entry_body = {
        "framework": framework,
        "aliases": _normalized_list(row.get("aliases")),
        "runtime": {
            "package": runtime_package,
            "version": runtime_version,
            "release_channel": row.get("release_channel") or "declared-compatible",
        },
        "adapter": {
            "version": adapter_version,
            "hook_mode": hook_mode,
            "schema_url": ADAPTER_SCHEMA_URL,
        },
        "status": status,
        "tested_at": tested_at,
        "trace_fixture": {
            **trace_fixture,
            "event_count": len(matching_events),
            "event_names": event_names,
            "normalized_event_root": content_hash(matching_events),
        },
        "required_event_names": required_event_names,
        "release_refs": _normalized_list(row.get("release_refs")),
        "evidence_refs": _normalized_list(row.get("evidence_refs")),
        "controls": _controls(status=status, hook_mode=hook_mode, release_refs=_normalized_list(row.get("release_refs"))),
    }
    return {**entry_body, "compatibility_hash": content_hash(entry_body)}


def _verify_matrix_entry(root_path: Path, entry: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    if entry.get("compatibility_hash") != content_hash(without_keys(entry, "compatibility_hash")):
        errors.append(f"framework adapter entry hash mismatch: {entry.get('framework')}")
    try:
        framework = _normalize_framework(entry.get("framework"))
    except ValueError as exc:
        errors.append(str(exc))
        framework = ""

    runtime = entry.get("runtime", {})
    if not isinstance(runtime, dict):
        errors.append(f"framework adapter {framework} runtime must be an object")
        runtime = {}
    for field in ("package", "version"):
        if not runtime.get(field):
            errors.append(f"framework adapter {framework} runtime.{field} is required")

    adapter = entry.get("adapter", {})
    if not isinstance(adapter, dict):
        errors.append(f"framework adapter {framework} adapter must be an object")
        adapter = {}
    hook_mode = adapter.get("hook_mode")
    if hook_mode not in ADAPTER_HOOK_MODES:
        errors.append(f"framework adapter {framework} hook_mode is unsupported")
    if adapter.get("schema_url") != ADAPTER_SCHEMA_URL:
        errors.append(f"framework adapter {framework} schema_url mismatch")

    status = entry.get("status")
    if status not in ADAPTER_COMPATIBILITY_STATUSES:
        errors.append(f"framework adapter {framework} status is unsupported")
    elif status == "verified-reference":
        warnings.append(f"framework adapter {framework} is verified only against local fixtures")
    try:
        parse_rfc3339(str(entry.get("tested_at") or ""))
    except ValueError as exc:
        errors.append(f"framework adapter {framework} tested_at invalid: {exc}")

    trace_fixture = entry.get("trace_fixture", {})
    if not isinstance(trace_fixture, dict):
        errors.append(f"framework adapter {framework} trace_fixture must be an object")
        return
    _verify_file_ref(root_path, trace_fixture, f"framework adapter {framework} trace_fixture", errors)
    if trace_fixture.get("present"):
        try:
            matching_events = _events_for_framework(root_path / trace_fixture["path"], framework)
            event_names = sorted({event["event_name"] for event in matching_events})
            chain_errors = verify_framework_event_chains(matching_events)
            errors.extend(f"framework adapter {framework} event chain: {error}" for error in chain_errors)
            if trace_fixture.get("event_count") != len(matching_events):
                errors.append(f"framework adapter {framework} event_count mismatch")
            if trace_fixture.get("event_names") != event_names:
                errors.append(f"framework adapter {framework} event_names mismatch")
            if trace_fixture.get("normalized_event_root") != content_hash(matching_events):
                errors.append(f"framework adapter {framework} normalized_event_root mismatch")
            required = entry.get("required_event_names", [])
            if not _is_string_list(required):
                errors.append(f"framework adapter {framework} required_event_names must be a string array")
            else:
                missing = sorted(set(required) - set(event_names))
                if missing:
                    errors.append(f"framework adapter {framework} missing required event names: {', '.join(missing)}")
        except (OSError, ValueError) as exc:
            errors.append(f"framework adapter {framework} fixture replay failed: {exc}")


def _events_for_framework(path: Path, framework: str) -> list[dict[str, Any]]:
    events = load_framework_events(path)
    matching = [
        event
        for event in events
        if event.get("attributes", {}).get("trustai.adapter.framework") == framework
    ]
    if not matching:
        raise ValueError(f"trace fixture produced no events for framework: {framework}")
    return matching


def _summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = {status: 0 for status in sorted(ADAPTER_COMPATIBILITY_STATUSES)}
    by_hook_mode = {mode: 0 for mode in sorted(ADAPTER_HOOK_MODES)}
    frameworks: list[str] = []
    total_events = 0
    for entry in entries:
        framework = str(entry.get("framework") or "")
        if framework:
            frameworks.append(framework)
        status = entry.get("status")
        if status in by_status:
            by_status[status] += 1
        adapter = entry.get("adapter", {}) if isinstance(entry.get("adapter"), dict) else {}
        hook_mode = adapter.get("hook_mode")
        if hook_mode in by_hook_mode:
            by_hook_mode[hook_mode] += 1
        fixture = entry.get("trace_fixture", {}) if isinstance(entry.get("trace_fixture"), dict) else {}
        if isinstance(fixture.get("event_count"), int):
            total_events += fixture["event_count"]
    return {
        "row_count": len(entries),
        "framework_count": len(set(frameworks)),
        "frameworks": sorted(set(frameworks)),
        "total_fixture_events": total_events,
        "by_status": by_status,
        "by_hook_mode": by_hook_mode,
    }


def _file_ref(root: Path, path: str | Path) -> dict[str, Any]:
    relative = Path(path).as_posix()
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError(f"framework adapter matrix path must be repository-relative: {relative}")
    target = root / relative
    if target.exists() and target.is_file():
        return {"path": relative, "present": True, "sha256": "sha256:" + sha256(target.read_bytes()).hexdigest()}
    return {"path": relative, "present": False, "sha256": None}


def _verify_file_ref(root: Path, value: dict[str, Any], label: str, errors: list[str]) -> None:
    path_value = value.get("path")
    if not isinstance(path_value, str) or not path_value:
        errors.append(f"{label} missing path")
        return
    if Path(path_value).is_absolute() or ".." in Path(path_value).parts:
        errors.append(f"{label} path must be repository-relative: {path_value}")
        return
    target = root / path_value
    if value.get("present"):
        if not target.exists() or not target.is_file():
            errors.append(f"{label} path missing: {path_value}")
            return
        actual = "sha256:" + sha256(target.read_bytes()).hexdigest()
        if value.get("sha256") != actual:
            errors.append(f"{label} sha256 mismatch: {path_value}")
    elif value.get("sha256") is not None:
        errors.append(f"{label} missing file must not include sha256")


def _normalize_framework(value: Any) -> str:
    framework = str(value or "").strip().lower().replace("-", "_")
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"unsupported framework adapter framework: {value}")
    return framework


def _require_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"framework adapter matrix {field} is required")
    return text


def _normalized_list(values: Any) -> list[str]:
    if not values:
        return []
    if not isinstance(values, list):
        raise ValueError("framework adapter matrix list fields must be arrays")
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _controls(*, status: str, hook_mode: str, release_refs: list[str]) -> list[dict[str, str]]:
    return [
        {
            "id": "runtime-version-declared",
            "status": "implemented",
            "description": "Runtime package and version range are explicitly bound into the compatibility row.",
        },
        {
            "id": "fixture-replay-verified",
            "status": "implemented",
            "description": "The checked-in trace fixture is replayed through the adapter and bound by event root hash.",
        },
        {
            "id": "native-hook-release-matrix",
            "status": "implemented" if hook_mode != "json-export-reference" and release_refs else "planned-production",
            "description": "Native runtime hook release evidence is attached for production adapter packages.",
        },
        {
            "id": "compatibility-status-signed",
            "status": "implemented" if status in ADAPTER_COMPATIBILITY_STATUSES else "missing",
            "description": "Compatibility status is included in the signed matrix row.",
        },
    ]
