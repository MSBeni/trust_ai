from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .adapters import SUPPORTED_FRAMEWORKS, load_framework_events, verify_framework_event_chains
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_adapter_matrix import verify_framework_adapter_matrix

FRAMEWORK_HOOK_RELEASE_SCHEMA = "trustai.framework-hook-release/0.1"
FRAMEWORK_HOOK_RELEASE_ENTRY_TYPE = "framework_hook.release_attested"
HOOK_RELEASE_MODES = {"native-hook", "otel-bridge", "mcp-observed", "managed-runtime-bridge"}
HOOK_RELEASE_STATUSES = {"reference-release", "native-hook-tested", "production-certified"}


@dataclass
class FrameworkHookReleaseVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_hook_release_source(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework hook release source must contain an object")
    return value


def load_framework_hook_release(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework hook release must contain an object")
    return value


def write_framework_hook_release(path: str | Path, release: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(release, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_hook_release(
    source: dict[str, Any],
    matrix: dict[str, Any],
    *,
    root: str | Path = ".",
    released_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if not isinstance(source, dict):
        raise ValueError("framework hook release source must be an object")
    entries = source.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("framework hook release source requires a non-empty entries list")

    root_path = Path(root)
    matrix_result = verify_framework_adapter_matrix(matrix, root=root_path, key=key)
    if not matrix_result.ok:
        raise ValueError("invalid framework adapter matrix: " + "; ".join(matrix_result.errors))

    released = released_at or source.get("released_at") or utc_now()
    parse_rfc3339(str(released))
    spec_path = str(source.get("spec_path") or "docs/specs/framework-hook-release-v0.1.md")
    built_entries = [_build_release_entry(row, matrix, root_path=root_path, released_at=str(released)) for row in entries]
    built_entries.sort(key=lambda item: (item["framework"], item["runtime"]["package"], item["runtime"]["version"]))
    body = {
        "schema": FRAMEWORK_HOOK_RELEASE_SCHEMA,
        "release_ref": str(source.get("release_ref") or "framework-hook-release"),
        "released_at": str(released),
        "source_spec": _file_ref(root_path, spec_path),
        "adapter_matrix": {
            "matrix_id": matrix.get("matrix_id"),
            "matrix_hash": content_hash(matrix),
            "matrix_ref": matrix.get("matrix_ref"),
            "issued_at": matrix.get("issued_at"),
        },
        "entries": built_entries,
        "summary": _summary(built_entries),
        "limitations": [
            "This receipt binds framework hook release metadata to replayed adapter fixtures and source artifacts.",
            "Reference-release rows prove packaged hook metadata and fixture compatibility; they do not claim live production interception.",
            "Production-certified rows require provider/runtime deployment evidence, immutable audit logs, and collector service receipts.",
        ],
    }
    release_id = content_hash(body)
    return {
        **body,
        "release_id": release_id,
        "signatures": [sign_value({"release_id": release_id, "framework_hook_release": body}, key)],
    }


def verify_framework_hook_release(
    release: dict[str, Any],
    matrix: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> FrameworkHookReleaseVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if release.get("schema") != FRAMEWORK_HOOK_RELEASE_SCHEMA:
        errors.append(f"unsupported framework hook release schema: {release.get('schema')}")
    body = without_keys(release, "release_id", "signatures")
    expected_id = content_hash(body)
    if release.get("release_id") != expected_id:
        errors.append("release_id does not match canonical framework hook release body")

    signatures = release.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework hook release must include at least one signature")
    else:
        signed_value = {"release_id": release.get("release_id"), "framework_hook_release": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework hook release signature verification failed")

    try:
        parse_rfc3339(str(release.get("released_at") or ""))
    except ValueError as exc:
        errors.append(f"framework hook release released_at invalid: {exc}")

    source_spec = release.get("source_spec", {})
    if isinstance(source_spec, dict):
        _verify_file_ref(root_path, source_spec, "source_spec", errors)
    else:
        errors.append("framework hook release source_spec must be an object")

    if matrix is not None:
        matrix_result = verify_framework_adapter_matrix(matrix, root=root_path, key=key)
        if not matrix_result.ok:
            errors.extend(f"adapter matrix: {error}" for error in matrix_result.errors)
        matrix_record = release.get("adapter_matrix", {}) if isinstance(release.get("adapter_matrix"), dict) else {}
        if matrix_record.get("matrix_id") != matrix.get("matrix_id"):
            errors.append("framework hook release adapter matrix_id mismatch")
        if matrix_record.get("matrix_hash") != content_hash(matrix):
            errors.append("framework hook release adapter matrix_hash mismatch")
    else:
        warnings.append("framework hook release adapter matrix replay was not supplied")

    entries = release.get("entries", [])
    if not isinstance(entries, list) or not entries:
        errors.append("framework hook release requires entries")
        entries = []

    seen: set[tuple[str, str, str, str]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"framework hook release entry {index + 1} must be an object")
            continue
        _verify_release_entry(root_path, entry, matrix, errors, warnings)
        runtime = entry.get("runtime", {}) if isinstance(entry.get("runtime"), dict) else {}
        hook = entry.get("hook", {}) if isinstance(entry.get("hook"), dict) else {}
        key_tuple = (
            str(entry.get("framework") or ""),
            str(runtime.get("package") or ""),
            str(runtime.get("version") or ""),
            str(hook.get("package") or ""),
        )
        if key_tuple in seen:
            errors.append(f"duplicate framework hook release entry: {'/'.join(key_tuple)}")
        seen.add(key_tuple)

    expected_summary = _summary([entry for entry in entries if isinstance(entry, dict)])
    if release.get("summary") != expected_summary:
        errors.append("framework hook release summary does not match entries")
    if not any(isinstance(entry, dict) and entry.get("status") == "production-certified" for entry in entries):
        warnings.append("framework hook release has no production-certified rows")
    return FrameworkHookReleaseVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_hook_release(
    chain: EvidenceChain,
    release: dict[str, Any],
    matrix: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    if matrix is None:
        raise ValueError("framework hook release append requires adapter matrix replay")
    result = verify_framework_hook_release(release, matrix, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid framework hook release: " + "; ".join(result.errors))
    payload = {
        "release_id": release["release_id"],
        "release_hash": content_hash(release),
        "release_ref": release.get("release_ref"),
        "released_at": release.get("released_at"),
        "adapter_matrix": release.get("adapter_matrix"),
        "frameworks": [entry.get("framework") for entry in release.get("entries", []) if isinstance(entry, dict)],
        "hook_release_hashes": [entry.get("hook_release_hash") for entry in release.get("entries", []) if isinstance(entry, dict)],
        "control_summary": _control_summary(release.get("entries", [])),
    }
    return chain.append(FRAMEWORK_HOOK_RELEASE_ENTRY_TYPE, payload, key=key, timestamp=release.get("released_at"))


def _build_release_entry(row: Any, matrix: dict[str, Any], *, root_path: Path, released_at: str) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError("framework hook release entries must be objects")
    framework = _normalize_framework(row.get("framework"))
    runtime_package = _require_text(row.get("runtime_package"), "runtime_package")
    runtime_version = _require_text(row.get("runtime_version"), "runtime_version")
    matrix_entry = _matrix_entry(matrix, framework, runtime_package, runtime_version)
    if matrix_entry is None:
        raise ValueError(f"framework hook release {framework} has no matching adapter matrix row")

    hook_mode = str(row.get("hook_mode") or "native-hook")
    if hook_mode not in HOOK_RELEASE_MODES:
        raise ValueError(f"unsupported framework hook release hook_mode: {hook_mode}")
    status = str(row.get("status") or "reference-release")
    if status not in HOOK_RELEASE_STATUSES:
        raise ValueError(f"unsupported framework hook release status: {status}")
    row_released_at = str(row.get("released_at") or released_at)
    parse_rfc3339(row_released_at)

    hook_package = _require_text(row.get("hook_package"), "hook_package")
    hook_version = _require_text(row.get("hook_version"), "hook_version")
    module_ref = _require_text(row.get("module_ref"), "module_ref")
    entrypoint_ref = _require_text(row.get("entrypoint_ref"), "entrypoint_ref")
    collector_hook_ref = _require_text(row.get("collector_hook_ref"), "collector_hook_ref")
    source_artifacts = [_file_ref(root_path, path) for path in _normalized_list(row.get("source_artifacts"))]
    if not source_artifacts:
        raise ValueError(f"framework hook release {framework} requires at least one source artifact")
    missing_artifacts = [artifact["path"] for artifact in source_artifacts if not artifact.get("present")]
    if missing_artifacts:
        raise ValueError(f"framework hook release {framework} source artifacts missing: {', '.join(missing_artifacts)}")

    trace_fixture = matrix_entry.get("trace_fixture", {}) if isinstance(matrix_entry.get("trace_fixture"), dict) else {}
    matching_events = _events_for_framework(root_path / str(trace_fixture.get("path") or ""), framework)
    chain_errors = verify_framework_event_chains(matching_events)
    if chain_errors:
        raise ValueError(f"framework hook release {framework} fixture event chain failed: {'; '.join(chain_errors)}")
    event_names = sorted({event["event_name"] for event in matching_events})
    trace_roots = sorted(
        {
            str(event.get("attributes", {}).get("trustai.adapter.trace_root"))
            for event in matching_events
            if isinstance(event.get("attributes"), dict) and event.get("attributes", {}).get("trustai.adapter.trace_root")
        }
    )

    entry_body = {
        "framework": framework,
        "aliases": _normalized_list(row.get("aliases")),
        "runtime": {
            "package": runtime_package,
            "version": runtime_version,
            "release_channel": row.get("release_channel") or matrix_entry.get("runtime", {}).get("release_channel"),
        },
        "hook": {
            "package": hook_package,
            "version": hook_version,
            "mode": hook_mode,
            "module_ref": module_ref,
            "entrypoint_ref": entrypoint_ref,
            "collector_hook_ref": collector_hook_ref,
        },
        "status": status,
        "released_at": row_released_at,
        "adapter_matrix_binding": {
            "matrix_id": matrix.get("matrix_id"),
            "compatibility_hash": matrix_entry.get("compatibility_hash"),
            "matrix_status": matrix_entry.get("status"),
            "matrix_hook_mode": matrix_entry.get("adapter", {}).get("hook_mode") if isinstance(matrix_entry.get("adapter"), dict) else None,
            "normalized_event_root": trace_fixture.get("normalized_event_root"),
        },
        "trace_fixture": {
            "path": trace_fixture.get("path"),
            "event_count": len(matching_events),
            "event_names": event_names,
            "trace_roots": trace_roots,
            "event_chain_verified": True,
        },
        "source_artifacts": source_artifacts,
        "source_artifact_root": content_hash(source_artifacts),
        "release_refs": _normalized_list(row.get("release_refs")),
        "evidence_refs": _normalized_list(row.get("evidence_refs")),
        "audit_log": {
            "ref": row.get("audit_log_ref"),
            "root": row.get("audit_log_root"),
        },
        "controls": _controls(status=status, hook_mode=hook_mode, release_refs=_normalized_list(row.get("release_refs")), evidence_refs=_normalized_list(row.get("evidence_refs")), audit_log_ref=row.get("audit_log_ref")),
    }
    return {**entry_body, "hook_release_hash": content_hash(entry_body)}


def _verify_release_entry(root_path: Path, entry: dict[str, Any], matrix: dict[str, Any] | None, errors: list[str], warnings: list[str]) -> None:
    if entry.get("hook_release_hash") != content_hash(without_keys(entry, "hook_release_hash")):
        errors.append(f"framework hook release entry hash mismatch: {entry.get('framework')}")
    try:
        framework = _normalize_framework(entry.get("framework"))
    except ValueError as exc:
        errors.append(str(exc))
        framework = ""

    runtime = entry.get("runtime", {})
    if not isinstance(runtime, dict):
        errors.append(f"framework hook release {framework} runtime must be an object")
        runtime = {}
    for field in ("package", "version"):
        if not runtime.get(field):
            errors.append(f"framework hook release {framework} runtime.{field} is required")

    hook = entry.get("hook", {})
    if not isinstance(hook, dict):
        errors.append(f"framework hook release {framework} hook must be an object")
        hook = {}
    for field in ("package", "version", "mode", "module_ref", "entrypoint_ref", "collector_hook_ref"):
        if not hook.get(field):
            errors.append(f"framework hook release {framework} hook.{field} is required")
    if hook.get("mode") not in HOOK_RELEASE_MODES:
        errors.append(f"framework hook release {framework} hook.mode is unsupported")

    status = entry.get("status")
    if status not in HOOK_RELEASE_STATUSES:
        errors.append(f"framework hook release {framework} status is unsupported")
    elif status == "reference-release":
        warnings.append(f"framework hook release {framework} is a reference release, not a live runtime hook")
    try:
        parse_rfc3339(str(entry.get("released_at") or ""))
    except ValueError as exc:
        errors.append(f"framework hook release {framework} released_at invalid: {exc}")

    artifacts = entry.get("source_artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(f"framework hook release {framework} source_artifacts are required")
        artifacts = []
    for artifact in artifacts:
        if isinstance(artifact, dict):
            _verify_file_ref(root_path, artifact, f"framework hook release {framework} source_artifact", errors)
        else:
            errors.append(f"framework hook release {framework} source_artifact must be an object")
    if entry.get("source_artifact_root") != content_hash(artifacts):
        errors.append(f"framework hook release {framework} source_artifact_root mismatch")

    if matrix is not None and framework:
        matrix_entry = _matrix_entry(matrix, framework, str(runtime.get("package") or ""), str(runtime.get("version") or ""))
        if matrix_entry is None:
            errors.append(f"framework hook release {framework} has no matching adapter matrix row")
        else:
            _verify_matrix_binding(root_path, entry, matrix, matrix_entry, errors, warnings)

    controls = entry.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append(f"framework hook release {framework} controls are required")


def _verify_matrix_binding(root_path: Path, entry: dict[str, Any], matrix: dict[str, Any], matrix_entry: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    framework = str(entry.get("framework") or "")
    binding = entry.get("adapter_matrix_binding", {})
    if not isinstance(binding, dict):
        errors.append(f"framework hook release {framework} adapter_matrix_binding must be an object")
        return
    if binding.get("matrix_id") != matrix.get("matrix_id"):
        errors.append(f"framework hook release {framework} matrix_id binding mismatch")
    if binding.get("compatibility_hash") != matrix_entry.get("compatibility_hash"):
        errors.append(f"framework hook release {framework} compatibility_hash binding mismatch")
    trace_fixture = matrix_entry.get("trace_fixture", {}) if isinstance(matrix_entry.get("trace_fixture"), dict) else {}
    if binding.get("normalized_event_root") != trace_fixture.get("normalized_event_root"):
        errors.append(f"framework hook release {framework} normalized_event_root binding mismatch")

    try:
        matching_events = _events_for_framework(root_path / str(trace_fixture.get("path") or ""), framework)
        chain_errors = verify_framework_event_chains(matching_events)
        errors.extend(f"framework hook release {framework} event chain: {error}" for error in chain_errors)
        fixture = entry.get("trace_fixture", {}) if isinstance(entry.get("trace_fixture"), dict) else {}
        event_names = sorted({event["event_name"] for event in matching_events})
        trace_roots = sorted(
            {
                str(event.get("attributes", {}).get("trustai.adapter.trace_root"))
                for event in matching_events
                if isinstance(event.get("attributes"), dict) and event.get("attributes", {}).get("trustai.adapter.trace_root")
            }
        )
        if fixture.get("event_count") != len(matching_events):
            errors.append(f"framework hook release {framework} event_count mismatch")
        if fixture.get("event_names") != event_names:
            errors.append(f"framework hook release {framework} event_names mismatch")
        if fixture.get("trace_roots") != trace_roots:
            errors.append(f"framework hook release {framework} trace_roots mismatch")
        if fixture.get("event_chain_verified") is not True:
            errors.append(f"framework hook release {framework} event_chain_verified must be true")
    except (OSError, ValueError) as exc:
        errors.append(f"framework hook release {framework} fixture replay failed: {exc}")

    if matrix_entry.get("status") != "production-certified":
        warnings.append(f"framework hook release {framework} is bound to matrix row status {matrix_entry.get('status')}")


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


def _matrix_entry(matrix: dict[str, Any], framework: str, runtime_package: str, runtime_version: str) -> dict[str, Any] | None:
    for entry in matrix.get("entries", []):
        if not isinstance(entry, dict):
            continue
        runtime = entry.get("runtime", {}) if isinstance(entry.get("runtime"), dict) else {}
        if (
            entry.get("framework") == framework
            and runtime.get("package") == runtime_package
            and runtime.get("version") == runtime_version
        ):
            return entry
    return None


def _summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = {status: 0 for status in sorted(HOOK_RELEASE_STATUSES)}
    by_mode = {mode: 0 for mode in sorted(HOOK_RELEASE_MODES)}
    frameworks: list[str] = []
    for entry in entries:
        framework = str(entry.get("framework") or "")
        if framework:
            frameworks.append(framework)
        status = entry.get("status")
        if status in by_status:
            by_status[status] += 1
        hook = entry.get("hook", {}) if isinstance(entry.get("hook"), dict) else {}
        mode = hook.get("mode")
        if mode in by_mode:
            by_mode[mode] += 1
    return {
        "row_count": len(entries),
        "framework_count": len(set(frameworks)),
        "frameworks": sorted(set(frameworks)),
        "by_status": by_status,
        "by_hook_mode": by_mode,
    }


def _controls(*, status: str, hook_mode: str, release_refs: list[str], evidence_refs: list[str], audit_log_ref: Any) -> list[dict[str, Any]]:
    production_evidence = status == "production-certified" and bool(release_refs) and bool(evidence_refs) and bool(audit_log_ref)
    return [
        {"control": "adapter-matrix-bound", "status": "passed"},
        {"control": "source-artifacts-present", "status": "passed"},
        {"control": "fixture-event-chain-replayed", "status": "passed"},
        {"control": "collector-hook-ref-present", "status": "passed"},
        {
            "control": "production-runtime-evidence",
            "status": "passed" if production_evidence else "deferred",
            "mode": hook_mode,
        },
    ]


def _control_summary(entries: list[Any]) -> dict[str, int]:
    summary = {"passed": 0, "warning": 0, "deferred": 0, "failed": 0}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for control in entry.get("controls", []):
            if not isinstance(control, dict):
                continue
            status = str(control.get("status") or "")
            if status in summary:
                summary[status] += 1
    return summary


def _file_ref(root: Path, path: str | Path) -> dict[str, Any]:
    relative = Path(path).as_posix()
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError(f"framework hook release path must be repository-relative: {relative}")
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
        raise ValueError(f"unsupported framework hook release framework: {value}")
    return framework


def _require_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"framework hook release {field} is required")
    return text


def _normalized_list(values: Any) -> list[str]:
    if not values:
        return []
    if not isinstance(values, list):
        raise ValueError("framework hook release list fields must be arrays")
    return sorted({str(value).strip() for value in values if str(value).strip()})