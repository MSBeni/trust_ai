from __future__ import annotations

import json
from hashlib import sha256
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters import SUPPORTED_FRAMEWORKS, framework_trace_to_events, verify_framework_event_chains
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .framework_hook_release import verify_framework_hook_release

FRAMEWORK_HOOK_OPERATION_SCHEMA = "trustai.framework-hook-operation/0.1"
FRAMEWORK_HOOK_OPERATION_ENTRY_TYPE = "framework_hook.operation_recorded"
HOOK_OPERATION_MODES = {"local-reference", "native-runtime", "collector-observed", "production-capture"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class FrameworkHookOperationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_framework_hook_operation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework hook operation receipt must contain an object")
    return value


def load_framework_trace_payload(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("framework trace payload must contain an object")
    return value


def write_framework_hook_operation(path: str | Path, operation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(operation, indent=2, sort_keys=True), encoding="utf-8")


def build_framework_hook_operation(
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    *,
    framework: str,
    trace_id: str | None = None,
    root: str | Path = ".",
    mode: str = "native-runtime",
    environment: str = "local",
    operation_ref: str,
    runtime_instance_ref: str,
    runtime_process_ref: str | None = None,
    collector_service_ref: str | None = None,
    collector_worker_ref: str | None = None,
    stream_message_ref: str | None = None,
    audit_log_ref: str,
    audit_log_root: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    captured_at: str | None = None,
    trace_source_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    framework_name = _normalize_framework(framework)
    if mode not in HOOK_OPERATION_MODES:
        raise ValueError(f"mode must be one of {sorted(HOOK_OPERATION_MODES)}")
    for value, field in (
        (environment, "environment"),
        (operation_ref, "operation_ref"),
        (runtime_instance_ref, "runtime_instance_ref"),
        (audit_log_ref, "audit_log_ref"),
        (audit_log_root, "audit_log_root"),
        (actor_ref, "actor_ref"),
        (credential_ref, "credential_ref"),
    ):
        _require_text(value, field)

    release_result = verify_framework_hook_release(release, matrix, root=root, key=key)
    if not release_result.ok:
        raise ValueError("invalid framework hook release: " + "; ".join(release_result.errors))
    selected_trace = _select_trace(trace_payload, framework_name, trace_id)
    events = framework_trace_to_events(selected_trace)
    chain_errors = verify_framework_event_chains(events)
    if chain_errors:
        raise ValueError("framework hook operation event chain failed: " + "; ".join(chain_errors))

    emitted_trace_id = str(events[0].get("trace_id") or "")
    emitted_attrs = events[0].get("attributes", {}) if isinstance(events[0].get("attributes"), dict) else {}
    source_trace_id = str(emitted_attrs.get("trustai.adapter.source_trace_id") or trace_id or emitted_trace_id)
    release_entry = _release_entry(release, framework_name)
    if release_entry is None:
        raise ValueError(f"framework hook operation has no release row for framework: {framework_name}")
    matrix_record = release.get("adapter_matrix", {}) if isinstance(release.get("adapter_matrix"), dict) else {}
    timestamp = captured_at or utc_now()
    parse_rfc3339(timestamp)
    event_names = sorted({str(event.get("event_name")) for event in events})
    trace_roots = _trace_roots(events)
    contract_hashes = sorted({str(event.get("contract_hash")) for event in events if event.get("contract_hash")})
    agents = [event.get("agent") for event in events if isinstance(event.get("agent"), dict)]
    agent = agents[0] if agents else None

    trace_record: dict[str, Any] = {
        "trace_id": emitted_trace_id,
        "source_trace_id": source_trace_id,
        "source_trace_hash": content_hash(selected_trace),
        "event_count": len(events),
        "event_names": event_names,
        "event_root": content_hash(events),
        "trace_roots": trace_roots,
        "event_chain_verified": True,
        "contract_hashes": contract_hashes,
        "agent": agent,
    }
    if trace_source_path is not None:
        trace_record["source_artifact"] = _trace_source_artifact(
            trace_source_path,
            trace_payload=trace_payload,
            selected_trace=selected_trace,
            events=events,
            root=Path(root),
            framework=framework_name,
        )

    body: dict[str, Any] = {
        "schema": FRAMEWORK_HOOK_OPERATION_SCHEMA,
        "mode": mode,
        "environment": environment,
        "captured_at": timestamp,
        "operation": {
            "operation_ref": operation_ref,
            "actor_ref": actor_ref,
            "credential": _redacted_ref(credential_ref),
            "evidence_refs": _normalized_list(evidence_refs),
        },
        "runtime": {
            "framework": framework_name,
            "package": release_entry.get("runtime", {}).get("package") if isinstance(release_entry.get("runtime"), dict) else None,
            "version": release_entry.get("runtime", {}).get("version") if isinstance(release_entry.get("runtime"), dict) else None,
            "instance_ref": runtime_instance_ref,
            "process_ref": runtime_process_ref,
        },
        "hook": {
            **(release_entry.get("hook", {}) if isinstance(release_entry.get("hook"), dict) else {}),
            "hook_release_hash": release_entry.get("hook_release_hash"),
        },
        "release_binding": {
            "release_id": release.get("release_id"),
            "release_hash": content_hash(release),
            "release_ref": release.get("release_ref"),
            "matrix_id": matrix_record.get("matrix_id"),
            "matrix_hash": matrix_record.get("matrix_hash"),
        },
        "trace": trace_record,
        "collector": {
            "collector_service_ref": collector_service_ref,
            "collector_worker_ref": collector_worker_ref,
            "stream_message_ref": stream_message_ref,
        },
        "audit_log": {
            "ref": audit_log_ref,
            "root": audit_log_root,
        },
        "controls": _controls(
            mode=mode,
            collector_worker_ref=collector_worker_ref,
            audit_log_ref=audit_log_ref,
            source_artifact_bound=trace_source_path is not None,
        ),
        "limitations": [
            "This receipt proves a hook entrypoint normalized one framework runtime trace into hash-chained TrustAI adapter events.",
            "Local-reference and native-runtime receipts bind supplied runtime metadata; production-capture requires provider/runtime audit evidence and collector delivery evidence.",
            "Raw framework payloads are not embedded in chain append entries; they are replayed by offline verification when supplied.",
        ],
    }
    operation_id = content_hash(body)
    return {
        **body,
        "operation_id": operation_id,
        "signatures": [sign_value({"operation_id": operation_id, "framework_hook_operation": body}, key)],
    }


def verify_framework_hook_operation(
    operation: dict[str, Any],
    trace_payload: dict[str, Any] | None = None,
    release: dict[str, Any] | None = None,
    matrix: dict[str, Any] | None = None,
    *,
    root: str | Path = ".",
    trace_source_path: str | Path | None = None,
    key: str | None = None,
) -> FrameworkHookOperationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if operation.get("schema") != FRAMEWORK_HOOK_OPERATION_SCHEMA:
        errors.append(f"unsupported framework hook operation schema: {operation.get('schema')}")
    body = without_keys(operation, "operation_id", "signatures")
    expected_id = content_hash(body)
    if operation.get("operation_id") != expected_id:
        errors.append("operation_id does not match canonical framework hook operation body")

    signatures = operation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("framework hook operation must include at least one signature")
    else:
        signed_value = {"operation_id": operation.get("operation_id"), "framework_hook_operation": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("framework hook operation signature verification failed")

    mode = operation.get("mode")
    if mode not in HOOK_OPERATION_MODES:
        errors.append("framework hook operation mode is unsupported")
    elif mode != "production-capture":
        warnings.append(f"framework hook operation is {mode}; production capture is not claimed")
    try:
        parse_rfc3339(str(operation.get("captured_at") or ""))
    except ValueError as exc:
        errors.append(f"framework hook operation captured_at invalid: {exc}")

    runtime = operation.get("runtime", {})
    if not isinstance(runtime, dict):
        errors.append("framework hook operation runtime must be an object")
        runtime = {}
    try:
        framework = _normalize_framework(runtime.get("framework"))
    except ValueError as exc:
        errors.append(str(exc))
        framework = ""
    for field in ("package", "version", "instance_ref"):
        if not runtime.get(field):
            errors.append(f"framework hook operation runtime.{field} is required")

    op = operation.get("operation", {})
    if not isinstance(op, dict):
        errors.append("framework hook operation operation must be an object")
        op = {}
    for field in ("operation_ref", "actor_ref"):
        if not op.get(field):
            errors.append(f"framework hook operation operation.{field} is required")
    _verify_redacted_ref(op.get("credential"), "framework hook operation credential", errors)

    hook = operation.get("hook", {})
    if not isinstance(hook, dict):
        errors.append("framework hook operation hook must be an object")
        hook = {}
    for field in ("package", "version", "mode", "module_ref", "entrypoint_ref", "collector_hook_ref", "hook_release_hash"):
        if not hook.get(field):
            errors.append(f"framework hook operation hook.{field} is required")

    binding = operation.get("release_binding", {})
    if not isinstance(binding, dict):
        errors.append("framework hook operation release_binding must be an object")
        binding = {}
    if release is not None and matrix is not None:
        release_result = verify_framework_hook_release(release, matrix, root=root, key=key)
        if not release_result.ok:
            errors.extend(f"framework hook release: {error}" for error in release_result.errors)
        if binding.get("release_id") != release.get("release_id"):
            errors.append("framework hook operation release_id binding mismatch")
        if binding.get("release_hash") != content_hash(release):
            errors.append("framework hook operation release_hash binding mismatch")
        matrix_record = release.get("adapter_matrix", {}) if isinstance(release.get("adapter_matrix"), dict) else {}
        if binding.get("matrix_id") != matrix_record.get("matrix_id"):
            errors.append("framework hook operation matrix_id binding mismatch")
        if binding.get("matrix_hash") != matrix_record.get("matrix_hash"):
            errors.append("framework hook operation matrix_hash binding mismatch")
        release_entry = _release_entry(release, framework, str(runtime.get("package") or ""), str(runtime.get("version") or ""))
        if release_entry is None:
            errors.append(f"framework hook operation has no matching release row: {framework}")
        else:
            _verify_release_entry_binding(operation, release_entry, errors)
    else:
        warnings.append("framework hook operation release/matrix replay was not supplied")

    if trace_payload is not None and framework:
        _verify_trace_binding(
            operation,
            trace_payload,
            framework,
            errors,
            warnings,
            root=Path(root),
            trace_source_path=trace_source_path,
        )
    else:
        warnings.append("framework hook operation trace payload replay was not supplied")

    audit_log = operation.get("audit_log", {})
    if not isinstance(audit_log, dict) or not audit_log.get("ref") or not audit_log.get("root"):
        errors.append("framework hook operation audit_log.ref and audit_log.root are required")

    controls = operation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("framework hook operation controls are required")
    _check_no_secret_values(operation, errors)
    return FrameworkHookOperationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_framework_hook_operation(
    chain: EvidenceChain,
    operation: dict[str, Any],
    trace_payload: dict[str, Any],
    release: dict[str, Any],
    matrix: dict[str, Any],
    *,
    root: str | Path = ".",
    trace_source_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_framework_hook_operation(
        operation,
        trace_payload,
        release,
        matrix,
        root=root,
        trace_source_path=trace_source_path,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid framework hook operation: " + "; ".join(result.errors))
    payload = {
        "operation_id": operation["operation_id"],
        "operation_hash": content_hash(operation),
        "mode": operation.get("mode"),
        "environment": operation.get("environment"),
        "captured_at": operation.get("captured_at"),
        "runtime": operation.get("runtime"),
        "hook": {
            "package": operation.get("hook", {}).get("package") if isinstance(operation.get("hook"), dict) else None,
            "version": operation.get("hook", {}).get("version") if isinstance(operation.get("hook"), dict) else None,
            "collector_hook_ref": operation.get("hook", {}).get("collector_hook_ref") if isinstance(operation.get("hook"), dict) else None,
            "hook_release_hash": operation.get("hook", {}).get("hook_release_hash") if isinstance(operation.get("hook"), dict) else None,
        },
        "release_binding": operation.get("release_binding"),
        "trace": operation.get("trace"),
        "collector": operation.get("collector"),
        "control_summary": _control_summary(operation.get("controls", [])),
    }
    return chain.append(FRAMEWORK_HOOK_OPERATION_ENTRY_TYPE, payload, key=key, timestamp=operation.get("captured_at"))


def _verify_trace_binding(
    operation: dict[str, Any],
    payload: dict[str, Any],
    framework: str,
    errors: list[str],
    warnings: list[str],
    *,
    root: Path,
    trace_source_path: str | Path | None,
) -> None:
    trace_record = operation.get("trace", {}) if isinstance(operation.get("trace"), dict) else {}
    selected = _select_trace(payload, framework, trace_record.get("source_trace_id") or trace_record.get("trace_id"))
    events = framework_trace_to_events(selected)
    chain_errors = verify_framework_event_chains(events)
    errors.extend(f"framework hook operation event chain: {error}" for error in chain_errors)
    if trace_record.get("source_trace_hash") != content_hash(selected):
        errors.append("framework hook operation source_trace_hash mismatch")
    if trace_record.get("event_count") != len(events):
        errors.append("framework hook operation event_count mismatch")
    if trace_record.get("event_names") != sorted({str(event.get("event_name")) for event in events}):
        errors.append("framework hook operation event_names mismatch")
    if trace_record.get("event_root") != content_hash(events):
        errors.append("framework hook operation event_root mismatch")
    if trace_record.get("trace_roots") != _trace_roots(events):
        errors.append("framework hook operation trace_roots mismatch")
    if trace_record.get("event_chain_verified") is not True:
        errors.append("framework hook operation event_chain_verified must be true")
    emitted_trace_id = str(events[0].get("trace_id") or "")
    emitted_attrs = events[0].get("attributes", {}) if isinstance(events[0].get("attributes"), dict) else {}
    emitted_source_trace_id = str(emitted_attrs.get("trustai.adapter.source_trace_id") or "")
    if trace_record.get("source_trace_id") and trace_record.get("source_trace_id") != emitted_source_trace_id:
        errors.append("framework hook operation source_trace_id mismatch")
    if trace_record.get("trace_id") != emitted_trace_id:
        errors.append("framework hook operation trace_id mismatch")
    source_artifact = trace_record.get("source_artifact")
    if source_artifact is not None:
        if trace_source_path is None:
            warnings.append("framework hook operation source_artifact was not byte-replayed because trace_source_path was not supplied")
        elif not isinstance(source_artifact, dict):
            errors.append("framework hook operation source_artifact must be an object")
        else:
            try:
                expected_artifact = _trace_source_artifact(
                    trace_source_path,
                    trace_payload=payload,
                    selected_trace=selected,
                    events=events,
                    root=root,
                    framework=framework,
                )
            except (OSError, ValueError) as exc:
                errors.append(f"framework hook operation source_artifact invalid: {exc}")
            else:
                if source_artifact != expected_artifact:
                    errors.append("framework hook operation source_artifact does not match supplied trace bytes")


def _verify_release_entry_binding(operation: dict[str, Any], release_entry: dict[str, Any], errors: list[str]) -> None:
    hook = operation.get("hook", {}) if isinstance(operation.get("hook"), dict) else {}
    release_hook = release_entry.get("hook", {}) if isinstance(release_entry.get("hook"), dict) else {}
    if hook.get("hook_release_hash") != release_entry.get("hook_release_hash"):
        errors.append("framework hook operation hook_release_hash mismatch")
    for field in ("package", "version", "mode", "module_ref", "entrypoint_ref", "collector_hook_ref"):
        if hook.get(field) != release_hook.get(field):
            errors.append(f"framework hook operation hook.{field} release binding mismatch")


def _select_trace(payload: dict[str, Any], framework: str, trace_id: Any = None) -> dict[str, Any]:
    traces = payload.get("traces") if isinstance(payload.get("traces"), list) else [payload]
    matches: list[dict[str, Any]] = []
    for item in traces:
        if not isinstance(item, dict):
            continue
        item_framework = str(item.get("framework") or "").strip().lower().replace("-", "_")
        item_trace_id = item.get("trace_id") or item.get("traceId") or item.get("run_id") or item.get("runId")
        if item_framework == framework and (trace_id in (None, "") or str(item_trace_id) == str(trace_id)):
            matches.append(item)
    if not matches:
        raise ValueError(f"framework trace payload has no trace for framework={framework} trace_id={trace_id}")
    if len(matches) > 1:
        raise ValueError(f"framework trace payload has multiple traces for framework={framework}; provide trace_id")
    return matches[0]


def _release_entry(release: dict[str, Any], framework: str, package: str | None = None, version: str | None = None) -> dict[str, Any] | None:
    matches: list[dict[str, Any]] = []
    for entry in release.get("entries", []):
        if not isinstance(entry, dict) or entry.get("framework") != framework:
            continue
        runtime = entry.get("runtime", {}) if isinstance(entry.get("runtime"), dict) else {}
        if package and runtime.get("package") != package:
            continue
        if version and runtime.get("version") != version:
            continue
        matches.append(entry)
    if len(matches) == 1:
        return matches[0]
    return None


def _trace_roots(events: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(event.get("attributes", {}).get("trustai.adapter.trace_root"))
            for event in events
            if isinstance(event.get("attributes"), dict) and event.get("attributes", {}).get("trustai.adapter.trace_root")
        }
    )


def _trace_source_artifact(
    path: str | Path,
    *,
    trace_payload: dict[str, Any],
    selected_trace: dict[str, Any],
    events: list[dict[str, Any]],
    root: Path,
    framework: str,
) -> dict[str, Any]:
    target = _resolve_trace_source_path(path, root)
    data = target.read_bytes()
    body = {
        "path": _artifact_path(target, root),
        "sha256": "sha256:" + sha256(data).hexdigest(),
        "size_bytes": len(data),
        "source_payload_hash": content_hash(trace_payload),
        "selected_trace_hash": content_hash(selected_trace),
        "framework": framework,
        "source_trace_id": str(selected_trace.get("trace_id") or selected_trace.get("traceId") or selected_trace.get("run_id") or selected_trace.get("runId") or ""),
        "event_count": len(events),
        "event_root": content_hash(events),
        "trace_roots": _trace_roots(events),
    }
    return {**body, "artifact_id": content_hash(body)}


def _resolve_trace_source_path(path: str | Path, root: Path) -> Path:
    target = Path(path)
    if target.is_absolute():
        return target
    rooted = root / target
    if rooted.exists():
        return rooted
    return target


def _artifact_path(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _controls(*, mode: str, collector_worker_ref: str | None, audit_log_ref: str | None, source_artifact_bound: bool) -> list[dict[str, Any]]:
    production = mode == "production-capture" and bool(collector_worker_ref) and bool(audit_log_ref)
    return [
        {"control": "hook-release-bound", "status": "passed"},
        {"control": "adapter-matrix-bound", "status": "passed"},
        {"control": "source-trace-replayed", "status": "passed"},
        {"control": "source-trace-artifact-bound", "status": "passed" if source_artifact_bound else "deferred"},
        {"control": "event-chain-verified", "status": "passed"},
        {"control": "collector-delivery-bound", "status": "passed" if collector_worker_ref else "deferred"},
        {"control": "production-runtime-evidence", "status": "passed" if production else "deferred"},
    ]


def _control_summary(controls: list[Any]) -> dict[str, int]:
    summary = {"passed": 0, "warning": 0, "deferred": 0, "failed": 0}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status") or "")
        if status in summary:
            summary[status] += 1
    return summary


def _normalize_framework(value: Any) -> str:
    framework = str(value or "").strip().lower().replace("-", "_")
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"unsupported framework hook operation framework: {value}")
    return framework


def _require_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"framework hook operation {field} is required")
    return text


def _normalized_list(values: Any) -> list[str]:
    if not values:
        return []
    if not isinstance(values, list):
        raise ValueError("framework hook operation list fields must be arrays")
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _redacted_ref(ref: str | None) -> dict[str, Any]:
    if not ref:
        raise ValueError("framework hook operation credential_ref is required")
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _check_no_secret_values(value: Any, errors: list[str], *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if not (isinstance(item, dict) and item.get("redacted") is True and item.get("ref")):
                    errors.append(f"framework hook operation secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(item, errors, path=child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_no_secret_values(item, errors, path=f"{path}[{index}]")