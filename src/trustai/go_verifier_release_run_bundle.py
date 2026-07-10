from __future__ import annotations

import base64
import binascii
import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .go_verifier_release_run import verify_go_verifier_release_run_receipt
from .verifier_conformance import verify_verifier_conformance_report
from .verifier_release import verify_verifier_release_manifest

GO_VERIFIER_RELEASE_RUN_BUNDLE_SCHEMA = "trustai.go-verifier-release-run-bundle/0.1"
GO_VERIFIER_RELEASE_RUN_BUNDLE_ENTRY_TYPE = "verifier.go_release_run_bundle_exported"
GO_VERIFIER_RELEASE_RUN_BUNDLE_MODES = {"offline-review", "auditor-review", "standards-review"}

SOURCE_TYPES: tuple[tuple[str, str], ...] = (
    ("release_run", "go-verifier-release-run-receipt"),
    ("verifier_release", "verifier-release-manifest"),
    ("build_attestation", "go-verifier-build-attestation"),
    ("conformance_report", "verifier-conformance-report"),
    ("standards_package", "standards-submission"),
)
REQUIRED_SOURCES = {"release_run", "verifier_release", "build_attestation", "conformance_report", "standards_package"}

SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class GoVerifierReleaseRunBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_go_verifier_release_run_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Go verifier release-run bundle must contain an object")
    return value


def write_go_verifier_release_run_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_go_verifier_release_run_bundle(
    release_run: dict[str, Any],
    verifier_release: dict[str, Any],
    build_attestation: dict[str, Any],
    conformance_report: dict[str, Any],
    standards_package: dict[str, Any],
    *,
    artifact_paths: dict[str, str | Path],
    root: str | Path = ".",
    binary_path: str | Path | None = None,
    mode: str = "offline-review",
    environment: str | None = None,
    reviewer_ref: str,
    bundle_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in GO_VERIFIER_RELEASE_RUN_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(GO_VERIFIER_RELEASE_RUN_BUNDLE_MODES)}")
    if not isinstance(reviewer_ref, str) or not reviewer_ref.strip():
        raise ValueError("Go verifier release-run bundle reviewer_ref is required")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    replay = verify_go_verifier_release_run_receipt(
        release_run,
        verifier_release,
        build_attestation,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        binary_path=binary_path,
        key=key,
    )
    if not replay.ok:
        raise ValueError("invalid Go verifier release-run source: " + "; ".join(replay.errors))

    sources = _source_objects(
        release_run=release_run,
        verifier_release=verifier_release,
        build_attestation=build_attestation,
        conformance_report=conformance_report,
        standards_package=standards_package,
    )
    secret_errors: list[str] = []
    _check_no_secret_values(sources, secret_errors)
    if secret_errors:
        raise ValueError("Go verifier release-run bundle source contains secret-like values: " + "; ".join(secret_errors))

    source_artifacts = _build_source_artifacts(artifact_paths, sources)
    raw_artifacts = _build_raw_artifacts(release_run, verifier_release, build_attestation, root)
    body: dict[str, Any] = {
        "schema": GO_VERIFIER_RELEASE_RUN_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "generated_at": timestamp,
        "reviewer_ref": reviewer_ref,
        "bundle_ref": bundle_ref or _default_bundle_ref(release_run),
        "source": _source_summary(release_run, verifier_release, build_attestation),
        "sources": sources,
        "source_artifacts": source_artifacts,
        "raw_artifacts": raw_artifacts,
        "summary": _bundle_summary(release_run, verifier_release, build_attestation, sources, source_artifacts, raw_artifacts),
        "controls": _controls(release_run, verifier_release, build_attestation, raw_artifacts, standards_package),
        "limitations": [
            "This bundle is self-contained for offline review of one Go verifier release workflow-run receipt and its replay sources.",
            "It embeds signed source JSON objects plus raw release source, workflow, build sidecar, provenance, and release artifact bytes.",
            "It binds the standards package object by hash, but does not inline every standards markdown source file.",
            "It does not claim the hosted workflow provider operated the run beyond the provider-native exports embedded in the bundle.",
        ],
    }
    bundle_id = content_hash(body)
    return {
        **body,
        "bundle_id": bundle_id,
        "signatures": [sign_value({"bundle_id": bundle_id, "go_verifier_release_run_bundle": body}, key)],
    }


def verify_go_verifier_release_run_bundle(
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> GoVerifierReleaseRunBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if bundle.get("schema") != GO_VERIFIER_RELEASE_RUN_BUNDLE_SCHEMA:
        errors.append(f"unsupported Go verifier release-run bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    expected_id = content_hash(body)
    if bundle.get("bundle_id") != expected_id:
        errors.append("bundle_id does not match canonical Go verifier release-run bundle body")

    signatures = bundle.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("Go verifier release-run bundle must include at least one signature")
    else:
        signed_value = {"bundle_id": bundle.get("bundle_id"), "go_verifier_release_run_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("Go verifier release-run bundle signature verification failed")

    mode = bundle.get("mode")
    if mode not in GO_VERIFIER_RELEASE_RUN_BUNDLE_MODES:
        errors.append("Go verifier release-run bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"Go verifier release-run bundle generated_at invalid: {exc}")
    if not isinstance(bundle.get("reviewer_ref"), str) or not bundle.get("reviewer_ref", "").strip():
        errors.append("Go verifier release-run bundle reviewer_ref is required")

    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        errors.append("Go verifier release-run bundle sources must be an object")
        sources = {}
    source_values = _required_source_objects(sources, errors)
    if source_values:
        _verify_source_artifacts(bundle.get("source_artifacts"), source_values, errors)
        raw_artifacts = bundle.get("raw_artifacts") if isinstance(bundle.get("raw_artifacts"), list) else []
        _verify_raw_artifacts(raw_artifacts, errors)
        release_run = source_values["release_run"]
        verifier_release = source_values["verifier_release"]
        build_attestation = source_values["build_attestation"]
        conformance_report = source_values["conformance_report"]
        standards_package = source_values["standards_package"]

        _verify_release_manifest(verifier_release, conformance_report, raw_artifacts, key, errors, warnings)
        _verify_build_attestation(build_attestation, verifier_release, conformance_report, raw_artifacts, key, errors, warnings)
        _verify_release_run(release_run, verifier_release, build_attestation, raw_artifacts, key, errors, warnings)
        _verify_standards_binding(verifier_release, standards_package, errors)

        expected_source = _source_summary(release_run, verifier_release, build_attestation)
        if bundle.get("source") != expected_source:
            errors.append("Go verifier release-run bundle source summary does not match embedded sources")
        source_artifacts = bundle.get("source_artifacts") if isinstance(bundle.get("source_artifacts"), list) else []
        expected_summary = _bundle_summary(release_run, verifier_release, build_attestation, source_values, source_artifacts, raw_artifacts)
        if bundle.get("summary") != expected_summary:
            errors.append("Go verifier release-run bundle summary does not match embedded sources")
        expected_controls = _controls(release_run, verifier_release, build_attestation, raw_artifacts, standards_package)
        if bundle.get("controls") != expected_controls:
            errors.append("Go verifier release-run bundle controls do not match embedded sources")

    _check_no_secret_values(bundle.get("sources", {}), errors)
    return GoVerifierReleaseRunBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def append_go_verifier_release_run_bundle(
    chain: EvidenceChain,
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_go_verifier_release_run_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid Go verifier release-run bundle: " + "; ".join(result.errors))
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
    return chain.append(GO_VERIFIER_RELEASE_RUN_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def write_go_verifier_release_run_bundle_markdown(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_go_verifier_release_run_bundle_markdown(bundle), encoding="utf-8")


def render_go_verifier_release_run_bundle_markdown(bundle: dict[str, Any]) -> str:
    source = bundle.get("source", {}) if isinstance(bundle.get("source"), dict) else {}
    summary = bundle.get("summary", {}) if isinstance(bundle.get("summary"), dict) else {}
    controls = bundle.get("controls", []) if isinstance(bundle.get("controls"), list) else []
    source_hashes = summary.get("source_object_hashes", {}) if isinstance(summary.get("source_object_hashes"), dict) else {}
    control_rows = "\n".join(
        "| {name} | {status} | {detail} |".format(
            name=_markdown_cell(control.get("name", "")),
            status=_markdown_cell(control.get("status", "")),
            detail=_markdown_cell(control.get("detail", "")),
        )
        for control in controls
        if isinstance(control, dict)
    )
    source_hash_lines = "\n".join(f"- {name}: `{value}`" for name, value in sorted(source_hashes.items()))
    limitations = "\n".join(f"- {limitation}" for limitation in bundle.get("limitations", []))
    return f"""# TrustAI Go Verifier Release-Run Bundle

Bundle ID: `{bundle.get('bundle_id', '')}`

Bundle ref: `{bundle.get('bundle_ref', '')}`

Mode: `{bundle.get('mode', '')}`

Environment: `{bundle.get('environment', '')}`

Generated at: `{bundle.get('generated_at', '')}`

Reviewer: `{bundle.get('reviewer_ref', '')}`

## Source

- Release-run ID: `{source.get('run_id', '')}`
- Workflow run ID: `{source.get('workflow_run_id', '')}`
- Release ID: `{source.get('release_id', '')}`
- Build ID: `{source.get('build_id', '')}`
- Build mode: `{source.get('build_mode', '')}`
- Binary SHA-256: `{source.get('binary_sha256', '')}`

## Summary

- JSON source artifacts: {summary.get('source_artifact_count', 0)}
- Embedded raw artifacts: {summary.get('raw_artifact_count', 0)}
- Release source files: {summary.get('release_source_file_count', 0)}
- Release artifacts: {summary.get('release_artifact_count', 0)}
- Checks: {summary.get('check_count', 0)}
- Source artifact SHA-256 root: `{summary.get('source_artifact_sha256_root', '')}`
- Raw artifact SHA-256 root: `{summary.get('raw_artifact_sha256_root', '')}`

## Source Object Hashes

{source_hash_lines}

## Controls

| Control | Status | Detail |
| --- | --- | --- |
{control_rows}

## Limits

{limitations}
"""


def extract_go_verifier_release_run_bundle_sources(
    bundle: dict[str, Any],
    out_dir: str | Path,
    *,
    key: str | None = None,
    overwrite: bool = False,
) -> list[dict[str, str]]:
    result = verify_go_verifier_release_run_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid Go verifier release-run bundle: " + "; ".join(result.errors))
    target_dir = Path(out_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[dict[str, str]] = []
    for artifact in bundle.get("source_artifacts", []):
        if not isinstance(artifact, dict):
            continue
        name = str(artifact.get("name") or "source")
        data = _artifact_bytes(artifact)
        target = target_dir / _source_extract_filename(name)
        _write_extracted(target, data, overwrite)
        extracted.append({"name": name, "artifact_type": str(artifact.get("artifact_type")), "extracted_to": str(target)})
    raw_dir = target_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for artifact in bundle.get("raw_artifacts", []):
        if not isinstance(artifact, dict):
            continue
        name = str(artifact.get("name") or "raw")
        data = _artifact_bytes(artifact)
        target = raw_dir / _raw_extract_filename(artifact)
        _write_extracted(target, data, overwrite)
        extracted.append({"name": name, "artifact_type": str(artifact.get("artifact_type")), "extracted_to": str(target)})
    return extracted


def _source_objects(**objects: Any) -> dict[str, Any]:
    return {name: _clone(value) for name, value in objects.items() if value is not None}


def _required_source_objects(sources: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    supported = {name for name, _ in SOURCE_TYPES}
    for name in sources:
        if name not in supported:
            errors.append(f"Go verifier release-run bundle sources.{name} is unsupported")
    for name in sorted(REQUIRED_SOURCES):
        value = sources.get(name)
        if not isinstance(value, dict):
            errors.append(f"Go verifier release-run bundle sources.{name} is required")
        else:
            values[name] = value
    return values if REQUIRED_SOURCES <= set(values) else {}


def _build_source_artifacts(artifact_paths: dict[str, str | Path], sources: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    artifact_types = dict(SOURCE_TYPES)
    for name in [source_name for source_name, _ in SOURCE_TYPES if source_name in sources]:
        path = artifact_paths.get(name)
        if path is None:
            raise ValueError(f"Go verifier release-run bundle artifact path is required: {name}")
        source = Path(path)
        data = source.read_bytes()
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Go verifier release-run bundle artifact JSON invalid: {name}: {exc}") from exc
        parsed_hash = content_hash(parsed)
        expected_hash = content_hash(sources[name])
        if parsed_hash != expected_hash:
            raise ValueError(f"Go verifier release-run bundle artifact content hash mismatch: {name}")
        body = {
            "name": name,
            "artifact_type": artifact_types[name],
            "path": str(path).replace("\\", "/"),
            "media_type": "application/json" if source.suffix.lower() == ".json" else "application/octet-stream",
            "size_bytes": len(data),
            "sha256": _sha256_hex(data),
            "content_hash": parsed_hash,
            "expected_content_hash": expected_hash,
            "content_b64": base64.b64encode(data).decode("ascii"),
        }
        artifacts.append({**body, "artifact_id": content_hash(body)})
    return artifacts


def _verify_source_artifacts(value: Any, source_objects: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append("Go verifier release-run bundle source_artifacts must be a list")
        return
    expected_names = set(source_objects)
    actual_names: set[str] = set()
    supported = dict(SOURCE_TYPES)
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("Go verifier release-run bundle source artifact must be an object")
            continue
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"Go verifier release-run bundle source artifact id mismatch: {artifact.get('name')}")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            errors.append("Go verifier release-run bundle source artifact name is required")
            continue
        actual_names.add(name)
        if name not in supported:
            errors.append(f"Go verifier release-run bundle source artifact unsupported: {name}")
            continue
        if artifact.get("artifact_type") != supported[name]:
            errors.append(f"Go verifier release-run bundle source artifact type mismatch: {name}")
        try:
            data = _artifact_bytes(artifact)
        except ValueError as exc:
            errors.append(f"Go verifier release-run bundle source artifact content_b64 invalid: {name}: {exc}")
            continue
        if artifact.get("sha256") != _sha256_hex(data):
            errors.append(f"Go verifier release-run bundle source artifact sha256 mismatch: {name}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"Go verifier release-run bundle source artifact size mismatch: {name}")
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"Go verifier release-run bundle source artifact JSON invalid: {name}: {exc}")
            continue
        parsed_hash = content_hash(parsed)
        if artifact.get("content_hash") != parsed_hash:
            errors.append(f"Go verifier release-run bundle source artifact content hash mismatch: {name}")
        source_object = source_objects.get(name)
        if source_object is None:
            errors.append(f"Go verifier release-run bundle source artifact has no embedded source: {name}")
        elif content_hash(source_object) != parsed_hash:
            errors.append(f"Go verifier release-run bundle source artifact does not match embedded source: {name}")
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing:
        errors.append("Go verifier release-run bundle source artifacts missing: " + ", ".join(missing))
    if extra:
        errors.append("Go verifier release-run bundle source artifacts unsupported for embedded sources: " + ", ".join(extra))


def _build_raw_artifacts(
    release_run: dict[str, Any],
    verifier_release: dict[str, Any],
    build_attestation: dict[str, Any],
    root: str | Path,
) -> list[dict[str, Any]]:
    root_path = Path(root)
    artifacts: list[dict[str, Any]] = []
    for ref in _expected_raw_refs(release_run, verifier_release, build_attestation):
        source_path = _local_ref_path(root_path, ref["path"])
        if source_path is None:
            raise ValueError(f"Go verifier release-run bundle raw artifact ref is not local: {ref['path']}")
        data = source_path.read_bytes()
        actual_sha = _sha256_hex(data)
        expected_sha = _normalize_sha256(ref.get("expected_sha256"))
        if expected_sha and actual_sha != expected_sha:
            raise ValueError(f"Go verifier release-run bundle raw artifact sha256 mismatch: {ref['name']}")
        expected_size = ref.get("expected_size_bytes")
        if expected_size is not None and len(data) != expected_size:
            raise ValueError(f"Go verifier release-run bundle raw artifact size mismatch: {ref['name']}")
        body = {
            "name": ref["name"],
            "artifact_type": ref["artifact_type"],
            "path": str(ref["path"]).replace("\\", "/"),
            "media_type": _media_type(source_path),
            "size_bytes": len(data),
            "expected_size_bytes": expected_size,
            "sha256": actual_sha,
            "expected_sha256": expected_sha,
            "content_b64": base64.b64encode(data).decode("ascii"),
        }
        artifacts.append({**body, "artifact_id": content_hash(body)})
    return artifacts


def _verify_raw_artifacts(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append("Go verifier release-run bundle raw_artifacts must be a list")
        return
    seen_ids: set[str] = set()
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("Go verifier release-run bundle raw artifact must be an object")
            continue
        body = without_keys(artifact, "artifact_id")
        artifact_id = artifact.get("artifact_id")
        if artifact_id != content_hash(body):
            errors.append(f"Go verifier release-run bundle raw artifact id mismatch: {artifact.get('name')}")
        if artifact_id in seen_ids:
            errors.append(f"Go verifier release-run bundle raw artifact duplicated: {artifact.get('name')}")
        if isinstance(artifact_id, str):
            seen_ids.add(artifact_id)
        for field in ("name", "artifact_type", "path", "sha256", "content_b64"):
            if artifact.get(field) in (None, ""):
                errors.append(f"Go verifier release-run bundle raw artifact {artifact.get('name')} missing {field}")
        try:
            data = _artifact_bytes(artifact)
        except ValueError as exc:
            errors.append(f"Go verifier release-run bundle raw artifact content_b64 invalid: {artifact.get('name')}: {exc}")
            continue
        if artifact.get("sha256") != _sha256_hex(data):
            errors.append(f"Go verifier release-run bundle raw artifact sha256 mismatch: {artifact.get('name')}")
        if artifact.get("expected_sha256") and artifact.get("expected_sha256") != _sha256_hex(data):
            errors.append(f"Go verifier release-run bundle raw artifact expected sha256 mismatch: {artifact.get('name')}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"Go verifier release-run bundle raw artifact size mismatch: {artifact.get('name')}")
        if artifact.get("expected_size_bytes") is not None and artifact.get("expected_size_bytes") != len(data):
            errors.append(f"Go verifier release-run bundle raw artifact expected size mismatch: {artifact.get('name')}")


def _verify_release_manifest(
    verifier_release: dict[str, Any],
    conformance_report: dict[str, Any],
    raw_artifacts: list[dict[str, Any]],
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_root = Path(tmp_dir)
        for source in verifier_release.get("source_files", []):
            if not isinstance(source, dict):
                continue
            path = source.get("path")
            artifact = _find_raw_artifact(raw_artifacts, "release-source", path, source.get("sha256"))
            if artifact is None:
                continue
            try:
                _write_temp_relative(temp_root, str(path), _artifact_bytes(artifact))
            except ValueError as exc:
                errors.append(f"Go verifier release-run bundle release source extract failed: {exc}")
        result = verify_verifier_release_manifest(
            verifier_release,
            root=temp_root,
            conformance_report=conformance_report,
            standards_package=None,
            key=key,
        )
    errors.extend(f"verifier release source: {error}" for error in result.errors)
    warnings.extend(f"verifier release source: {warning}" for warning in result.warnings)
    conformance_result = verify_verifier_conformance_report(conformance_report)
    if not conformance_result.ok:
        errors.extend(f"conformance report source: {error}" for error in conformance_result.errors)


def _verify_build_attestation(
    build_attestation: dict[str, Any],
    verifier_release: dict[str, Any],
    conformance_report: dict[str, Any],
    raw_artifacts: list[dict[str, Any]],
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if build_attestation.get("schema") != "trustai.go-verifier-build-attestation/0.1":
        errors.append(f"unsupported Go verifier build schema: {build_attestation.get('schema')}")
    body = without_keys(build_attestation, "build_id", "signatures")
    if build_attestation.get("build_id") != content_hash(body):
        errors.append("Go verifier build build_id does not match canonical body")
    _verify_signature(build_attestation, "build_id", "go_verifier_build", "Go verifier build attestation", key, errors)
    source = build_attestation.get("source", {}) if isinstance(build_attestation.get("source"), dict) else {}
    expected_go_sources = _go_source_records(verifier_release)
    expected_source = {
        "release_id": verifier_release.get("release_id"),
        "release_hash": content_hash(verifier_release),
        "release_version": verifier_release.get("release", {}).get("version"),
        "go_source_count": len(expected_go_sources),
        "go_source_hash": content_hash(expected_go_sources),
        "conformance_report_id": conformance_report.get("report_id"),
    }
    for field, expected in expected_source.items():
        if source.get(field) != expected:
            errors.append(f"Go verifier build source.{field} does not match embedded release/conformance source")
    if build_attestation.get("go_sources") != expected_go_sources:
        errors.append("Go verifier build go_sources do not match embedded verifier release source files")
    build = build_attestation.get("build", {}) if isinstance(build_attestation.get("build"), dict) else {}
    if build.get("cgo_enabled") is not False:
        errors.append("Go verifier build must set cgo_enabled=false for static verifier releases")
    if build.get("trimpath") is not True:
        errors.append("Go verifier build must set trimpath=true for reproducible verifier releases")
    if build.get("mode") == "binary-attested" and (not build.get("build_log_ref") or not build.get("build_log_hash")):
        errors.append("Go verifier build binary-attested mode requires build_log_ref and build_log_hash")
    for label, ref, expected_hash in _build_sidecar_refs(build_attestation):
        if not expected_hash:
            continue
        if _find_raw_artifact(raw_artifacts, "build-sidecar", ref, expected_hash) is None:
            errors.append(f"Go verifier build sidecar raw artifact missing: {label}")
    binary = build_attestation.get("binary", {}) if isinstance(build_attestation.get("binary"), dict) else {}
    if binary.get("status") == "available" and not binary.get("sha256"):
        errors.append("Go verifier build available binary must include sha256")
    if binary.get("status") != "available":
        warnings.append("Go verifier build static binary was not supplied")


def _verify_release_run(
    release_run: dict[str, Any],
    verifier_release: dict[str, Any],
    build_attestation: dict[str, Any],
    raw_artifacts: list[dict[str, Any]],
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if release_run.get("schema") != "trustai.go-verifier-release-run/0.1":
        errors.append(f"unsupported Go verifier release-run schema: {release_run.get('schema')}")
    body = without_keys(release_run, "run_id", "signatures")
    if release_run.get("run_id") != content_hash(body):
        errors.append("Go verifier release-run run_id does not match canonical body")
    _verify_signature(release_run, "run_id", "go_verifier_release_run", "Go verifier release-run receipt", key, errors)
    source = release_run.get("source", {}) if isinstance(release_run.get("source"), dict) else {}
    if source.get("release_id") != verifier_release.get("release_id"):
        errors.append("Go verifier release-run source.release_id does not match embedded verifier release")
    if source.get("release_hash") != content_hash(verifier_release):
        errors.append("Go verifier release-run source.release_hash does not match embedded verifier release")
    if source.get("build_id") != build_attestation.get("build_id"):
        errors.append("Go verifier release-run source.build_id does not match embedded build attestation")
    if source.get("build_hash") != content_hash(build_attestation):
        errors.append("Go verifier release-run source.build_hash does not match embedded build attestation")
    workflow_run = release_run.get("workflow_run", {}) if isinstance(release_run.get("workflow_run"), dict) else {}
    if workflow_run.get("status") != "completed":
        errors.append("Go verifier release-run workflow_run.status must be completed")
    if workflow_run.get("conclusion") != "success":
        errors.append("Go verifier release-run workflow_run.conclusion must be success")
    for field in ("started_at", "completed_at"):
        if workflow_run.get(field):
            try:
                parse_rfc3339(str(workflow_run.get(field)))
            except ValueError as exc:
                errors.append(f"Go verifier release-run workflow_run.{field} invalid: {exc}")
    workflow = release_run.get("workflow", {}) if isinstance(release_run.get("workflow"), dict) else {}
    workflow_artifact = _find_raw_artifact(raw_artifacts, "workflow-source", workflow.get("path"), workflow.get("sha256"))
    if workflow_artifact is None:
        errors.append("Go verifier release-run workflow raw artifact missing")
    else:
        text = _artifact_bytes(workflow_artifact).decode("utf-8", errors="replace")
        for marker in ("actions/setup-go@v5", 'CGO_ENABLED: "0"', "go build -trimpath", "actions/attest-build-provenance@v2"):
            if marker not in text:
                errors.append(f"Go verifier release-run workflow missing required release control: {marker}")
    checks = release_run.get("checks", [])
    if not isinstance(checks, list) or not checks:
        errors.append("Go verifier release-run must include at least one completed check")
    else:
        for check in checks:
            if not isinstance(check, dict):
                errors.append("Go verifier release-run check entries must be objects")
                continue
            if check.get("status") != "completed" or check.get("conclusion") != "success":
                errors.append(f"Go verifier release-run check {check.get('name')} must complete successfully")
    artifacts = release_run.get("artifacts", [])
    binary_sha = source.get("binary_sha256")
    has_binary = False
    if not isinstance(artifacts, list):
        errors.append("Go verifier release-run artifacts must be a list")
    else:
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                errors.append("Go verifier release-run artifact entries must be objects")
                continue
            if artifact.get("sha256") == binary_sha:
                has_binary = True
            if artifact.get("sha256") and _find_raw_artifact(raw_artifacts, "release-artifact", artifact.get("path"), artifact.get("sha256")) is None:
                errors.append(f"Go verifier release-run artifact raw bytes missing: {artifact.get('name')}")
    if binary_sha and not has_binary:
        errors.append("Go verifier release-run binary artifact matching Go verifier build binary_sha256 is missing")
    provenance = release_run.get("provenance", {}) if isinstance(release_run.get("provenance"), dict) else {}
    if provenance.get("hosted_provenance_hash"):
        if not provenance.get("oidc_issuer") or not provenance.get("oidc_subject"):
            errors.append("Go verifier release-run hosted provenance requires oidc_issuer and oidc_subject")
        if _find_raw_artifact(raw_artifacts, "hosted-provenance", provenance.get("hosted_provenance_ref"), provenance.get("hosted_provenance_hash")) is None:
            errors.append("Go verifier release-run hosted provenance raw artifact missing")
    else:
        warnings.append("Go verifier release-run hosted provenance hash was not supplied")


def _verify_standards_binding(verifier_release: dict[str, Any], standards_package: dict[str, Any], errors: list[str]) -> None:
    standards_ref = verifier_release.get("standards_package")
    if not isinstance(standards_ref, dict):
        errors.append("verifier release missing standards package reference")
        return
    if standards_ref.get("content_hash") != content_hash(standards_package):
        errors.append("standards package source hash mismatch")
    if standards_ref.get("package_id") != standards_package.get("package_id"):
        errors.append("standards package id mismatch")


def _verify_signature(value: dict[str, Any], id_field: str, body_field: str, label: str, key: str | None, errors: list[str]) -> None:
    signatures = value.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append(f"{label} must include at least one signature")
        return
    body = without_keys(value, id_field, "signatures")
    signed_value = {id_field: value.get(id_field), body_field: body}
    if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
        errors.append(f"{label} signature verification failed")


def _expected_raw_refs(
    release_run: dict[str, Any],
    verifier_release: dict[str, Any],
    build_attestation: dict[str, Any],
) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for source in verifier_release.get("source_files", []):
        if isinstance(source, dict) and source.get("path"):
            refs.append(
                {
                    "name": f"release-source:{source.get('path')}",
                    "artifact_type": "release-source",
                    "path": source.get("path"),
                    "expected_sha256": source.get("sha256"),
                    "expected_size_bytes": source.get("size_bytes"),
                }
            )
    workflow = release_run.get("workflow", {}) if isinstance(release_run.get("workflow"), dict) else {}
    if workflow.get("path"):
        refs.append(
            {
                "name": f"workflow:{workflow.get('path')}",
                "artifact_type": "workflow-source",
                "path": workflow.get("path"),
                "expected_sha256": workflow.get("sha256"),
                "expected_size_bytes": workflow.get("size_bytes"),
            }
        )
    for artifact in release_run.get("artifacts", []):
        if isinstance(artifact, dict) and artifact.get("path"):
            refs.append(
                {
                    "name": f"release-artifact:{artifact.get('name')}",
                    "artifact_type": "release-artifact",
                    "path": artifact.get("path"),
                    "expected_sha256": artifact.get("sha256"),
                    "expected_size_bytes": artifact.get("size_bytes"),
                }
            )
    for label, ref, expected_hash in _build_sidecar_refs(build_attestation):
        if ref:
            refs.append(
                {
                    "name": f"build-sidecar:{label}",
                    "artifact_type": "build-sidecar",
                    "path": ref,
                    "expected_sha256": expected_hash,
                    "expected_size_bytes": None,
                }
            )
    provenance = release_run.get("provenance", {}) if isinstance(release_run.get("provenance"), dict) else {}
    if provenance.get("hosted_provenance_ref"):
        refs.append(
            {
                "name": "hosted-provenance:release-run",
                "artifact_type": "hosted-provenance",
                "path": provenance.get("hosted_provenance_ref"),
                "expected_sha256": provenance.get("hosted_provenance_hash"),
                "expected_size_bytes": None,
            }
        )
    return refs


def _build_sidecar_refs(build_attestation: dict[str, Any]) -> list[tuple[str, Any, Any]]:
    build = build_attestation.get("build", {}) if isinstance(build_attestation.get("build"), dict) else {}
    provenance = build_attestation.get("provenance", {}) if isinstance(build_attestation.get("provenance"), dict) else {}
    return [
        ("build-log", build.get("build_log_ref"), build.get("build_log_hash")),
        ("sbom", provenance.get("sbom_ref"), provenance.get("sbom_hash")),
        ("provenance", provenance.get("provenance_ref"), provenance.get("provenance_hash")),
        ("signature", provenance.get("signature_ref"), provenance.get("signature_hash")),
    ]


def _find_raw_artifact(raw_artifacts: list[Any], artifact_type: str, path: Any, expected_sha256: Any) -> dict[str, Any] | None:
    if not isinstance(path, str) or not path:
        return None
    expected = _normalize_sha256(expected_sha256)
    normalized_path = path.replace("\\", "/")
    for artifact in raw_artifacts:
        if not isinstance(artifact, dict):
            continue
        if artifact.get("artifact_type") != artifact_type:
            continue
        if str(artifact.get("path") or "").replace("\\", "/") != normalized_path:
            continue
        if expected and artifact.get("sha256") != expected:
            continue
        return artifact
    return None


def _source_summary(release_run: dict[str, Any], verifier_release: dict[str, Any], build_attestation: dict[str, Any]) -> dict[str, Any]:
    workflow_run = release_run.get("workflow_run", {}) if isinstance(release_run.get("workflow_run"), dict) else {}
    build = build_attestation.get("build", {}) if isinstance(build_attestation.get("build"), dict) else {}
    binary = build_attestation.get("binary", {}) if isinstance(build_attestation.get("binary"), dict) else {}
    return {
        "run_id": release_run.get("run_id"),
        "run_hash": content_hash(release_run),
        "workflow_run_id": workflow_run.get("workflow_run_id"),
        "workflow_run_url": workflow_run.get("workflow_run_url"),
        "release_id": verifier_release.get("release_id"),
        "release_hash": content_hash(verifier_release),
        "release_version": verifier_release.get("release", {}).get("version"),
        "build_id": build_attestation.get("build_id"),
        "build_hash": content_hash(build_attestation),
        "build_mode": build.get("mode"),
        "binary_sha256": binary.get("sha256"),
        "artifact_count": len(release_run.get("artifacts", [])) if isinstance(release_run.get("artifacts"), list) else 0,
        "check_count": len(release_run.get("checks", [])) if isinstance(release_run.get("checks"), list) else 0,
    }


def _bundle_summary(
    release_run: dict[str, Any],
    verifier_release: dict[str, Any],
    build_attestation: dict[str, Any],
    sources: dict[str, Any],
    source_artifacts: list[dict[str, Any]],
    raw_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "source_artifact_count": len(source_artifacts),
        "raw_artifact_count": len(raw_artifacts),
        "source_artifact_sha256_root": content_hash([artifact.get("sha256") for artifact in source_artifacts]),
        "raw_artifact_sha256_root": content_hash([artifact.get("sha256") for artifact in raw_artifacts]),
        "source_object_hashes": {name: content_hash(value) for name, value in sorted(sources.items())},
        "release_source_file_count": len(verifier_release.get("source_files", [])) if isinstance(verifier_release.get("source_files"), list) else 0,
        "release_artifact_count": len(release_run.get("artifacts", [])) if isinstance(release_run.get("artifacts"), list) else 0,
        "check_count": len(release_run.get("checks", [])) if isinstance(release_run.get("checks"), list) else 0,
        "build_sidecar_count": len([item for item in _build_sidecar_refs(build_attestation) if item[1]]),
        "release_run_control_summary": _status_summary(release_run.get("controls", [])),
        "build_control_summary": _status_summary(build_attestation.get("controls", [])),
    }


def _controls(
    release_run: dict[str, Any],
    verifier_release: dict[str, Any],
    build_attestation: dict[str, Any],
    raw_artifacts: list[dict[str, Any]],
    standards_package: dict[str, Any],
) -> list[dict[str, str]]:
    expected_release_sources = [
        source for source in verifier_release.get("source_files", []) if isinstance(source, dict) and source.get("path")
    ]
    release_sources_present = all(
        _find_raw_artifact(raw_artifacts, "release-source", source.get("path"), source.get("sha256")) is not None
        for source in expected_release_sources
    )
    workflow = release_run.get("workflow", {}) if isinstance(release_run.get("workflow"), dict) else {}
    workflow_present = _find_raw_artifact(raw_artifacts, "workflow-source", workflow.get("path"), workflow.get("sha256")) is not None
    artifacts = release_run.get("artifacts", []) if isinstance(release_run.get("artifacts"), list) else []
    release_artifacts_present = all(
        not isinstance(artifact, dict)
        or not artifact.get("sha256")
        or _find_raw_artifact(raw_artifacts, "release-artifact", artifact.get("path"), artifact.get("sha256")) is not None
        for artifact in artifacts
    )
    sidecar_refs = [item for item in _build_sidecar_refs(build_attestation) if item[1] and item[2]]
    sidecars_present = all(_find_raw_artifact(raw_artifacts, "build-sidecar", ref, expected_hash) is not None for _, ref, expected_hash in sidecar_refs)
    provenance = release_run.get("provenance", {}) if isinstance(release_run.get("provenance"), dict) else {}
    hosted_present = not provenance.get("hosted_provenance_hash") or _find_raw_artifact(
        raw_artifacts,
        "hosted-provenance",
        provenance.get("hosted_provenance_ref"),
        provenance.get("hosted_provenance_hash"),
    ) is not None
    standards_ref = verifier_release.get("standards_package", {}) if isinstance(verifier_release.get("standards_package"), dict) else {}
    standards_bound = bool(standards_ref) and standards_ref.get("content_hash") == content_hash(standards_package)
    return [
        {
            "name": "release-run-source-object-replay",
            "status": "passed",
            "detail": "Signed release-run, verifier release, build attestation, conformance report, and standards package source objects are embedded and hash-bound.",
        },
        {
            "name": "verifier-release-source-byte-binding",
            "status": "passed" if release_sources_present else "failed",
            "detail": "Verifier release source files are embedded as raw bytes and replay against release manifest hashes.",
        },
        {
            "name": "workflow-source-byte-binding",
            "status": "passed" if workflow_present else "failed",
            "detail": "Release workflow source bytes are embedded and checked for required static verifier release controls.",
        },
        {
            "name": "release-artifact-byte-binding",
            "status": "passed" if release_artifacts_present else "failed",
            "detail": "Workflow release artifact bytes are embedded and checked against release-run artifact hashes.",
        },
        {
            "name": "build-sidecar-byte-binding",
            "status": "passed" if sidecars_present else "failed",
            "detail": "Build log, SBOM, provenance, and signature sidecars are embedded when the build attestation records hashes.",
        },
        {
            "name": "hosted-provenance-byte-binding",
            "status": "passed" if hosted_present else "failed",
            "detail": "Hosted provenance bytes are embedded when the release-run receipt records a hosted provenance hash.",
        },
        {
            "name": "standards-package-hash-binding",
            "status": "passed" if standards_bound else "failed",
            "detail": "Embedded standards package object hash matches the signed verifier release reference.",
        },
    ]


def _go_source_records(release: dict[str, Any]) -> list[dict[str, Any]]:
    records = [
        {
            "path": source.get("path"),
            "sha256": source.get("sha256"),
            "size_bytes": source.get("size_bytes"),
        }
        for source in release.get("source_files", [])
        if isinstance(source, dict) and str(source.get("path", "")).startswith("verifier/go/trustai-verify/")
    ]
    return sorted(records, key=lambda item: str(item.get("path")))


def _status_summary(items: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            status = str(item.get("status", "unknown"))
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _default_bundle_ref(release_run: dict[str, Any]) -> str:
    return f"go-verifier-release-run-bundle:{release_run.get('run_id', 'unknown')}"


def _artifact_bytes(artifact: dict[str, Any]) -> bytes:
    try:
        return base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ValueError(str(exc)) from exc


def _write_extracted(target: Path, data: bytes, overwrite: bool) -> None:
    if target.exists() and not overwrite:
        raise ValueError(f"extracted bundle source already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _write_temp_relative(root: Path, path: str, data: bytes) -> None:
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe relative path: {path}")
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _local_ref_path(root: Path, ref: Any) -> Path | None:
    if not isinstance(ref, str) or not ref:
        return None
    if "://" in ref:
        return None
    if ":" in ref and not (len(ref) > 1 and ref[1] == ":"):
        return None
    path = Path(ref)
    if path.is_absolute():
        return path
    return root / path


def _normalize_sha256(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("sha256:"):
        return value[7:]
    return value


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix in {".md", ".txt", ".log", ".yml", ".yaml", ".go", ".py", ".mod"}:
        return "text/plain"
    return "application/octet-stream"


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _source_extract_filename(name: str) -> str:
    return _safe_filename(name) + ".json"


def _raw_extract_filename(artifact: dict[str, Any]) -> str:
    path = Path(str(artifact.get("path") or "artifact"))
    suffix = path.suffix if path.suffix else ".bin"
    return f"{_safe_filename(str(artifact.get('name') or 'raw'))}-{str(artifact.get('artifact_id', ''))[:12]}{suffix}"


def _safe_filename(value: str) -> str:
    result = "".join(character if character.isalnum() or character in {".", "-", "_"} else "_" for character in value)
    return result.strip("._") or "artifact"


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
                    errors.append(f"Go verifier release-run bundle secret-like field must be redacted reference: {child_path}")
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
