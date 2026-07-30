from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, sha256_hex, utc_now, without_keys
from .chain import EvidenceChain
from .contracts import contract_hash, validate_contract
from .crypto import sign_value, verify_value
from .lifecycle import verify_soak_demotion_receipt
from .reexecution import verify_reexecution_report
from .shadow import (
    verify_temporal_holdout_manifest,
    verify_traffic_completeness_receipt,
    verify_traffic_holdout_export,
)
from .shadow_authority import verify_shadow_authority_dossier

SHADOW_REPLAY_REVIEW_BUNDLE_SCHEMA = "trustai.shadow-replay-review-bundle/0.1"
SHADOW_REPLAY_REVIEW_BUNDLE_ENTRY_TYPE = "shadow.replay_review_bundle.attested"
SHADOW_REPLAY_REVIEW_BUNDLE_MODES = {"offline-review", "auditor-review", "production-review"}

SOURCE_TYPES: tuple[tuple[str, str], ...] = (
    ("contract", "verification-contract"),
    ("replay", "shadow-replay-source"),
    ("temporal_holdout", "temporal-holdout-manifest"),
    ("traffic_export", "traffic-holdout-export"),
    ("traffic_completeness", "traffic-completeness-receipt"),
    ("provider_export", "traffic-completeness-provider-export"),
    ("reexecution_report", "reexecution-report"),
    ("soak_entry", "soak-report-chain-entry"),
    ("demotion_entry", "demotion-chain-entry"),
    ("soak_demotion", "soak-demotion-receipt"),
    ("shadow_authority", "shadow-authority-dossier"),
)
REQUIRED_SOURCES = {
    "contract",
    "replay",
    "temporal_holdout",
    "traffic_export",
    "traffic_completeness",
    "provider_export",
}
OPTIONAL_SOURCE_GROUPS = (
    {"reexecution_report"},
    {"soak_entry", "demotion_entry", "soak_demotion"},
    {"shadow_authority"},
)


@dataclass
class ShadowReplayReviewBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_shadow_replay_review_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("shadow replay review bundle must contain an object")
    return value


def write_shadow_replay_review_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def build_shadow_replay_review_bundle(
    contract: dict[str, Any],
    replay: dict[str, Any],
    temporal_holdout: dict[str, Any],
    traffic_export: dict[str, Any],
    traffic_completeness: dict[str, Any],
    provider_export: dict[str, Any],
    *,
    artifact_paths: dict[str, str | Path],
    reexecution_report: dict[str, Any] | None = None,
    soak_entry: dict[str, Any] | None = None,
    demotion_entry: dict[str, Any] | None = None,
    soak_demotion: dict[str, Any] | None = None,
    shadow_authority: dict[str, Any] | None = None,
    mode: str = "offline-review",
    environment: str | None = None,
    reviewer_ref: str,
    bundle_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in SHADOW_REPLAY_REVIEW_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(SHADOW_REPLAY_REVIEW_BUNDLE_MODES)}")
    _require_text(reviewer_ref, "reviewer_ref")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    _validate_required_sources(contract, replay, temporal_holdout, traffic_export, traffic_completeness, provider_export)
    _validate_optional_groups(
        reexecution_report=reexecution_report,
        soak_entry=soak_entry,
        demotion_entry=demotion_entry,
        soak_demotion=soak_demotion,
        shadow_authority=shadow_authority,
    )

    _replay_sources(
        contract=contract,
        replay=replay,
        temporal_holdout=temporal_holdout,
        traffic_export=traffic_export,
        traffic_completeness=traffic_completeness,
        provider_export=provider_export,
        replay_source_path=artifact_paths["replay"],
        provider_export_path=artifact_paths["provider_export"],
        reexecution_report=reexecution_report,
        soak_entry=soak_entry,
        demotion_entry=demotion_entry,
        soak_demotion=soak_demotion,
        shadow_authority=shadow_authority,
        key=key,
    )
    sources = _source_objects(
        contract=contract,
        replay=replay,
        temporal_holdout=temporal_holdout,
        traffic_export=traffic_export,
        traffic_completeness=traffic_completeness,
        provider_export=provider_export,
        reexecution_report=reexecution_report,
        soak_entry=soak_entry,
        demotion_entry=demotion_entry,
        soak_demotion=soak_demotion,
        shadow_authority=shadow_authority,
    )
    source_artifacts = _build_source_artifacts(artifact_paths, sources)
    body: dict[str, Any] = {
        "schema": SHADOW_REPLAY_REVIEW_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment or _source_environment(contract, traffic_export),
        "generated_at": timestamp,
        "reviewer_ref": reviewer_ref,
        "bundle_ref": bundle_ref or _default_bundle_ref(replay, traffic_export),
        "source": _source_summary(contract, replay, temporal_holdout, traffic_export, traffic_completeness, provider_export, shadow_authority),
        "sources": sources,
        "source_artifacts": source_artifacts,
        "summary": _bundle_summary(sources, source_artifacts),
        "controls": _controls(sources, source_artifacts),
        "limitations": [
            "This bundle is self-contained for offline review of shadow replay, temporal holdout, traffic export, and traffic completeness evidence.",
            "It embeds parsed source objects and raw source bytes so reviewers can replay contract, replay, temporal holdout, traffic export, provider export, and completeness bindings without original file paths.",
            "Optional re-execution reports, soak-demotion receipts, and shadow authority dossiers are replayed when embedded with their required source artifacts.",
            "Production-review mode still depends on fresh provider-owned exports and authority evidence; this bundle proves what the supplied retained sources can prove.",
        ],
    }
    bundle_id = content_hash(body)
    return {
        **body,
        "bundle_id": bundle_id,
        "signatures": [sign_value({"bundle_id": bundle_id, "shadow_replay_review_bundle": body}, key)],
    }


def verify_shadow_replay_review_bundle(bundle: dict[str, Any], *, key: str | None = None) -> ShadowReplayReviewBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if bundle.get("schema") != SHADOW_REPLAY_REVIEW_BUNDLE_SCHEMA:
        errors.append(f"unsupported shadow replay review bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    if bundle.get("bundle_id") != content_hash(body):
        errors.append("bundle_id does not match canonical shadow replay review bundle body")
    signatures = bundle.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        errors.append("shadow replay review bundle must include at least one signature")
    else:
        signed_value = {"bundle_id": bundle.get("bundle_id"), "shadow_replay_review_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("shadow replay review bundle signature verification failed")

    mode = bundle.get("mode")
    if mode not in SHADOW_REPLAY_REVIEW_BUNDLE_MODES:
        errors.append("shadow replay review bundle mode is unsupported")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"shadow replay review bundle generated_at invalid: {exc}")
    if not isinstance(bundle.get("reviewer_ref"), str) or not bundle.get("reviewer_ref", "").strip():
        errors.append("shadow replay review bundle reviewer_ref is required")

    sources = bundle.get("sources")
    if not isinstance(sources, dict):
        errors.append("shadow replay review bundle sources must be an object")
        sources = {}
    source_values = _required_source_objects(sources, errors)
    optional_values = _optional_source_objects(sources, errors)
    source_values.update(optional_values)

    artifacts = bundle.get("source_artifacts")
    if source_values:
        _verify_source_artifacts(artifacts, source_values, errors)
        artifact_bytes = _artifact_bytes_by_name(artifacts, errors)
        replay_warnings = _verify_embedded_replay(source_values, artifact_bytes, errors, key=key)
        warnings.extend(replay_warnings)
        if REQUIRED_SOURCES <= set(source_values):
            expected_source = _source_summary(
                source_values["contract"],
                source_values["replay"],
                source_values["temporal_holdout"],
                source_values["traffic_export"],
                source_values["traffic_completeness"],
                source_values["provider_export"],
                source_values.get("shadow_authority"),
            )
            if bundle.get("source") != expected_source:
                errors.append("shadow replay review bundle source summary does not match embedded sources")
            source_artifacts = artifacts if isinstance(artifacts, list) else []
            if bundle.get("summary") != _bundle_summary(source_values, source_artifacts):
                errors.append("shadow replay review bundle summary does not match embedded sources")
            if bundle.get("controls") != _controls(source_values, source_artifacts):
                errors.append("shadow replay review bundle controls do not match embedded sources")
    if mode == "production-review" and "shadow_authority" not in source_values:
        errors.append("production-review mode requires an embedded shadow authority dossier")
    return ShadowReplayReviewBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def render_shadow_replay_review_bundle_markdown(bundle: dict[str, Any]) -> str:
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
        "| {name} | {kind} | {size} | `{sha}` | `{content_hash}` |".format(
            name=_markdown_cell(artifact.get("name", "")),
            kind=_markdown_cell(artifact.get("artifact_type", "")),
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
    return f"""# TrustAI Shadow Replay Review Bundle

Bundle ID: `{bundle.get('bundle_id', '')}`

Bundle ref: `{bundle.get('bundle_ref', '')}`

Mode: `{bundle.get('mode', '')}`

Environment: `{bundle.get('environment', '')}`

Generated at: `{bundle.get('generated_at', '')}`

Reviewer: `{bundle.get('reviewer_ref', '')}`

## Source

- Contract ID: `{source.get('contract_id', '')}`
- Contract hash: `{source.get('contract_hash', '')}`
- Replay run: `{source.get('run_id', '')}`
- Dataset: `{source.get('dataset_id', '')}`
- Temporal holdout manifest: `{source.get('temporal_holdout_manifest_id', '')}`
- Traffic export: `{source.get('traffic_export_id', '')}`
- Traffic completeness: `{source.get('traffic_completeness_id', '')}`
- Provider export hash: `{source.get('provider_export_hash', '')}`
- Shadow authority dossier: `{source.get('shadow_authority_dossier_id', '')}`
- Passed: `{source.get('passed', '')}`

## Embedded Source Summary

- Source artifacts: {summary.get('source_artifact_count', 0)}
- Required sources present: {summary.get('required_sources_present', False)}
- Replay source bytes embedded: {summary.get('replay_source_bytes_embedded', False)}
- Provider export bytes embedded: {summary.get('provider_export_bytes_embedded', False)}
- Re-execution report embedded: {summary.get('reexecution_report_embedded', False)}
- Soak demotion replay embedded: {summary.get('soak_demotion_replay_embedded', False)}
- Shadow authority embedded: {summary.get('shadow_authority_embedded', False)}
- Source artifact SHA-256 root: `{summary.get('source_artifact_sha256_root', '')}`
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


def write_shadow_replay_review_bundle_markdown(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_shadow_replay_review_bundle_markdown(bundle), encoding="utf-8")


def extract_shadow_replay_review_bundle_sources(
    bundle: dict[str, Any],
    out_dir: str | Path,
    *,
    key: str | None = None,
    overwrite: bool = False,
) -> list[dict[str, Any]]:
    result = verify_shadow_replay_review_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid shadow replay review bundle: " + "; ".join(result.errors))
    source_artifacts = bundle.get("source_artifacts", [])
    if not isinstance(source_artifacts, list):
        raise ValueError("shadow replay review bundle source_artifacts must be a list")
    output_root = Path(out_dir)
    extracted: list[dict[str, Any]] = []
    for artifact in source_artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("shadow replay review bundle source artifact must be an object")
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("shadow replay review bundle source artifact name is required")
        data = _decode_artifact_bytes(artifact, [])
        target = output_root / _artifact_extract_filename(name, str(artifact.get("media_type") or "application/json"))
        if target.exists():
            if target.is_dir():
                raise ValueError(f"shadow replay review bundle output path is a directory: {target}")
            if not overwrite:
                raise ValueError(f"shadow replay review bundle output already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append(
            {
                "name": name,
                "artifact_type": artifact.get("artifact_type"),
                "path": artifact.get("path"),
                "sha256": "sha256:" + sha256_hex(data),
                "bytes": len(data),
                "artifact_id": artifact.get("artifact_id"),
                "extracted_to": str(target),
            }
        )
    return extracted


def append_shadow_replay_review_bundle(
    chain: EvidenceChain,
    bundle: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_shadow_replay_review_bundle(bundle, key=key)
    if not result.ok:
        raise ValueError("invalid shadow replay review bundle: " + "; ".join(result.errors))
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
    return chain.append(SHADOW_REPLAY_REVIEW_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def _validate_required_sources(
    contract: dict[str, Any],
    replay: dict[str, Any],
    temporal_holdout: dict[str, Any],
    traffic_export: dict[str, Any],
    traffic_completeness: dict[str, Any],
    provider_export: dict[str, Any],
) -> None:
    for name, value in (
        ("contract", contract),
        ("replay", replay),
        ("temporal_holdout", temporal_holdout),
        ("traffic_export", traffic_export),
        ("traffic_completeness", traffic_completeness),
        ("provider_export", provider_export),
    ):
        if not isinstance(value, dict):
            raise ValueError(f"shadow replay review bundle {name} must be an object")


def _validate_optional_groups(
    *,
    reexecution_report: dict[str, Any] | None,
    soak_entry: dict[str, Any] | None,
    demotion_entry: dict[str, Any] | None,
    soak_demotion: dict[str, Any] | None,
    shadow_authority: dict[str, Any] | None,
) -> None:
    if reexecution_report is not None and not isinstance(reexecution_report, dict):
        raise ValueError("shadow replay review bundle reexecution_report must be an object")
    soak_values = [soak_entry, demotion_entry, soak_demotion]
    if any(value is not None for value in soak_values) and not all(isinstance(value, dict) for value in soak_values):
        raise ValueError("soak_entry, demotion_entry, and soak_demotion are required together")
    if shadow_authority is not None and not isinstance(shadow_authority, dict):
        raise ValueError("shadow replay review bundle shadow_authority must be an object")


def _replay_sources(
    *,
    contract: dict[str, Any],
    replay: dict[str, Any],
    temporal_holdout: dict[str, Any],
    traffic_export: dict[str, Any],
    traffic_completeness: dict[str, Any],
    provider_export: dict[str, Any],
    replay_source_path: str | Path | None,
    provider_export_path: str | Path | None,
    replay_source_bytes: bytes | None = None,
    provider_export_bytes: bytes | None = None,
    reexecution_report: dict[str, Any] | None = None,
    soak_entry: dict[str, Any] | None = None,
    demotion_entry: dict[str, Any] | None = None,
    soak_demotion: dict[str, Any] | None = None,
    shadow_authority: dict[str, Any] | None = None,
    key: str | None = None,
) -> list[str]:
    warnings: list[str] = []
    contract_errors = validate_contract(contract)
    if contract_errors:
        raise ValueError("invalid verification contract source: " + "; ".join(contract_errors))
    temporal_result = verify_temporal_holdout_manifest(
        temporal_holdout,
        contract=contract,
        replay=replay,
        replay_source_path=replay_source_path,
        replay_source_bytes=replay_source_bytes,
        key=key,
    )
    if not temporal_result.ok:
        raise ValueError("invalid temporal holdout source: " + "; ".join(temporal_result.errors))
    warnings.extend(temporal_result.warnings)
    traffic_result = verify_traffic_holdout_export(
        traffic_export,
        contract=contract,
        replay=replay,
        replay_source_path=replay_source_path,
        replay_source_bytes=replay_source_bytes,
        key=key,
    )
    if not traffic_result.ok:
        raise ValueError("invalid traffic holdout export source: " + "; ".join(traffic_result.errors))
    warnings.extend(traffic_result.warnings)
    completeness_result = verify_traffic_completeness_receipt(
        traffic_completeness,
        traffic_export=traffic_export,
        provider_export=provider_export,
        provider_export_path=provider_export_path,
        provider_export_bytes=provider_export_bytes,
        key=key,
    )
    if not completeness_result.ok:
        raise ValueError("invalid traffic completeness source: " + "; ".join(completeness_result.errors))
    warnings.extend(completeness_result.warnings)
    if reexecution_report is not None:
        reexecution_result = verify_reexecution_report(reexecution_report)
        if not reexecution_result.ok:
            raise ValueError("invalid re-execution report source: " + "; ".join(reexecution_result.errors))
        warnings.extend(reexecution_result.warnings)
    if soak_demotion is not None:
        soak_result = verify_soak_demotion_receipt(
            soak_demotion,
            contract=contract,
            soak_entry=soak_entry,
            demotion_entry=demotion_entry,
            key=key,
        )
        if not soak_result.ok:
            raise ValueError("invalid soak demotion source: " + "; ".join(soak_result.errors))
        warnings.extend(soak_result.warnings)
    if shadow_authority is not None:
        authority_result = verify_shadow_authority_dossier(
            shadow_authority,
            contract=contract,
            replay=replay,
            temporal_holdout=temporal_holdout,
            traffic_export=traffic_export,
            traffic_completeness=traffic_completeness,
            provider_export=provider_export,
            provider_export_path=provider_export_path,
            key=key,
        )
        if not authority_result.ok:
            raise ValueError("invalid shadow authority source: " + "; ".join(authority_result.errors))
        warnings.extend(authority_result.warnings)
    return warnings


def _source_objects(**objects: Any) -> dict[str, Any]:
    return {name: _clone(value) for name, value in objects.items() if value is not None}


def _required_source_objects(sources: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    supported = {name for name, _ in SOURCE_TYPES}
    for name in sources:
        if name not in supported:
            errors.append(f"shadow replay review bundle sources.{name} is unsupported")
    for name in sorted(REQUIRED_SOURCES):
        value = sources.get(name)
        if not isinstance(value, dict):
            errors.append(f"shadow replay review bundle sources.{name} is required")
        else:
            values[name] = value
    return values if REQUIRED_SOURCES <= set(values) else {}


def _optional_source_objects(sources: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for group in OPTIONAL_SOURCE_GROUPS:
        present = {name for name in group if name in sources}
        if present and present != group:
            errors.append("shadow replay review bundle optional source group incomplete: " + ", ".join(sorted(group)))
            continue
        for name in sorted(group):
            if name not in sources:
                continue
            value = sources.get(name)
            if not isinstance(value, dict):
                errors.append(f"shadow replay review bundle sources.{name} must be an object")
            else:
                values[name] = value
    return values


def _build_source_artifacts(artifact_paths: dict[str, str | Path], sources: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    artifact_types = dict(SOURCE_TYPES)
    for name, source in sorted(sources.items()):
        path = artifact_paths.get(name)
        if path is None:
            raise ValueError(f"shadow replay review bundle artifact path is required: {name}")
        data = Path(path).read_bytes()
        parsed = _parse_structured_artifact(data, name)
        if content_hash(parsed) != content_hash(source):
            raise ValueError(f"shadow replay review bundle artifact content hash mismatch: {name}")
        artifacts.append(
            _artifact_record(
                name,
                artifact_types[name],
                path,
                data,
                content_hash(parsed),
                "application/yaml" if name == "contract" else "application/json",
            )
        )
    return artifacts


def _verify_source_artifacts(value: Any, source_objects: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append("shadow replay review bundle source_artifacts must be a list")
        return
    artifact_types = dict(SOURCE_TYPES)
    actual_names: set[str] = set()
    expected_names = set(source_objects)
    for artifact in value:
        if not isinstance(artifact, dict):
            errors.append("shadow replay review bundle source artifact must be an object")
            continue
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            errors.append("shadow replay review bundle source artifact name is required")
            continue
        actual_names.add(name)
        if name not in artifact_types:
            errors.append(f"shadow replay review bundle source artifact unsupported: {name}")
            continue
        if artifact.get("artifact_type") != artifact_types[name]:
            errors.append(f"shadow replay review bundle source artifact type mismatch: {name}")
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"shadow replay review bundle source artifact id mismatch: {name}")
        data = _decode_artifact_bytes(artifact, errors)
        if not data:
            continue
        actual_sha = "sha256:" + sha256_hex(data)
        if artifact.get("sha256") != actual_sha:
            errors.append(f"shadow replay review bundle source artifact sha256 mismatch: {name}")
        if artifact.get("size_bytes") != len(data):
            errors.append(f"shadow replay review bundle source artifact size mismatch: {name}")
        try:
            parsed = _parse_structured_artifact(data, name)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        parsed_hash = content_hash(parsed)
        if artifact.get("content_hash") != parsed_hash:
            errors.append(f"shadow replay review bundle source artifact content hash mismatch: {name}")
        if name in source_objects and parsed_hash != content_hash(source_objects[name]):
            errors.append(f"shadow replay review bundle source artifact does not match embedded source: {name}")
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing:
        errors.append("shadow replay review bundle source artifacts missing: " + ", ".join(missing))
    if extra:
        errors.append("shadow replay review bundle source artifacts unsupported for embedded sources: " + ", ".join(extra))


def _verify_embedded_replay(source_values: dict[str, Any], artifact_bytes: dict[str, bytes], errors: list[str], *, key: str | None) -> list[str]:
    required_bytes = {"replay", "provider_export"}
    missing_bytes = sorted(name for name in required_bytes if name not in artifact_bytes)
    if missing_bytes:
        errors.append("shadow replay review bundle embedded replay source bytes missing: " + ", ".join(missing_bytes))
        return []
    try:
        return _replay_sources(
            contract=source_values["contract"],
            replay=source_values["replay"],
            temporal_holdout=source_values["temporal_holdout"],
            traffic_export=source_values["traffic_export"],
            traffic_completeness=source_values["traffic_completeness"],
            provider_export=source_values["provider_export"],
            replay_source_path=None,
            provider_export_path=None,
            replay_source_bytes=artifact_bytes["replay"],
            provider_export_bytes=artifact_bytes["provider_export"],
            reexecution_report=source_values.get("reexecution_report"),
            soak_entry=source_values.get("soak_entry"),
            demotion_entry=source_values.get("demotion_entry"),
            soak_demotion=source_values.get("soak_demotion"),
            shadow_authority=source_values.get("shadow_authority"),
            key=key,
        )
    except ValueError as exc:
        errors.append("shadow replay review bundle source replay failed: " + str(exc))
        return []


def _source_summary(
    contract: dict[str, Any],
    replay: dict[str, Any],
    temporal_holdout: dict[str, Any],
    traffic_export: dict[str, Any],
    traffic_completeness: dict[str, Any],
    provider_export: dict[str, Any],
    shadow_authority: dict[str, Any] | None,
) -> dict[str, Any]:
    body = {
        "contract_id": contract.get("id"),
        "contract_hash": contract_hash(contract),
        "agent": contract.get("agent"),
        "freeze_at": contract.get("freeze", {}).get("frozen_at") if isinstance(contract.get("freeze"), dict) else None,
        "min_timestamp": contract.get("holdout", {}).get("min_timestamp") if isinstance(contract.get("holdout"), dict) else None,
        "run_id": replay.get("run_id"),
        "dataset_id": replay.get("dataset_id") or "shadow-replay",
        "candidate_version": replay.get("candidate_version") or contract.get("agent", {}).get("version"),
        "replay_hash": content_hash(replay),
        "temporal_holdout_manifest_id": temporal_holdout.get("manifest_id"),
        "temporal_holdout_hash": content_hash(temporal_holdout),
        "temporal_records_root": temporal_holdout.get("records_root"),
        "traffic_export_id": traffic_export.get("export_id"),
        "traffic_export_hash": content_hash(traffic_export),
        "traffic_records_root": traffic_export.get("records_root"),
        "traffic_completeness_id": traffic_completeness.get("completeness_id"),
        "traffic_completeness_hash": content_hash(traffic_completeness),
        "traffic_completeness_mode": traffic_completeness.get("mode"),
        "traffic_completeness_production_claim": traffic_completeness.get("production_claim"),
        "provider_export_hash": content_hash(provider_export),
        "provider_export_ref": provider_export.get("export_ref"),
        "provider_export_record_count": len(provider_export.get("stream_records", [])) if isinstance(provider_export.get("stream_records"), list) else None,
        "shadow_authority_dossier_id": shadow_authority.get("dossier_id") if isinstance(shadow_authority, dict) else None,
        "shadow_authority_hash": content_hash(shadow_authority) if isinstance(shadow_authority, dict) else None,
        "passed": bool(temporal_holdout.get("passed")) and bool(traffic_export.get("passed")) and bool(traffic_completeness.get("passed")),
    }
    return {key: value for key, value in body.items() if value is not None}


def _bundle_summary(sources: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    artifact_names = {artifact.get("name") for artifact in artifacts if isinstance(artifact, dict)}
    return {
        "source_artifact_count": len(artifacts),
        "source_artifact_sha256_root": content_hash([artifact.get("sha256") for artifact in artifacts]),
        "source_artifact_content_root": content_hash([artifact.get("content_hash") for artifact in artifacts]),
        "source_object_hashes": {name: content_hash(value) for name, value in sorted(sources.items())},
        "required_sources_present": REQUIRED_SOURCES <= set(sources),
        "replay_source_bytes_embedded": "replay" in artifact_names,
        "provider_export_bytes_embedded": "provider_export" in artifact_names,
        "temporal_holdout_passed": bool(sources.get("temporal_holdout", {}).get("passed")) if isinstance(sources.get("temporal_holdout"), dict) else False,
        "traffic_export_passed": bool(sources.get("traffic_export", {}).get("passed")) if isinstance(sources.get("traffic_export"), dict) else False,
        "traffic_completeness_passed": bool(sources.get("traffic_completeness", {}).get("passed")) if isinstance(sources.get("traffic_completeness"), dict) else False,
        "traffic_completeness_production_claim": sources.get("traffic_completeness", {}).get("production_claim") if isinstance(sources.get("traffic_completeness"), dict) else None,
        "reexecution_report_embedded": "reexecution_report" in sources,
        "soak_demotion_replay_embedded": {"soak_entry", "demotion_entry", "soak_demotion"} <= set(sources),
        "shadow_authority_embedded": "shadow_authority" in sources,
    }


def _controls(sources: dict[str, Any], artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    summary = _bundle_summary(sources, artifacts)
    return [
        {
            "name": "shadow-review-offline-replay",
            "status": "passed" if summary["required_sources_present"] and summary["replay_source_bytes_embedded"] and summary["provider_export_bytes_embedded"] else "failed",
            "detail": "Embedded contract, replay, holdout, traffic export, provider export, and completeness sources replay through TrustAI verifiers.",
        },
        {
            "name": "temporal-holdout-boundary",
            "status": "passed" if summary["temporal_holdout_passed"] else "failed",
            "detail": "Temporal holdout manifest binds replay record timestamps after the agent freeze and holdout minimum.",
        },
        {
            "name": "traffic-export-record-chain",
            "status": "passed" if summary["traffic_export_passed"] else "failed",
            "detail": "Traffic holdout export binds the replay records, previous-record hash chain, and retained replay source bytes.",
        },
        {
            "name": "traffic-completeness-provider-replay",
            "status": "passed" if summary["traffic_completeness_passed"] and summary["provider_export_bytes_embedded"] else "failed",
            "detail": "Traffic completeness receipt replays the retained provider export bytes and provider stream/audit rows.",
        },
        {
            "name": "production-completeness-claim",
            "status": "passed" if _production_claim_passed(summary.get("traffic_completeness_production_claim")) else "failed",
            "detail": "Traffic completeness source declares a canonical production claim for the supplied provider export.",
        },
        {
            "name": "distributional-reexecution",
            "status": "passed" if summary["reexecution_report_embedded"] else "not-applicable",
            "detail": "Optional re-execution report is embedded and replayed when supplied.",
        },
        {
            "name": "soak-demotion-replay",
            "status": "passed" if summary["soak_demotion_replay_embedded"] else "not-applicable",
            "detail": "Optional failed-soak to demotion receipt is embedded with chain entries and replayed when supplied.",
        },
        {
            "name": "shadow-authority-dossier",
            "status": "passed" if summary["shadow_authority_embedded"] else "not-applicable",
            "detail": "Optional production authority dossier is embedded and replayed against retained shadow and provider sources when supplied.",
        },
    ]


def _production_claim_passed(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("passed") or value.get("claimed"))
    return bool(value)


def _source_environment(contract: dict[str, Any], traffic_export: dict[str, Any]) -> str | None:
    if isinstance(contract.get("environment"), str):
        return contract["environment"]
    return traffic_export.get("source_ref")


def _default_bundle_ref(replay: dict[str, Any], traffic_export: dict[str, Any]) -> str:
    run_id = str(replay.get("run_id") or "shadow-replay")
    export_id = str(traffic_export.get("export_id") or "")
    return f"shadow-replay-review:{run_id}:{export_id[:16]}"


def _artifact_record(name: str, artifact_type: str, path: str | Path, data: bytes, content_hash_value: str, media_type: str) -> dict[str, Any]:
    body = {
        "name": name,
        "artifact_type": artifact_type,
        "path": str(path).replace("\\", "/"),
        "media_type": media_type,
        "size_bytes": len(data),
        "sha256": "sha256:" + sha256_hex(data),
        "content_hash": content_hash_value,
        "content_b64": base64.b64encode(data).decode("ascii"),
    }
    return {**body, "artifact_id": content_hash(body)}


def _artifact_bytes_by_name(value: Any, errors: list[str]) -> dict[str, bytes]:
    if not isinstance(value, list):
        return {}
    artifacts: dict[str, bytes] = {}
    for artifact in value:
        if not isinstance(artifact, dict):
            continue
        name = artifact.get("name")
        if not isinstance(name, str):
            continue
        artifacts[name] = _decode_artifact_bytes(artifact, errors)
    return artifacts


def _decode_artifact_bytes(artifact: dict[str, Any], errors: list[str]) -> bytes:
    try:
        return base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        errors.append(f"shadow replay review bundle source artifact content_b64 invalid: {artifact.get('name')}: {exc}")
        return b""


def _parse_structured_artifact(data: bytes, name: str) -> Any:
    text = data.decode("utf-8-sig")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ValueError(f"shadow replay review bundle artifact is not JSON and PyYAML is unavailable: {name}") from exc
        value = yaml.safe_load(text)
        if not isinstance(value, dict):
            raise ValueError(f"shadow replay review bundle artifact must contain an object: {name}")
        return value


def _artifact_extract_filename(name: str, media_type: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in name).strip("-")
    suffix = ".yaml" if media_type == "application/yaml" else ".json"
    return f"{safe or 'source'}{suffix}"


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if isinstance(controls, list):
        for control in controls:
            if not isinstance(control, dict):
                continue
            status = str(control.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"shadow replay review bundle {field} is required")
    return value.strip()


def _markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))
