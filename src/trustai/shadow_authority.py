from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .contracts import contract_hash
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .shadow import (
    TEMPORAL_HOLDOUT_SCHEMA,
    TRAFFIC_COMPLETENESS_SCHEMA,
    TRAFFIC_HOLDOUT_EXPORT_SCHEMA,
    verify_temporal_holdout_manifest,
    verify_traffic_completeness_receipt,
    verify_traffic_holdout_export,
)

SHADOW_AUTHORITY_SCHEMA = "trustai.shadow-temporal-holdout-production-authority-dossier/0.1"
SHADOW_AUTHORITY_ENTRY_TYPE = "shadow.temporal_holdout_authority_recorded"
SHADOW_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SHADOW_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA = "trustai.shadow-temporal-holdout-authority-evidence-bundle/0.1"
SHADOW_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE = "shadow.temporal_holdout_authority_evidence_bundled"
SHADOW_AUTHORITY_EVIDENCE_BUNDLE_MODES = {"authority-export", "offline-review", "production-export"}

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {
        "id": "pre-registered-temporal-boundary",
        "title": "Registered contract freeze and holdout boundary were fixed before replay traffic",
        "authority_kinds": ["standards-body", "provider-api"],
    },
    {
        "id": "production-traffic-export-window",
        "title": "Production traffic export window, query, cursor, and replay record roots",
        "authority_kinds": ["provider-api"],
    },
    {
        "id": "collector-stream-completeness",
        "title": "Provider-owned stream/storage completeness for the exported holdout records",
        "authority_kinds": ["provider-api"],
    },
    {
        "id": "candidate-version-freeze",
        "title": "Candidate agent version identity and freeze provenance for replayed traffic",
        "authority_kinds": ["identity-provider", "provider-api"],
    },
    {
        "id": "replay-runner-identity",
        "title": "Replay runner service identity, RBAC, and least-privilege authorization",
        "authority_kinds": ["identity-provider", "provider-api"],
    },
    {
        "id": "kms-signed-holdout-receipts",
        "title": "KMS/HSM-backed signing custody for holdout, traffic, and completeness receipts",
        "authority_kinds": ["kms-hsm"],
    },
    {
        "id": "immutable-traffic-audit-log",
        "title": "Immutable replay, collector, and traffic export audit logs",
        "authority_kinds": ["provider-api", "kms-hsm"],
    },
    {
        "id": "deterministic-replay-runner",
        "title": "Replay runner provenance, deterministic inputs, and nondeterminism limits",
        "authority_kinds": ["provider-api", "standards-body"],
    },
    {
        "id": "holdout-leakage-review",
        "title": "Independent review that holdout traffic postdates freeze and was not leaked into tuning",
        "authority_kinds": ["standards-body", "provider-api"],
    },
    {
        "id": "freshness-and-monitoring-window",
        "title": "Fresh provider evidence windows for traffic, completeness, and drift monitoring",
        "authority_kinds": ["provider-api", "kms-hsm"],
    },
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class ShadowAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


@dataclass
class ShadowAuthorityEvidenceBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_shadow_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("shadow authority dossier must contain an object")
    return value


def write_shadow_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def load_shadow_authority_evidence_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("shadow authority evidence bundle must contain an object")
    return value


def write_shadow_authority_evidence_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def parse_shadow_authority_evidence_arg(value: str) -> dict[str, Any]:
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


def build_shadow_authority_evidence_bundle(
    *,
    authority_evidence: list[dict[str, Any]],
    mode: str = "authority-export",
    environment: str = "local",
    bundle_ref: str,
    issuer_ref: str,
    subject_ref: str,
    authority_ref: str,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in SHADOW_AUTHORITY_EVIDENCE_BUNDLE_MODES:
        raise ValueError(f"mode must be one of {sorted(SHADOW_AUTHORITY_EVIDENCE_BUNDLE_MODES)}")
    for value, field in ((environment, "environment"), (bundle_ref, "bundle_ref"), (issuer_ref, "issuer_ref"), (subject_ref, "subject_ref"), (authority_ref, "authority_ref")):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    evidence_items = [_build_authority_evidence_bundle_item(item) for item in authority_evidence]
    summary = _evidence_bundle_summary(evidence_items)
    body = {
        "schema": SHADOW_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "generated_at": timestamp,
        "bundle_ref": bundle_ref,
        "issuer_ref": issuer_ref,
        "subject_ref": subject_ref,
        "authority_ref": authority_ref,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _bundle_controls(mode, evidence_items, summary),
        "limitations": [
            "This bundle records shadow replay and temporal holdout production-authority evidence rows before binding them to a concrete traffic export.",
            "A shadow authority dossier must still replay the temporal holdout manifest, production traffic export, and traffic completeness receipt sources.",
            "Production claims require production-export mode, complete checklist coverage, live source URIs, and fresh evidence windows.",
        ],
    }
    secret_errors: list[str] = []
    _check_no_secret_values(body, secret_errors)
    if secret_errors:
        raise ValueError("shadow authority evidence bundle contains secret-like values: " + "; ".join(secret_errors))
    bundle_id = content_hash(body)
    return {
        **body,
        "bundle_id": bundle_id,
        "signatures": [sign_value({"bundle_id": bundle_id, "shadow_authority_evidence_bundle": body}, key)],
    }


def verify_shadow_authority_evidence_bundle(
    bundle: dict[str, Any],
    *,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> ShadowAuthorityEvidenceBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(bundle, now, errors)

    if bundle.get("schema") != SHADOW_AUTHORITY_EVIDENCE_BUNDLE_SCHEMA:
        errors.append(f"unsupported shadow authority evidence bundle schema: {bundle.get('schema')}")
    body = without_keys(bundle, "bundle_id", "signatures")
    if bundle.get("bundle_id") != content_hash(body):
        errors.append("bundle_id does not match canonical shadow authority evidence bundle body")
    signatures = bundle.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("shadow authority evidence bundle must include at least one signature")
    else:
        signed_value = {"bundle_id": bundle.get("bundle_id"), "shadow_authority_evidence_bundle": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("shadow authority evidence bundle signature verification failed")

    mode = bundle.get("mode")
    if mode not in SHADOW_AUTHORITY_EVIDENCE_BUNDLE_MODES:
        errors.append("shadow authority evidence bundle mode is unsupported")
    elif mode != "production-export":
        warnings.append(f"shadow authority evidence bundle mode is {mode}; production evidence export is not claimed")
    try:
        parse_rfc3339(str(bundle.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"shadow authority evidence bundle generated_at invalid: {exc}")
    for field in ("environment", "bundle_ref", "issuer_ref", "subject_ref", "authority_ref"):
        if not bundle.get(field):
            errors.append(f"shadow authority evidence bundle {field} is required")
    if bundle.get("required_production_authority") != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("shadow authority evidence bundle required_production_authority does not match the required checklist")

    evidence = bundle.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("shadow authority evidence bundle authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    evidence_items: list[dict[str, Any]] = []
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("shadow authority evidence bundle item must be an object")
            freshness_counts["missing"] += 1
            continue
        status = _verify_authority_evidence_bundle_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh)
        freshness_counts[status] += 1
        evidence_items.append(item)

    expected_summary = _evidence_bundle_summary(evidence_items)
    if bundle.get("summary") != expected_summary:
        errors.append("shadow authority evidence bundle summary does not match authority evidence")
    if not isinstance(bundle.get("controls"), list) or not bundle.get("controls"):
        errors.append("shadow authority evidence bundle controls are required")
    elif bundle.get("controls") != _bundle_controls(str(mode), evidence_items, expected_summary):
        errors.append("shadow authority evidence bundle controls do not match bundle body")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("shadow authority evidence bundle missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("shadow authority evidence bundle is incomplete")
    if mode == "production-export" and missing:
        errors.append("production-export mode requires every shadow authority requirement to be covered")
    if mode == "production-export" and _source_uri_counts(evidence_items)["placeholder"]:
        errors.append("production-export mode requires live source_uri values for every shadow authority evidence item")
    if mode == "production-export" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-export mode requires every shadow authority evidence item to be fresh")
    _check_no_secret_values(bundle, errors)

    return ShadowAuthorityEvidenceBundleVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def shadow_authority_evidence_from_bundle(
    bundle: dict[str, Any],
    *,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> list[dict[str, Any]]:
    result = verify_shadow_authority_evidence_bundle(
        bundle,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid shadow authority evidence bundle: " + "; ".join(result.errors))
    evidence: list[dict[str, Any]] = []
    for item in bundle.get("authority_evidence", []):
        if isinstance(item, dict):
            evidence.append(without_keys(item, "evidence_id", "source_context"))
    return evidence


def append_shadow_authority_evidence_bundle(
    chain: EvidenceChain,
    bundle: dict[str, Any],
    *,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_shadow_authority_evidence_bundle(bundle, key=key, require_complete=require_complete, require_fresh=require_fresh, now=now)
    if not result.ok:
        raise ValueError("invalid shadow authority evidence bundle: " + "; ".join(result.errors))
    payload = {
        "bundle_id": bundle["bundle_id"],
        "bundle_hash": content_hash(bundle),
        "mode": bundle.get("mode"),
        "environment": bundle.get("environment"),
        "generated_at": bundle.get("generated_at"),
        "bundle_ref": bundle.get("bundle_ref"),
        "authority_ref": bundle.get("authority_ref"),
        "summary": bundle.get("summary"),
        "control_summary": _status_summary(bundle.get("controls", [])),
    }
    return chain.append(SHADOW_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE, payload, key=key, timestamp=bundle.get("generated_at"))


def build_shadow_authority_dossier(
    contract: dict[str, Any],
    replay: dict[str, Any],
    temporal_holdout: dict[str, Any],
    traffic_export: dict[str, Any],
    traffic_completeness: dict[str, Any],
    *,
    provider_export: dict[str, Any] | None = None,
    provider_export_path: str | Path | None = None,
    mode: str = "provider-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in SHADOW_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(SHADOW_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    binding = _source_binding(
        contract,
        replay,
        temporal_holdout,
        traffic_export,
        traffic_completeness,
        provider_export=provider_export,
        provider_export_path=provider_export_path,
        key=key,
    )
    source_context = _authority_source_context(binding)
    evidence_items = [_build_authority_evidence_item(item, source_context) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body = {
        "schema": SHADOW_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or "local",
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
            "This dossier binds shadow replay temporal holdout receipts to a production-authority evidence checklist.",
            "It proves the supplied contract, replay, temporal manifest, traffic export, and completeness receipt are mutually bound when source artifacts are supplied.",
            "It does not claim production shadow replay authority unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {
        **body,
        "dossier_id": dossier_id,
        "signatures": [sign_value({"dossier_id": dossier_id, "shadow_authority": body}, key)],
    }


def verify_shadow_authority_dossier(
    dossier: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    replay: dict[str, Any] | None = None,
    temporal_holdout: dict[str, Any] | None = None,
    traffic_export: dict[str, Any] | None = None,
    traffic_completeness: dict[str, Any] | None = None,
    provider_export: dict[str, Any] | None = None,
    provider_export_path: str | Path | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> ShadowAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != SHADOW_AUTHORITY_SCHEMA:
        errors.append(f"unsupported shadow authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical shadow authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("shadow authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "shadow_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("shadow authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in SHADOW_AUTHORITY_MODES:
        errors.append("shadow authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"shadow authority mode is {mode}; live production shadow replay authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"shadow authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"shadow authority {field} is required")

    binding = dossier.get("source_binding")
    _verify_source_binding(
        binding,
        contract=contract,
        replay=replay,
        temporal_holdout=temporal_holdout,
        traffic_export=traffic_export,
        traffic_completeness=traffic_completeness,
        provider_export=provider_export,
        provider_export_path=provider_export_path,
        key=key,
        errors=errors,
        warnings=warnings,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("shadow authority authority_evidence must be a list")
        evidence = []
    source_context = _authority_source_context(binding if isinstance(binding, dict) else {})
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("shadow authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        status = _verify_authority_evidence_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh, source_context=source_context)
        freshness_counts[status] += 1

    evidence_dicts = [item for item in evidence if isinstance(item, dict)]
    expected_summary = _summary(evidence_dicts)
    if dossier.get("summary") != expected_summary:
        errors.append("shadow authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("shadow authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("shadow authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every shadow authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every shadow authority evidence item to be fresh")
    if mode == "production-dossier" and isinstance(binding, dict):
        if not binding.get("passed"):
            errors.append("production-dossier mode requires passing temporal holdout, traffic export, and completeness sources")
        completeness = binding.get("traffic_completeness", {})
        if not isinstance(completeness, dict) or completeness.get("mode") != "production-export":
            errors.append("production-dossier mode requires production-export traffic completeness")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("shadow authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), binding if isinstance(binding, dict) else {}, evidence_dicts, expected_summary):
        errors.append("shadow authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)

    return ShadowAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_shadow_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    contract: dict[str, Any],
    replay: dict[str, Any],
    temporal_holdout: dict[str, Any],
    traffic_export: dict[str, Any],
    traffic_completeness: dict[str, Any],
    provider_export: dict[str, Any] | None = None,
    provider_export_path: str | Path | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_shadow_authority_dossier(
        dossier,
        contract=contract,
        replay=replay,
        temporal_holdout=temporal_holdout,
        traffic_export=traffic_export,
        traffic_completeness=traffic_completeness,
        provider_export=provider_export,
        provider_export_path=provider_export_path,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid shadow authority dossier: " + "; ".join(result.errors))
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
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
                "source_context": item.get("source_context"),
            }
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(SHADOW_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _source_binding(
    contract: dict[str, Any],
    replay: dict[str, Any],
    temporal_holdout: dict[str, Any],
    traffic_export: dict[str, Any],
    traffic_completeness: dict[str, Any],
    *,
    provider_export: dict[str, Any] | None = None,
    provider_export_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    holdout_result = verify_temporal_holdout_manifest(temporal_holdout, contract=contract, replay=replay, key=key)
    if not holdout_result.ok:
        raise ValueError("invalid temporal holdout source: " + "; ".join(holdout_result.errors))
    export_result = verify_traffic_holdout_export(traffic_export, contract=contract, replay=replay, key=key)
    if not export_result.ok:
        raise ValueError("invalid traffic holdout export source: " + "; ".join(export_result.errors))
    completeness_result = verify_traffic_completeness_receipt(
        traffic_completeness,
        traffic_export=traffic_export,
        provider_export=provider_export,
        provider_export_path=provider_export_path,
        key=key,
    )
    if not completeness_result.ok:
        raise ValueError("invalid traffic completeness source: " + "; ".join(completeness_result.errors))
    passed = bool(temporal_holdout.get("passed")) and bool(traffic_export.get("passed")) and bool(traffic_completeness.get("passed"))
    return {
        "contract": {
            "id": contract.get("id"),
            "hash": contract_hash(contract),
            "freeze_at": contract.get("freeze", {}).get("frozen_at"),
            "min_timestamp": contract.get("holdout", {}).get("min_timestamp"),
        },
        "replay": {
            "run_id": replay.get("run_id"),
            "dataset_id": replay.get("dataset_id") or "shadow-replay",
            "candidate_version": replay.get("candidate_version") or contract.get("agent", {}).get("version"),
            "hash": content_hash(replay),
            "record_count": len(replay.get("records", [])) if isinstance(replay.get("records"), list) else None,
        },
        "temporal_holdout": {
            "schema": temporal_holdout.get("schema"),
            "manifest_id": temporal_holdout.get("manifest_id"),
            "manifest_hash": content_hash(temporal_holdout),
            "record_count": temporal_holdout.get("record_count"),
            "records_root": temporal_holdout.get("records_root"),
            "earliest_record_timestamp": temporal_holdout.get("earliest_record_timestamp"),
            "latest_record_timestamp": temporal_holdout.get("latest_record_timestamp"),
            "violation_count": len(temporal_holdout.get("violations", [])),
            "passed": temporal_holdout.get("passed"),
        },
        "traffic_export": {
            "schema": traffic_export.get("schema"),
            "export_id": traffic_export.get("export_id"),
            "export_hash": content_hash(traffic_export),
            "export_ref": traffic_export.get("export_ref"),
            "source_ref": traffic_export.get("source_ref"),
            "query_ref": traffic_export.get("query_ref"),
            "cursor_start": traffic_export.get("cursor_start"),
            "cursor_end": traffic_export.get("cursor_end"),
            "extraction_window": traffic_export.get("extraction_window"),
            "record_count": traffic_export.get("record_count"),
            "records_root": traffic_export.get("records_root"),
            "violation_count": len(traffic_export.get("violations", [])),
            "passed": traffic_export.get("passed"),
        },
        "traffic_completeness": {
            "schema": traffic_completeness.get("schema"),
            "completeness_id": traffic_completeness.get("completeness_id"),
            "completeness_hash": content_hash(traffic_completeness),
            "mode": traffic_completeness.get("mode"),
            "authority_ref": traffic_completeness.get("authority_ref"),
            "matched_record_count": traffic_completeness.get("source_completeness", {}).get("matched_record_count")
            if isinstance(traffic_completeness.get("source_completeness"), dict)
            else None,
            "missing_record_count": traffic_completeness.get("source_completeness", {}).get("missing_record_count")
            if isinstance(traffic_completeness.get("source_completeness"), dict)
            else None,
            "extra_provider_record_count": len(traffic_completeness.get("extra_provider_records", [])),
            "provider_export_artifact": traffic_completeness.get("provider_export_artifact"),
            "violation_count": len(traffic_completeness.get("violations", [])),
            "passed": traffic_completeness.get("passed"),
        },
        "source_replay": {
            "temporal_holdout_replayed": True,
            "traffic_export_replayed": True,
            "traffic_completeness_replayed": True,
            "provider_export_replayed": provider_export is not None,
        },
        "passed": passed,
    }


def _verify_source_binding(
    binding: Any,
    *,
    contract: dict[str, Any] | None,
    replay: dict[str, Any] | None,
    temporal_holdout: dict[str, Any] | None,
    traffic_export: dict[str, Any] | None,
    traffic_completeness: dict[str, Any] | None,
    provider_export: dict[str, Any] | None,
    provider_export_path: str | Path | None,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(binding, dict):
        errors.append("shadow authority source_binding is required")
        return
    for field in ("contract", "replay", "temporal_holdout", "traffic_export", "traffic_completeness", "source_replay", "passed"):
        if binding.get(field) in (None, "", []):
            errors.append(f"shadow authority source_binding.{field} is required")
    if binding.get("temporal_holdout", {}).get("schema") != TEMPORAL_HOLDOUT_SCHEMA:
        errors.append("shadow authority temporal holdout schema is unsupported")
    if binding.get("traffic_export", {}).get("schema") != TRAFFIC_HOLDOUT_EXPORT_SCHEMA:
        errors.append("shadow authority traffic export schema is unsupported")
    if binding.get("traffic_completeness", {}).get("schema") != TRAFFIC_COMPLETENESS_SCHEMA:
        errors.append("shadow authority traffic completeness schema is unsupported")
    if not all(value is not None for value in (contract, replay, temporal_holdout, traffic_export, traffic_completeness)):
        warnings.append("shadow authority sources not supplied; source binding hashes were not replayed")
        return
    try:
        expected = _source_binding(
            contract,
            replay,
            temporal_holdout,
            traffic_export,
            traffic_completeness,
            provider_export=provider_export,
            provider_export_path=provider_export_path,
            key=key,
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"shadow authority source replay failed: {exc}")
        return
    if binding != expected:
        errors.append("shadow authority source_binding does not match supplied sources")


def _build_authority_evidence_bundle_item(item: dict[str, Any]) -> dict[str, Any]:
    built = _normalize_authority_evidence(item, include_source_context=False)
    evidence_id = content_hash(built)
    return {**built, "evidence_id": evidence_id}


def _build_authority_evidence_item(item: dict[str, Any], source_context: dict[str, Any]) -> dict[str, Any]:
    built = _normalize_authority_evidence(item, include_source_context=True, source_context=source_context)
    evidence_id = content_hash(built)
    return {**built, "evidence_id": evidence_id}


def _normalize_authority_evidence(
    item: dict[str, Any],
    *,
    include_source_context: bool,
    source_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported shadow authority requirement: {requirement_id}")
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in requirement["authority_kinds"]:
        raise ValueError(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    evidence_hash = _normalize_sha256_ref(evidence_hash, "evidence_hash")
    built = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description,
    }
    for field in ("issuer", "subject", "source_uri", "issued_at", "expires_at"):
        if item.get(field) not in (None, ""):
            built[field] = str(item[field])
    if include_source_context:
        built["source_context"] = source_context or {}
    return built


def _verify_authority_evidence_bundle_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now: str | None,
    require_fresh: bool,
) -> str:
    try:
        normalized = _normalize_authority_evidence(item, include_source_context=False)
    except ValueError as exc:
        errors.append(f"invalid shadow authority evidence bundle item: {exc}")
        return "missing"
    if item.get("evidence_id") != content_hash(normalized):
        errors.append(f"shadow authority evidence bundle item {item.get('requirement_id')} evidence_id mismatch")
    _verify_common_authority_fields(item, errors, warnings)
    if _source_uri_is_placeholder(item.get("source_uri")):
        warnings.append(f"shadow authority evidence bundle item {item.get('requirement_id')} has placeholder source_uri")
    return _freshness_status(item, errors, require_fresh=require_fresh, now=now)


def _verify_authority_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now: str | None,
    require_fresh: bool,
    source_context: dict[str, Any],
) -> str:
    try:
        normalized = _normalize_authority_evidence(item, include_source_context=True, source_context=source_context)
    except ValueError as exc:
        errors.append(f"invalid shadow authority evidence item: {exc}")
        return "missing"
    if item.get("evidence_id") != content_hash(normalized):
        errors.append(f"shadow authority evidence item {item.get('requirement_id')} evidence_id mismatch")
    if item.get("source_context") != source_context:
        errors.append(f"shadow authority evidence item {item.get('requirement_id')} source_context mismatch")
    _verify_common_authority_fields(item, errors, warnings)
    return _freshness_status(item, errors, require_fresh=require_fresh, now=now)


def _verify_common_authority_fields(item: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unsupported shadow authority requirement: {requirement_id}")
        return
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif authority_kind not in requirement["authority_kinds"]:
        errors.append(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if item.get(field) in (None, ""):
            errors.append(f"shadow authority evidence item {requirement_id} missing {field}")
    if _source_uri_is_placeholder(item.get("source_uri")):
        warnings.append(f"shadow authority evidence item {requirement_id} has placeholder source_uri")


def _freshness_status(item: dict[str, Any], errors: list[str], *, require_fresh: bool, now: str | None) -> str:
    issued_at = item.get("issued_at")
    expires_at = item.get("expires_at")
    if not issued_at or not expires_at:
        if require_fresh:
            errors.append(f"shadow authority evidence item {item.get('requirement_id')} requires issued_at and expires_at")
        return "missing"
    try:
        issued = parse_rfc3339(str(issued_at))
        expires = parse_rfc3339(str(expires_at))
        current = parse_rfc3339(str(now)) if now else parse_rfc3339(utc_now())
    except ValueError as exc:
        errors.append(f"shadow authority evidence freshness invalid for {item.get('requirement_id')}: {exc}")
        return "missing"
    if expires <= issued:
        errors.append(f"shadow authority evidence item {item.get('requirement_id')} expires_at must be after issued_at")
        return "stale"
    if issued <= current < expires:
        return "fresh"
    if require_fresh:
        errors.append(f"shadow authority evidence item {item.get('requirement_id')} is not fresh at {current.isoformat()}")
    return "stale"


def _summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    covered: dict[str, set[str]] = {req_id: set() for req_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS}
    for item in evidence:
        req_id = item.get("requirement_id")
        kind = item.get("authority_kind")
        if req_id in covered and isinstance(kind, str):
            covered[req_id].add(kind)
    covered_ids = [req_id for req_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if covered[req_id]]
    missing = [req_id for req_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if not covered[req_id]]
    return {
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENTS),
        "covered_requirement_count": len(covered_ids),
        "missing_requirement_count": len(missing),
        "covered_requirement_ids": covered_ids,
        "missing_requirement_ids": missing,
        "authority_kind_counts": {kind: sum(1 for item in evidence if item.get("authority_kind") == kind) for kind in sorted(AUTHORITY_KINDS)},
        "evidence_count": len(evidence),
        "source_uri_counts": _source_uri_counts(evidence),
    }


def _evidence_bundle_summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    return _summary(evidence)


def _controls(mode: str, binding: dict[str, Any], evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    freshness = _freshness_counts(evidence)
    source_uri_counts = _source_uri_counts(evidence)
    complete = not summary.get("missing_requirement_ids")
    source_passed = bool(binding.get("passed"))
    production_completeness = isinstance(binding.get("traffic_completeness"), dict) and binding["traffic_completeness"].get("mode") == "production-export"
    return [
        {"name": "temporal-holdout-source-replayed", "status": "passed" if isinstance(binding.get("temporal_holdout"), dict) else "failed"},
        {"name": "traffic-export-source-replayed", "status": "passed" if isinstance(binding.get("traffic_export"), dict) else "failed"},
        {"name": "traffic-completeness-source-replayed", "status": "passed" if isinstance(binding.get("traffic_completeness"), dict) else "failed"},
        {"name": "source-receipts-passed", "status": "passed" if source_passed else "failed"},
        {"name": "production-completeness-mode", "status": "passed" if production_completeness else ("not-applicable" if mode != "production-dossier" else "failed")},
        {"name": "authority-checklist-covered", "status": "passed" if complete else "failed"},
        {"name": "authority-evidence-live-source-uris", "status": "passed" if source_uri_counts["placeholder"] == 0 and source_uri_counts["missing"] == 0 else "failed"},
        {"name": "authority-evidence-freshness", "status": "passed" if freshness["stale"] == 0 and freshness["missing"] == 0 else "failed"},
    ]


def _bundle_controls(mode: str, evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    freshness = _freshness_counts(evidence)
    source_uri_counts = _source_uri_counts(evidence)
    complete = not summary.get("missing_requirement_ids")
    return [
        {"name": "authority-checklist-covered", "status": "passed" if complete else "failed"},
        {"name": "authority-evidence-live-source-uris", "status": "passed" if source_uri_counts["placeholder"] == 0 and source_uri_counts["missing"] == 0 else "failed"},
        {"name": "authority-evidence-freshness", "status": "passed" if freshness["stale"] == 0 and freshness["missing"] == 0 else "failed"},
        {"name": "production-export-mode", "status": "passed" if mode == "production-export" else "not-applicable"},
    ]


def _authority_source_context(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "contract_hash": binding.get("contract", {}).get("hash") if isinstance(binding.get("contract"), dict) else None,
        "replay_hash": binding.get("replay", {}).get("hash") if isinstance(binding.get("replay"), dict) else None,
        "temporal_manifest_id": binding.get("temporal_holdout", {}).get("manifest_id") if isinstance(binding.get("temporal_holdout"), dict) else None,
        "traffic_export_id": binding.get("traffic_export", {}).get("export_id") if isinstance(binding.get("traffic_export"), dict) else None,
        "traffic_records_root": binding.get("traffic_export", {}).get("records_root") if isinstance(binding.get("traffic_export"), dict) else None,
        "traffic_completeness_id": binding.get("traffic_completeness", {}).get("completeness_id") if isinstance(binding.get("traffic_completeness"), dict) else None,
        "traffic_completeness_mode": binding.get("traffic_completeness", {}).get("mode") if isinstance(binding.get("traffic_completeness"), dict) else None,
    }


def _freshness_reference(value: dict[str, Any], now: str | None, errors: list[str]) -> str | None:
    reference = now or value.get("generated_at")
    if reference:
        try:
            parse_rfc3339(str(reference))
        except ValueError as exc:
            errors.append(f"freshness reference invalid: {exc}")
            return None
    return str(reference) if reference else None


def _freshness_counts(evidence: list[dict[str, Any]], now: str | None = None) -> dict[str, int]:
    counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not item.get("issued_at") or not item.get("expires_at"):
            counts["missing"] += 1
            continue
        try:
            issued = parse_rfc3339(str(item["issued_at"]))
            expires = parse_rfc3339(str(item["expires_at"]))
            current = parse_rfc3339(now) if now else parse_rfc3339(str(item["issued_at"]))
        except ValueError:
            counts["missing"] += 1
            continue
        if issued <= current < expires:
            counts["fresh"] += 1
        else:
            counts["stale"] += 1
    return counts


def _source_uri_counts(evidence: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"live": 0, "placeholder": 0, "missing": 0}
    for item in evidence:
        source_uri = item.get("source_uri")
        if not source_uri:
            counts["missing"] += 1
        elif _source_uri_is_placeholder(source_uri):
            counts["placeholder"] += 1
        else:
            counts["live"] += 1
    return counts


def _source_uri_is_placeholder(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return not text or text.startswith("todo://") or "todo" in text or "placeholder" in text


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("shadow authority required_production_authority does not match the required checklist")


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if isinstance(controls, list):
        for control in controls:
            if isinstance(control, dict):
                status = str(control.get("status") or "unknown")
                summary[status] = summary.get(status, 0) + 1
    return summary


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    secret_markers = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if any(marker in str(key).lower() for marker in secret_markers) and child not in (None, "", [], {}):
                errors.append(f"secret-like field must be redacted: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    return value.strip()


def _normalize_sha256_ref(value: str | None, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    if not value.startswith("sha256:"):
        raise ValueError(f"{field} must start with sha256:")
    hexdigest = value.removeprefix("sha256:")
    if len(hexdigest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in hexdigest):
        raise ValueError(f"{field} must contain a 64-character sha256 digest")
    return "sha256:" + hexdigest.lower()
