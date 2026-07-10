from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .verifier_public_release import verify_verifier_public_release_receipt

VERIFIER_RELEASE_AUTHORITY_SCHEMA = "trustai.verifier-public-release-authority-dossier/0.1"
VERIFIER_RELEASE_AUTHORITY_ENTRY_TYPE = "verifier.public_release_authority_recorded"
VERIFIER_RELEASE_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "completed-provider-workflow-run", "title": "Completed provider-owned verifier release workflow run with immutable run export", "authority_kinds": ["ci-run", "provider-api"]},
    {"id": "binary-attested-static-build-artifacts", "title": "Binary-attested static verifier artifacts with retained checksums, SBOM, provenance, and signatures", "authority_kinds": ["ci-run", "provider-api", "customer"]},
    {"id": "public-release-api-publication", "title": "Provider release API publication for tag, metadata, publisher, and release URL", "authority_kinds": ["provider-api", "hosted-service"]},
    {"id": "artifact-manifest-and-download-hashes", "title": "Provider-owned release artifact manifest and public download hash replay", "authority_kinds": ["provider-api", "cloud-object-lock", "customer"]},
    {"id": "sbom-provenance-signature-retention", "title": "Retained SBOM, provenance, signature, and source-distribution sidecars", "authority_kinds": ["provider-api", "cloud-object-lock", "customer"]},
    {"id": "transparency-log-inclusion", "title": "Transparency-log inclusion or equivalent public signature log evidence", "authority_kinds": ["provider-api", "hosted-service"]},
    {"id": "immutable-release-audit-logs", "title": "Immutable release-provider audit-log exports and retention roots", "authority_kinds": ["provider-api", "cloud-object-lock", "customer"]},
    {"id": "source-distribution-publication", "title": "Published verifier source distribution, source SBOM, source provenance, and source signature evidence", "authority_kinds": ["provider-api", "hosted-service", "customer"]},
    {"id": "release-account-and-token-custody", "title": "Release account, token, signing key, and publisher credential custody controls", "authority_kinds": ["kms-hsm", "provider-api", "customer"]},
    {"id": "external-third-party-download-replay", "title": "External third-party replay of public release downloads, hashes, signatures, and verifier invocation", "authority_kinds": ["provider-api", "hosted-service", "customer"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class VerifierReleaseAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_verifier_release_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("verifier release authority dossier must contain an object")
    return value


def write_verifier_release_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_verifier_release_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError("authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]")
    requirement_id, authority_kind, evidence_ref, evidence_hash, description = [part.strip() for part in parts]
    description_parts = [part.strip() for part in description.split(";")]
    metadata: dict[str, Any] = {}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("authority evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in {"issuer", "subject", "source_uri", "issued_at", "expires_at"}:
            raise ValueError(f"unsupported authority evidence metadata key: {key}")
        metadata[key] = metadata_value
    return {"requirement_id": requirement_id, "authority_kind": authority_kind, "evidence_ref": evidence_ref, "evidence_hash": evidence_hash, "description": description_parts[0], **metadata}


def build_verifier_release_authority_dossier(
    public_release_receipt: dict[str, Any],
    *,
    verifier_release: dict[str, Any] | None = None,
    distribution_receipt: dict[str, Any] | None = None,
    build_attestation: dict[str, Any] | None = None,
    release_run: dict[str, Any] | None = None,
    release_run_bundle: dict[str, Any] | None = None,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    distribution_bundle_path: str | Path | None = None,
    distribution_sbom_path: str | Path | None = None,
    distribution_provenance_path: str | Path | None = None,
    distribution_signature_path: str | Path | None = None,
    binary_path: str | Path | None = None,
    mode: str = "provider-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in VERIFIER_RELEASE_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(VERIFIER_RELEASE_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    source_args = _public_release_source_args(
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        distribution_bundle_path=distribution_bundle_path,
        distribution_sbom_path=distribution_sbom_path,
        distribution_provenance_path=distribution_provenance_path,
        distribution_signature_path=distribution_signature_path,
        binary_path=binary_path,
        key=key,
    )
    source_result = verify_verifier_public_release_receipt(
        public_release_receipt,
        verifier_release,
        distribution_receipt,
        build_attestation,
        release_run,
        release_run_bundle,
        **source_args,
    )
    if not source_result.ok:
        raise ValueError("invalid verifier public release source: " + "; ".join(source_result.errors))

    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    body: dict[str, Any] = {
        "schema": VERIFIER_RELEASE_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or public_release_receipt.get("public_release", {}).get("provider") or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "public_release_binding": _public_release_binding(public_release_receipt),
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, public_release_receipt, evidence_items, summary),
        "limitations": [
            "This dossier binds a verified verifier public release receipt to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for provider workflow, release API, artifact, transparency-log, audit-log, and credential-custody evidence.",
            "It does not claim production verifier release authority unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value({"dossier_id": dossier_id, "verifier_release_authority": body}, key)]}

def verify_verifier_release_authority_dossier(
    dossier: dict[str, Any],
    *,
    public_release_receipt: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    distribution_receipt: dict[str, Any] | None = None,
    build_attestation: dict[str, Any] | None = None,
    release_run: dict[str, Any] | None = None,
    release_run_bundle: dict[str, Any] | None = None,
    root: str | Path = ".",
    conformance_report: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    distribution_bundle_path: str | Path | None = None,
    distribution_sbom_path: str | Path | None = None,
    distribution_provenance_path: str | Path | None = None,
    distribution_signature_path: str | Path | None = None,
    binary_path: str | Path | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> VerifierReleaseAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != VERIFIER_RELEASE_AUTHORITY_SCHEMA:
        errors.append(f"unsupported verifier release authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical verifier release authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("verifier release authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "verifier_release_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("verifier release authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in VERIFIER_RELEASE_AUTHORITY_MODES:
        errors.append("verifier release authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"verifier release authority mode is {mode}; live production release authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"verifier release authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"verifier release authority {field} is required")

    source_args = _public_release_source_args(
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        distribution_bundle_path=distribution_bundle_path,
        distribution_sbom_path=distribution_sbom_path,
        distribution_provenance_path=distribution_provenance_path,
        distribution_signature_path=distribution_signature_path,
        binary_path=binary_path,
        key=key,
    )
    _verify_public_release_binding(
        dossier.get("public_release_binding"),
        public_release_receipt,
        verifier_release,
        distribution_receipt,
        build_attestation,
        release_run,
        release_run_bundle,
        source_args,
        errors,
        warnings,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("verifier release authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("verifier release authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_counts[_verify_authority_evidence_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh)] += 1

    expected_summary = _summary([item for item in evidence if isinstance(item, dict)])
    if dossier.get("summary") != expected_summary:
        errors.append("verifier release authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("verifier release authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("verifier release authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every verifier release authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every verifier release authority evidence item to be fresh")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("verifier release authority controls are required")
    _check_no_secret_values(dossier, errors)
    return VerifierReleaseAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_verifier_release_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    public_release_receipt: dict[str, Any],
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
    **sources: Any,
) -> dict[str, Any]:
    result = verify_verifier_release_authority_dossier(
        dossier,
        public_release_receipt=public_release_receipt,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
        **sources,
    )
    if not result.ok:
        raise ValueError("invalid verifier release authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "public_release_binding": dossier.get("public_release_binding"),
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {"requirement_id": item.get("requirement_id"), "authority_kind": item.get("authority_kind"), "evidence_ref": item.get("evidence_ref"), "evidence_hash": item.get("evidence_hash"), "evidence_id": item.get("evidence_id"), "issued_at": item.get("issued_at"), "expires_at": item.get("expires_at")}
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(VERIFIER_RELEASE_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _public_release_source_args(**kwargs: Any) -> dict[str, Any]:
    return dict(kwargs)


def _public_release_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    public_release = receipt.get("public_release", {}) if isinstance(receipt.get("public_release"), dict) else {}
    source = receipt.get("source", {}) if isinstance(receipt.get("source"), dict) else {}
    provider = receipt.get("provider_evidence", {}) if isinstance(receipt.get("provider_evidence"), dict) else {}
    artifacts = receipt.get("artifacts", []) if isinstance(receipt.get("artifacts"), list) else []
    return {
        "release_publication_id": receipt.get("release_publication_id"),
        "release_publication_hash": content_hash(receipt),
        "receipt_schema": receipt.get("schema"),
        "generated_at": receipt.get("generated_at"),
        "provider": public_release.get("provider"),
        "release_ref": public_release.get("release_ref"),
        "release_url": public_release.get("release_url"),
        "tag": public_release.get("tag"),
        "publisher_ref": public_release.get("publisher_ref"),
        "published_at": public_release.get("published_at"),
        "release_id": source.get("release_id"),
        "release_hash": source.get("release_hash"),
        "distribution_id": source.get("distribution_id"),
        "distribution_hash": source.get("distribution_hash"),
        "build_id": source.get("build_id"),
        "build_hash": source.get("build_hash"),
        "build_mode": source.get("build_mode"),
        "run_id": source.get("run_id"),
        "run_hash": source.get("run_hash"),
        "bundle_id": source.get("bundle_id"),
        "bundle_hash": source.get("bundle_hash"),
        "conformance_report_id": source.get("conformance_report_id"),
        "standards_package_id": source.get("standards_package_id"),
        "artifact_count": len(artifacts),
        "artifact_root": content_hash(artifacts),
        "artifact_hashes": [item.get("sha256") for item in artifacts if isinstance(item, dict)],
        "provider_evidence": provider,
        "control_status_summary": _status_summary(receipt.get("controls", [])),
    }


def _verify_public_release_binding(
    binding: Any,
    public_release_receipt: dict[str, Any] | None,
    verifier_release: dict[str, Any] | None,
    distribution_receipt: dict[str, Any] | None,
    build_attestation: dict[str, Any] | None,
    release_run: dict[str, Any] | None,
    release_run_bundle: dict[str, Any] | None,
    source_args: dict[str, Any],
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(binding, dict):
        errors.append("verifier release authority public_release_binding must be an object")
        return
    if public_release_receipt is None:
        warnings.append("verifier public release receipt was not supplied; public release hash was not replayed")
        return
    expected = _public_release_binding(public_release_receipt)
    if binding != expected:
        errors.append("verifier release authority public_release_binding does not match supplied public release receipt")
    result = verify_verifier_public_release_receipt(
        public_release_receipt,
        verifier_release,
        distribution_receipt,
        build_attestation,
        release_run,
        release_run_bundle,
        **source_args,
    )
    if not result.ok:
        errors.extend(f"verifier release authority public release source: {error}" for error in result.errors)
    warnings.extend(f"verifier release authority public release source: {warning}" for warning in result.warnings)


def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unknown verifier release production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in _requirement_authority_kinds(requirement_id):
        raise ValueError(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    _require_hash_ref(evidence_hash, "evidence_hash")
    for field in ("issued_at", "expires_at"):
        if item.get(field):
            parse_rfc3339(str(item[field]))
    body = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description,
        "issuer": item.get("issuer"),
        "subject": item.get("subject"),
        "source_uri": item.get("source_uri"),
        "issued_at": item.get("issued_at"),
        "expires_at": item.get("expires_at"),
    }
    return {**body, "evidence_id": content_hash(body)}


def _verify_authority_evidence_item(item: dict[str, Any], errors: list[str], warnings: list[str], *, now: Any, require_fresh: bool) -> str:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"verifier release authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unknown verifier release production authority requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS and authority_kind not in _requirement_authority_kinds(str(requirement_id)):
        errors.append(f"authority kind {authority_kind} is not accepted for requirement {requirement_id}")
    for field in ("evidence_ref", "evidence_hash", "description"):
        if not item.get(field):
            errors.append(f"verifier release authority {field} is required: {requirement_id}")
    if item.get("evidence_hash") and not str(item.get("evidence_hash")).startswith("sha256:"):
        errors.append(f"verifier release authority evidence_hash must start with sha256: {requirement_id}")

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(f"verifier release authority freshness metadata missing for {requirement_id}: {', '.join(missing_fields)}", errors, warnings, require_fresh=require_fresh)
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"verifier release authority expires_at must be after issued_at: {requirement_id}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(f"verifier release authority evidence is not yet issued for {requirement_id}: {item.get('issued_at')}", errors, warnings, require_fresh=require_fresh)
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(f"verifier release authority evidence expired for {requirement_id}: {item.get('expires_at')}", errors, warnings, require_fresh=require_fresh)
    return freshness_status


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("verifier release authority required_production_authority does not match v0.1 requirements")


def _summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({str(item.get("requirement_id")) for item in evidence if item.get("requirement_id") in set(PRODUCTION_AUTHORITY_REQUIREMENT_IDS)})
    missing = [requirement_id for requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if requirement_id not in covered]
    return {
        "status": "complete" if not missing else "partial",
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "evidence_count": len(evidence),
        "issued_at_count": sum(1 for item in evidence if item.get("issued_at")),
        "expires_at_count": sum(1 for item in evidence if item.get("expires_at")),
        "freshness_window_count": sum(1 for item in evidence if item.get("issued_at") and item.get("expires_at")),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
    }


def _controls(mode: str, receipt: dict[str, Any], evidence: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    provider = receipt.get("provider_evidence", {}) if isinstance(receipt.get("provider_evidence"), dict) else {}
    provider_exports = all(provider.get(field) for field in ("workflow_run_export_hash", "release_api_export_hash", "artifact_manifest_hash"))
    audit_bound = bool(provider.get("audit_log_ref") and provider.get("audit_log_root") and provider.get("audit_log_size"))
    transparency_bound = bool(provider.get("transparency_log_ref") and provider.get("transparency_log_root"))
    return [
        {"name": "public_release_receipt_replayed", "status": "passed" if receipt.get("release_publication_id") else "failed", "detail": "The authority dossier binds a signed verifier public release receipt."},
        {"name": "release_source_graph_bound", "status": "passed" if receipt.get("source") else "failed", "detail": "Verifier release, source distribution, Go build, release-run, release-run bundle, conformance, and standards sources are hash-bound."},
        {"name": "provider_release_exports_bound", "status": "passed" if provider_exports and audit_bound and transparency_bound else "deferred", "detail": "Provider workflow, release API, artifact manifest, audit-log, and transparency-log evidence references are present when available."},
        {"name": "authority_evidence_manifested", "status": "passed" if evidence else "deferred", "detail": "External release authority evidence references are hash-bound when supplied."},
        {"name": "freshness_windows_tracked", "status": "passed" if evidence and summary["freshness_window_count"] == len(evidence) else "deferred", "detail": "Issued/expires freshness windows are tracked for every supplied authority item when available."},
        {"name": "complete_release_authority", "status": "passed" if summary["missing_requirement_count"] == 0 else "deferred", "detail": "Every verifier release production authority requirement must be covered before this can claim live public release authority."},
        {"name": "production_claim_limited", "status": "passed" if mode != "production-dossier" or summary["missing_requirement_count"] == 0 else "failed", "detail": "Non-production dossier modes explicitly avoid claiming live release-provider, artifact, transparency-log, audit-log, and credential-custody authority."},
    ]


def _status_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _requirement_authority_kinds(requirement_id: str) -> set[str]:
    for requirement in PRODUCTION_AUTHORITY_REQUIREMENTS:
        if requirement["id"] == requirement_id:
            return set(requirement["authority_kinds"])
    return set()


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]) -> Any:
    reference = now or dossier.get("generated_at")
    if not reference:
        return None
    try:
        return parse_rfc3339(str(reference))
    except ValueError as exc:
        label = "now" if now else "generated_at"
        errors.append(f"verifier release authority freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]) -> Any:
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"verifier release authority {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"verifier release authority {field} is required")
    return value


def _require_hash_ref(value: str, field: str) -> None:
    if not value.startswith("sha256:"):
        raise ValueError(f"verifier release authority {field} must start with sha256:")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}"
            if any(marker in normalized for marker in SECRET_KEY_MARKERS):
                if _allowed_secret_reference_key(normalized, child):
                    pass
                elif not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"verifier release authority contains secret-like field {child_path}; store only redacted refs")
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
