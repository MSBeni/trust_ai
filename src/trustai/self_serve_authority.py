from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .onboarding import verify_self_serve_onboarding_receipt

SELF_SERVE_AUTHORITY_SCHEMA = "trustai.self-serve-onboarding-production-authority-dossier/0.1"
SELF_SERVE_AUTHORITY_ENTRY_TYPE = "onboarding.self_serve.production_authority_recorded"
SELF_SERVE_AUTHORITY_MODES = {"local-dossier", "provider-dossier", "production-dossier"}

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {
        "id": "hosted-account-creation-service",
        "title": "Hosted signup, tenant creation, and first agent registration service evidence",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "production-identity-federation",
        "title": "Production identity federation, SSO/OIDC, MFA, and signup session evidence",
        "authority_kinds": ["identity-provider", "hosted-service", "provider-api"],
    },
    {
        "id": "billing-plan-entitlement",
        "title": "Billing setup, plan entitlement, trial conversion, and customer acceptance evidence",
        "authority_kinds": ["hosted-service", "provider-api", "customer"],
    },
    {
        "id": "usage-metering-quota-enforcement",
        "title": "Usage metering, quota enforcement, and evidence-volume accounting exports",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "support-slo-operations",
        "title": "Support operations, onboarding SLOs, and escalation evidence",
        "authority_kinds": ["hosted-service", "customer"],
    },
    {
        "id": "tenant-isolation-rbac",
        "title": "Tenant isolation, RBAC policy, organization membership, and authorization evidence",
        "authority_kinds": ["identity-provider", "hosted-service", "provider-api"],
    },
    {
        "id": "gateway-sdk-provisioning-replay",
        "title": "Hosted SDK key provisioning, MCP gateway setup replay, and quickstart completion evidence",
        "authority_kinds": ["hosted-service", "ci-run", "provider-api"],
    },
    {
        "id": "onboarding-audit-retention",
        "title": "Immutable onboarding audit logs, access logs, and retention evidence",
        "authority_kinds": ["hosted-service", "cloud-object-lock", "provider-api"],
    },
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class SelfServeAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_self_serve_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("self-serve onboarding authority dossier must contain an object")
    return value


def write_self_serve_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_self_serve_authority_evidence_arg(value: str) -> dict[str, Any]:
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
    return {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description_parts[0],
        **metadata,
    }


def build_self_serve_authority_dossier(
    onboarding_receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    authority_evidence: list[dict[str, Any]],
    mode: str = "provider-dossier",
    environment: str = "local",
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in SELF_SERVE_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(SELF_SERVE_AUTHORITY_MODES)}")
    for value, field in (
        (environment, "environment"),
        (dossier_ref, "dossier_ref"),
        (authority_ref, "authority_ref"),
        (producer_ref, "producer_ref"),
    ):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    source_binding = _onboarding_source_binding(onboarding_receipt)
    source_result = verify_self_serve_onboarding_receipt(onboarding_receipt, root=root, key=key)
    evidence_items = [_build_authority_evidence_item(item, source_binding) for item in authority_evidence]
    summary = _summary(evidence_items)
    body = {
        "schema": SELF_SERVE_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment,
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "onboarding_source": source_binding,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, source_result.ok, summary),
        "limitations": [
            "This dossier binds hosted self-serve authority evidence to a verified local SDK/gateway onboarding receipt.",
            "Provider-dossier mode records retained authority evidence without claiming the hosted PLG service is production complete.",
            "Production claims require production-dossier mode, complete checklist coverage, live authority source URIs, and fresh evidence windows.",
        ],
    }
    dossier_id = content_hash(body)
    return {
        **body,
        "dossier_id": dossier_id,
        "signatures": [sign_value({"dossier_id": dossier_id, "self_serve_onboarding_authority": body}, key)],
    }


def verify_self_serve_authority_dossier(
    dossier: dict[str, Any],
    *,
    onboarding_receipt: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> SelfServeAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != SELF_SERVE_AUTHORITY_SCHEMA:
        errors.append(f"unsupported self-serve onboarding authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical self-serve onboarding authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("self-serve onboarding authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "self_serve_onboarding_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("self-serve onboarding authority signature verification failed")
    mode = dossier.get("mode")
    if mode not in SELF_SERVE_AUTHORITY_MODES:
        errors.append("self-serve onboarding authority mode is unsupported")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"self-serve onboarding authority {field} is required")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"self-serve onboarding authority generated_at invalid: {exc}")

    source_binding = dossier.get("onboarding_source")
    source_ok = False
    if not isinstance(source_binding, dict):
        errors.append("self-serve onboarding authority onboarding_source must be an object")
    elif onboarding_receipt is None:
        warnings.append("self-serve onboarding receipt was not supplied; onboarding source was not replayed")
    else:
        expected = _onboarding_source_binding(onboarding_receipt)
        if source_binding != expected:
            errors.append("self-serve onboarding authority onboarding_source does not match supplied onboarding receipt")
        source_result = verify_self_serve_onboarding_receipt(onboarding_receipt, root=root, key=key)
        if not source_result.ok:
            errors.extend(f"self-serve onboarding authority source: {error}" for error in source_result.errors)
        warnings.extend(f"self-serve onboarding authority source: {warning}" for warning in source_result.warnings)
        source_ok = source_result.ok and source_binding == expected

    if dossier.get("required_production_authority") != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("self-serve onboarding authority required_production_authority does not match local checklist")
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("self-serve onboarding authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    expected_source_context = _authority_evidence_source_context(source_binding) if isinstance(source_binding, dict) else None
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("self-serve onboarding authority evidence item must be an object")
            continue
        freshness = _verify_authority_evidence_item(
            item,
            errors,
            warnings,
            now=freshness_now,
            require_fresh=require_fresh,
            expected_source_context=expected_source_context,
        )
        freshness_counts[freshness] = freshness_counts.get(freshness, 0) + 1
    summary = _summary([item for item in evidence if isinstance(item, dict)])
    if dossier.get("summary") != summary:
        errors.append("self-serve onboarding authority summary does not match authority evidence")
    expected_controls = _controls(str(mode), source_ok, summary)
    if dossier.get("controls") != expected_controls:
        errors.append("self-serve onboarding authority controls do not match dossier body")
    missing = _missing_requirement_ids(evidence)
    if missing:
        message = "self-serve onboarding authority evidence missing for: " + ", ".join(missing)
        if require_complete or mode == "production-dossier":
            errors.append(message)
        else:
            warnings.append(message)
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("self-serve onboarding authority production-dossier requires fresh authority evidence")
    return SelfServeAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=summary["covered_requirement_count"],
        required_count=summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_self_serve_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    onboarding_receipt: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_self_serve_authority_dossier(
        dossier,
        onboarding_receipt=onboarding_receipt,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid self-serve onboarding authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "onboarding_receipt_id": (dossier.get("onboarding_source") or {}).get("receipt_id"),
        "onboarding_ref": (dossier.get("onboarding_source") or {}).get("onboarding_ref"),
        "tenant_ref": (dossier.get("onboarding_source") or {}).get("tenant_ref"),
        "agent_ref": (dossier.get("onboarding_source") or {}).get("agent_ref"),
        "authority_evidence_count": len(dossier.get("authority_evidence", [])),
        "covered_requirement_count": result.covered_count,
        "required_requirement_count": result.required_count,
        "fresh_evidence_count": result.fresh_evidence_count,
        "stale_evidence_count": result.stale_evidence_count,
        "missing_freshness_count": result.missing_freshness_count,
        "control_summary": _status_summary(dossier.get("controls", [])),
    }
    return chain.append(SELF_SERVE_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _onboarding_source_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ValueError("self-serve onboarding authority source receipt must be an object")
    return {
        "receipt_id": receipt.get("receipt_id"),
        "receipt_hash": content_hash(receipt),
        "receipt_schema": receipt.get("schema"),
        "generated_at": receipt.get("generated_at"),
        "onboarding_ref": receipt.get("onboarding_ref"),
        "tenant_ref": receipt.get("tenant_ref"),
        "agent_ref": receipt.get("agent_ref"),
        "requester_ref": receipt.get("requester_ref"),
        "environment": receipt.get("environment"),
        "sdk_scope": receipt.get("sdk_scope"),
        "gateway_mode": receipt.get("gateway_mode"),
        "source_artifact_count": len(receipt.get("source_artifacts", [])),
        "quickstart_step_count": len(receipt.get("quickstart_steps", [])),
        "quickstart_replay_count": len(receipt.get("quickstart_replay", [])),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }


def _build_authority_evidence_item(item: dict[str, Any], source_binding: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = _normalize_sha256_ref(item.get("evidence_hash"), "evidence_hash")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported self-serve onboarding authority requirement: {requirement_id}")
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in requirement["authority_kinds"]:
        raise ValueError(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (description, "description")):
        _require_text(value, field)
    built = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description,
        "source_context": _authority_evidence_source_context(source_binding),
    }
    for field in ("issuer", "subject", "source_uri", "issued_at", "expires_at"):
        if item.get(field):
            built[field] = str(item[field])
    for field in ("issued_at", "expires_at"):
        if built.get(field):
            parse_rfc3339(str(built[field]))
    if built.get("issued_at") and built.get("expires_at") and parse_rfc3339(str(built["issued_at"])) > parse_rfc3339(str(built["expires_at"])):
        raise ValueError("authority evidence issued_at must not be after expires_at")
    built["evidence_id"] = content_hash(built)
    return built


def _verify_authority_evidence_item(
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now: Any,
    require_fresh: bool,
    expected_source_context: dict[str, Any] | None,
) -> str:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"self-serve onboarding authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unsupported self-serve onboarding authority requirement: {requirement_id}")
    else:
        requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
        if authority_kind not in requirement["authority_kinds"]:
            errors.append(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    for field in ("evidence_ref", "description"):
        if not item.get(field):
            errors.append(f"self-serve onboarding authority {field} is required")
    try:
        normalized_hash = _normalize_sha256_ref(item.get("evidence_hash"), "evidence_hash")
        if normalized_hash != item.get("evidence_hash"):
            errors.append(f"self-serve onboarding authority evidence_hash is not canonical for {requirement_id}")
    except ValueError as exc:
        errors.append(f"invalid self-serve onboarding authority evidence: {exc}")
    if expected_source_context is not None and item.get("source_context") != expected_source_context:
        errors.append(f"self-serve onboarding authority source_context does not match onboarding source: {requirement_id}")
    return _freshness_status(item, errors, warnings, now=now, require_fresh=require_fresh)


def _authority_evidence_source_context(source_binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": source_binding.get("receipt_id"),
        "receipt_hash": source_binding.get("receipt_hash"),
        "onboarding_ref": source_binding.get("onboarding_ref"),
        "tenant_ref": source_binding.get("tenant_ref"),
        "agent_ref": source_binding.get("agent_ref"),
        "sdk_scope": source_binding.get("sdk_scope"),
        "gateway_mode": source_binding.get("gateway_mode"),
        "quickstart_replay_count": source_binding.get("quickstart_replay_count"),
        "control_summary": source_binding.get("control_summary"),
    }


def _summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({str(item.get("requirement_id")) for item in evidence if item.get("requirement_id") in PRODUCTION_AUTHORITY_REQUIREMENT_IDS})
    kinds = sorted({str(item.get("authority_kind")) for item in evidence if item.get("authority_kind")})
    missing = _missing_requirement_ids(evidence)
    return {
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "authority_evidence_count": len(evidence),
        "covered_requirements": covered,
        "missing_requirements": missing,
        "authority_kinds": kinds,
        "hosted_service_evidence_count": sum(1 for item in evidence if item.get("authority_kind") == "hosted-service"),
        "identity_provider_evidence_count": sum(1 for item in evidence if item.get("authority_kind") == "identity-provider"),
    }


def _missing_requirement_ids(evidence: Any) -> list[str]:
    if not isinstance(evidence, list):
        evidence = []
    covered = {str(item.get("requirement_id")) for item in evidence if isinstance(item, dict)}
    return [requirement_id for requirement_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if requirement_id not in covered]


def _controls(mode: str, source_ok: bool, summary: dict[str, Any]) -> list[dict[str, str]]:
    complete = summary.get("missing_requirement_count") == 0
    has_hosted = summary.get("hosted_service_evidence_count", 0) > 0
    has_identity = summary.get("identity_provider_evidence_count", 0) > 0
    return [
        {
            "id": "local-onboarding-receipt-replayed",
            "status": "passed" if source_ok else "deferred",
            "detail": "The authority dossier is bound to a verified self-serve SDK/gateway onboarding receipt.",
        },
        {
            "id": "hosted-service-authority-present",
            "status": "passed" if has_hosted else "deferred",
            "detail": "Hosted PLG account creation, provisioning, metering, or audit evidence is present.",
        },
        {
            "id": "identity-provider-authority-present",
            "status": "passed" if has_identity else "deferred",
            "detail": "Production identity-provider signup/session evidence is present.",
        },
        {
            "id": "complete-production-authority-checklist",
            "status": "passed" if complete else "deferred",
            "detail": "Every self-serve production authority checklist item has at least one accepted authority row.",
        },
        {
            "id": "production-claim-limited",
            "status": "passed" if mode != "production-dossier" or complete else "failed",
            "detail": "Non-production dossier modes do not claim complete hosted self-serve production authority.",
        },
    ]


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]):
    value = now or dossier.get("generated_at") or utc_now()
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"self-serve onboarding authority freshness reference time invalid: {exc}")
        return parse_rfc3339(utc_now())


def _freshness_status(item: dict[str, Any], errors: list[str], warnings: list[str], *, now: Any, require_fresh: bool) -> str:
    issued_raw = item.get("issued_at")
    expires_raw = item.get("expires_at")
    if not issued_raw or not expires_raw:
        _freshness_problem(
            f"self-serve onboarding authority freshness metadata missing for {item.get('requirement_id')}: issued_at, expires_at",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
        return "missing"
    try:
        issued = parse_rfc3339(str(issued_raw))
        expires = parse_rfc3339(str(expires_raw))
    except ValueError as exc:
        errors.append(f"self-serve onboarding authority freshness timestamp invalid for {item.get('requirement_id')}: {exc}")
        return "stale"
    if expires <= issued:
        errors.append(f"self-serve onboarding authority expires_at must be after issued_at: {item.get('requirement_id')}")
        return "stale"
    if issued > now:
        _freshness_problem(
            f"self-serve onboarding authority evidence is not yet issued for {item.get('requirement_id')}: {issued_raw}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
        return "stale"
    if expires <= now:
        _freshness_problem(
            f"self-serve onboarding authority evidence expired for {item.get('requirement_id')}: {expires_raw}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
        return "stale"
    return "fresh"


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if not isinstance(controls, list):
        return summary
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _normalize_sha256_ref(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"self-serve onboarding authority {field} is required")
    if not value.startswith("sha256:"):
        raise ValueError(f"{field} must start with sha256:")
    hexdigest = value.removeprefix("sha256:")
    if len(hexdigest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in hexdigest):
        raise ValueError(f"{field} must contain a 64-character sha256 digest")
    return "sha256:" + hexdigest.lower()


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"self-serve onboarding authority {field} is required")
