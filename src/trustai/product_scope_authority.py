from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .product_scope import verify_product_scope_decision

PRODUCT_SCOPE_AUTHORITY_SCHEMA = "trustai.product-scope-production-authority-dossier/0.1"
PRODUCT_SCOPE_AUTHORITY_ENTRY_TYPE = "trustai.product_scope.production_authority.attested"
PRODUCT_SCOPE_AUTHORITY_MODES = {"local-dossier", "governance-dossier", "production-dossier"}

OPERATING_AUTHORITY_REQUIREMENTS = [
    {
        "id": "company-governance-adoption",
        "title": "Company governance adoption of the proof-strength scope discipline",
        "authority_kinds": ["customer"],
    },
    {
        "id": "product-council-enforcement",
        "title": "Product council enforcement and exception approval evidence",
        "authority_kinds": ["customer", "ci-run"],
    },
    {
        "id": "anti-focus-decline-ledger",
        "title": "Anti-focus decline ledger and non-proof feature rejection evidence",
        "authority_kinds": ["ci-run", "customer"],
    },
    {
        "id": "customer-pressure-exception-review",
        "title": "Customer-pressure exception review and refusal evidence",
        "authority_kinds": ["customer"],
    },
    {
        "id": "ongoing-roadmap-discipline",
        "title": "Ongoing roadmap discipline audit and CI/source review evidence",
        "authority_kinds": ["ci-run", "customer"],
    },
]
OPERATING_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in OPERATING_AUTHORITY_REQUIREMENTS]


@dataclass
class ProductScopeAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_product_scope_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("product scope authority dossier must contain an object")
    return value


def write_product_scope_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_product_scope_authority_evidence_arg(value: str) -> dict[str, Any]:
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


def build_product_scope_authority_dossier(
    decision_receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    authority_evidence: list[dict[str, Any]],
    mode: str = "governance-dossier",
    environment: str = "local",
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PRODUCT_SCOPE_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(PRODUCT_SCOPE_AUTHORITY_MODES)}")
    for value, field in (
        (environment, "environment"),
        (dossier_ref, "dossier_ref"),
        (authority_ref, "authority_ref"),
        (producer_ref, "producer_ref"),
    ):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    source_binding = _decision_source_binding(decision_receipt)
    source_result = verify_product_scope_decision(decision_receipt, root=root, key=key)
    evidence_items = [_build_authority_evidence_item(item, source_binding) for item in authority_evidence]
    summary = _summary(evidence_items)
    body = {
        "schema": PRODUCT_SCOPE_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment,
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "decision_source": source_binding,
        "required_operating_authority": OPERATING_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, source_result.ok, summary),
        "limitations": [
            "This dossier binds operating authority evidence to a verified product-scope discipline decision.",
            "Governance-dossier mode records retained authority evidence without claiming company-wide production enforcement is complete.",
            "Production claims require production-dossier mode, complete checklist coverage, live authority source URIs, and fresh evidence windows.",
        ],
    }
    dossier_id = content_hash(body)
    return {
        **body,
        "dossier_id": dossier_id,
        "signatures": [sign_value({"dossier_id": dossier_id, "product_scope_authority": body}, key)],
    }


def verify_product_scope_authority_dossier(
    dossier: dict[str, Any],
    *,
    decision_receipt: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> ProductScopeAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != PRODUCT_SCOPE_AUTHORITY_SCHEMA:
        errors.append(f"unsupported product scope authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical product scope authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("product scope authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "product_scope_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("product scope authority signature verification failed")
    mode = dossier.get("mode")
    if mode not in PRODUCT_SCOPE_AUTHORITY_MODES:
        errors.append("product scope authority mode is unsupported")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"product scope authority {field} is required")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"product scope authority generated_at invalid: {exc}")

    source_binding = dossier.get("decision_source")
    source_ok = False
    if not isinstance(source_binding, dict):
        errors.append("product scope authority decision_source must be an object")
    elif decision_receipt is None:
        warnings.append("product scope decision receipt was not supplied; decision source was not replayed")
    else:
        expected = _decision_source_binding(decision_receipt)
        if source_binding != expected:
            errors.append("product scope authority decision_source does not match supplied decision receipt")
        source_result = verify_product_scope_decision(decision_receipt, root=root, key=key)
        if not source_result.ok:
            errors.extend(f"product scope authority source: {error}" for error in source_result.errors)
        warnings.extend(f"product scope authority source: {warning}" for warning in source_result.warnings)
        source_ok = source_result.ok and source_binding == expected

    if dossier.get("required_operating_authority") != OPERATING_AUTHORITY_REQUIREMENTS:
        errors.append("product scope authority required_operating_authority does not match local checklist")
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("product scope authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    expected_source_context = _authority_evidence_source_context(source_binding) if isinstance(source_binding, dict) else None
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("product scope authority evidence item must be an object")
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
        errors.append("product scope authority summary does not match authority evidence")
    expected_controls = _controls(str(mode), source_ok, summary)
    if dossier.get("controls") != expected_controls:
        errors.append("product scope authority controls do not match dossier body")
    missing = _missing_requirement_ids(evidence)
    if missing:
        message = "product scope authority evidence missing for: " + ", ".join(missing)
        if require_complete or mode == "production-dossier":
            errors.append(message)
        else:
            warnings.append(message)
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("product scope authority production-dossier requires fresh authority evidence")
    return ProductScopeAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=summary["covered_requirement_count"],
        required_count=summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_product_scope_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    decision_receipt: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_product_scope_authority_dossier(
        dossier,
        decision_receipt=decision_receipt,
        root=root,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid product scope authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "decision_id": (dossier.get("decision_source") or {}).get("decision_id"),
        "decision_ref": (dossier.get("decision_source") or {}).get("decision_ref"),
        "decision": (dossier.get("decision_source") or {}).get("decision"),
        "feature_title": (dossier.get("decision_source") or {}).get("feature_title"),
        "authority_evidence_count": len(dossier.get("authority_evidence", [])),
        "covered_requirement_count": result.covered_count,
        "required_requirement_count": result.required_count,
        "fresh_evidence_count": result.fresh_evidence_count,
        "stale_evidence_count": result.stale_evidence_count,
        "missing_freshness_count": result.missing_freshness_count,
        "control_summary": _status_summary(dossier.get("controls", [])),
    }
    return chain.append(PRODUCT_SCOPE_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _decision_source_binding(decision_receipt: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(decision_receipt, dict):
        raise ValueError("product scope authority source decision must be an object")
    feature = decision_receipt.get("feature", {}) if isinstance(decision_receipt.get("feature"), dict) else {}
    return {
        "decision_id": decision_receipt.get("decision_id"),
        "decision_hash": content_hash(decision_receipt),
        "decision_schema": decision_receipt.get("schema"),
        "generated_at": decision_receipt.get("generated_at"),
        "decision_ref": decision_receipt.get("decision_ref"),
        "requester_ref": decision_receipt.get("requester_ref"),
        "reviewer_ref": decision_receipt.get("reviewer_ref"),
        "decision": decision_receipt.get("decision"),
        "feature_title": feature.get("title"),
        "proof_impacts": decision_receipt.get("proof_impacts", []),
        "anti_focus_flags": decision_receipt.get("anti_focus_flags", []),
        "control_summary": _status_summary(decision_receipt.get("controls", [])),
    }


def _build_authority_evidence_item(item: dict[str, Any], source_binding: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = _normalize_sha256_ref(item.get("evidence_hash"), "evidence_hash")
    description = str(item.get("description") or "")
    if requirement_id not in OPERATING_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported product scope authority requirement: {requirement_id}")
    requirement = next(req for req in OPERATING_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
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
        errors.append(f"product scope authority evidence_id does not match evidence body: {item.get('requirement_id')}")
    requirement_id = item.get("requirement_id")
    authority_kind = item.get("authority_kind")
    if requirement_id not in OPERATING_AUTHORITY_REQUIREMENT_IDS:
        errors.append(f"unsupported product scope authority requirement: {requirement_id}")
    else:
        requirement = next(req for req in OPERATING_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
        if authority_kind not in requirement["authority_kinds"]:
            errors.append(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    for field in ("evidence_ref", "description"):
        if not item.get(field):
            errors.append(f"product scope authority {field} is required")
    try:
        normalized_hash = _normalize_sha256_ref(item.get("evidence_hash"), "evidence_hash")
        if normalized_hash != item.get("evidence_hash"):
            errors.append(f"product scope authority evidence_hash is not canonical for {requirement_id}")
    except ValueError as exc:
        errors.append(f"invalid product scope authority evidence: {exc}")
    if expected_source_context is not None and item.get("source_context") != expected_source_context:
        errors.append(f"product scope authority source_context does not match decision source: {requirement_id}")
    return _freshness_status(item, errors, warnings, now=now, require_fresh=require_fresh)


def _authority_evidence_source_context(source_binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision_id": source_binding.get("decision_id"),
        "decision_hash": source_binding.get("decision_hash"),
        "decision_ref": source_binding.get("decision_ref"),
        "decision": source_binding.get("decision"),
        "feature_title": source_binding.get("feature_title"),
        "proof_impacts": source_binding.get("proof_impacts", []),
        "anti_focus_flags": source_binding.get("anti_focus_flags", []),
        "control_summary": source_binding.get("control_summary"),
    }


def _summary(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({str(item.get("requirement_id")) for item in evidence if item.get("requirement_id") in OPERATING_AUTHORITY_REQUIREMENT_IDS})
    kinds = sorted({str(item.get("authority_kind")) for item in evidence if item.get("authority_kind")})
    missing = _missing_requirement_ids(evidence)
    return {
        "required_requirement_count": len(OPERATING_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "authority_evidence_count": len(evidence),
        "covered_requirements": covered,
        "missing_requirements": missing,
        "authority_kinds": kinds,
        "ci_run_evidence_count": sum(1 for item in evidence if item.get("authority_kind") == "ci-run"),
        "customer_evidence_count": sum(1 for item in evidence if item.get("authority_kind") == "customer"),
    }


def _missing_requirement_ids(evidence: Any) -> list[str]:
    if not isinstance(evidence, list):
        evidence = []
    covered = {str(item.get("requirement_id")) for item in evidence if isinstance(item, dict)}
    return [requirement_id for requirement_id in OPERATING_AUTHORITY_REQUIREMENT_IDS if requirement_id not in covered]


def _controls(mode: str, source_ok: bool, summary: dict[str, Any]) -> list[dict[str, str]]:
    complete = summary.get("missing_requirement_count") == 0
    has_customer = summary.get("customer_evidence_count", 0) > 0
    has_ci = summary.get("ci_run_evidence_count", 0) > 0
    return [
        {
            "id": "product-scope-decision-replayed",
            "status": "passed" if source_ok else "deferred",
            "detail": "The authority dossier is bound to a verified product-scope discipline decision receipt.",
        },
        {
            "id": "customer-operating-authority-present",
            "status": "passed" if has_customer else "deferred",
            "detail": "Customer or governance authority evidence is present for scope discipline enforcement.",
        },
        {
            "id": "ci-governance-gate-present",
            "status": "passed" if has_ci else "deferred",
            "detail": "CI/source review evidence is present for anti-focus and roadmap discipline gates.",
        },
        {
            "id": "complete-operating-authority-checklist",
            "status": "passed" if complete else "deferred",
            "detail": "Every product-scope operating authority checklist item has at least one accepted authority row.",
        },
        {
            "id": "production-claim-limited",
            "status": "passed" if mode != "production-dossier" or complete else "failed",
            "detail": "Non-production dossier modes do not claim complete company operating authority.",
        },
    ]


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]):
    value = now or dossier.get("generated_at") or utc_now()
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"product scope authority freshness reference time invalid: {exc}")
        return parse_rfc3339(utc_now())


def _freshness_status(item: dict[str, Any], errors: list[str], warnings: list[str], *, now: Any, require_fresh: bool) -> str:
    issued_raw = item.get("issued_at")
    expires_raw = item.get("expires_at")
    if not issued_raw or not expires_raw:
        _freshness_problem(
            f"product scope authority freshness metadata missing for {item.get('requirement_id')}: issued_at, expires_at",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
        return "missing"
    try:
        issued = parse_rfc3339(str(issued_raw))
        expires = parse_rfc3339(str(expires_raw))
    except ValueError as exc:
        errors.append(f"product scope authority freshness timestamp invalid for {item.get('requirement_id')}: {exc}")
        return "stale"
    if expires <= issued:
        errors.append(f"product scope authority expires_at must be after issued_at: {item.get('requirement_id')}")
        return "stale"
    if issued > now:
        _freshness_problem(
            f"product scope authority evidence is not yet issued for {item.get('requirement_id')}: {issued_raw}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
        return "stale"
    if expires <= now:
        _freshness_problem(
            f"product scope authority evidence expired for {item.get('requirement_id')}: {expires_raw}",
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
        raise ValueError(f"product scope authority {field} is required")
    if not value.startswith("sha256:"):
        raise ValueError(f"{field} must start with sha256:")
    hexdigest = value.removeprefix("sha256:")
    if len(hexdigest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in hexdigest):
        raise ValueError(f"{field} must contain a 64-character sha256 digest")
    return "sha256:" + hexdigest.lower()


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"product scope authority {field} is required")
