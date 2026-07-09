from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .marketplace import (
    SUPPORTED_ASSET_TYPES,
    verify_marketplace_catalog,
    verify_marketplace_distribution,
)

MARKETPLACE_AUTHOR_SCHEMA = "trustai.marketplace-author-governance/0.1"
MARKETPLACE_AUTHOR_ENTRY_TYPE = "marketplace.author.governance_attested"
MARKETPLACE_AUTHOR_MODES = {"local-reference", "platform-governed", "partner-governed"}
MARKETPLACE_AUTHOR_KINDS = {"first-party", "third-party", "partner", "community"}
MARKETPLACE_BILLING_MODES = {"not-claimed", "entitlement-recorded", "billing-ready"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class MarketplaceAuthorVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_marketplace_author_governance(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("marketplace author governance receipt must contain an object")
    return value


def write_marketplace_author_governance(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_marketplace_author_governance(
    catalog: dict[str, Any],
    *,
    distribution: dict[str, Any] | None = None,
    root: str | Path = ".",
    mode: str = "platform-governed",
    author_name: str,
    author_ref: str,
    author_kind: str = "third-party",
    author_organization: str | None = None,
    contact_ref: str,
    identity_provider: str,
    identity_subject: str,
    identity_assurance: str,
    onboarding_status: str = "approved",
    agreement_ref: str,
    terms_ref: str,
    license_ref: str,
    ip_attestation_ref: str,
    review_ticket_ref: str,
    review_policy_ref: str,
    reviewer_ref: str,
    reviewer_role: str = "marketplace-reviewer",
    asset_ids: list[str] | None = None,
    billing_mode: str = "entitlement-recorded",
    billing_account_ref: str | None = None,
    entitlement_policy_ref: str | None = None,
    payout_account_ref: str | None = None,
    revenue_share_bps: int = 0,
    tax_form_ref: str | None = None,
    revocation_policy_ref: str,
    support_contact_ref: str,
    security_contact_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    evidence_refs: list[str] | None = None,
    issued_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in MARKETPLACE_AUTHOR_MODES:
        raise ValueError(f"mode must be one of {sorted(MARKETPLACE_AUTHOR_MODES)}")
    if author_kind not in MARKETPLACE_AUTHOR_KINDS:
        raise ValueError(f"author_kind must be one of {sorted(MARKETPLACE_AUTHOR_KINDS)}")
    if billing_mode not in MARKETPLACE_BILLING_MODES:
        raise ValueError(f"billing_mode must be one of {sorted(MARKETPLACE_BILLING_MODES)}")
    if not isinstance(revenue_share_bps, int) or revenue_share_bps < 0 or revenue_share_bps > 10000:
        raise ValueError("revenue_share_bps must be an integer between 0 and 10000")
    if billing_mode != "not-claimed":
        for field, value in {
            "billing_account_ref": billing_account_ref,
            "entitlement_policy_ref": entitlement_policy_ref,
            "payout_account_ref": payout_account_ref,
        }.items():
            _require_text(value, field)

    catalog_result = verify_marketplace_catalog(catalog, root=root)
    if not catalog_result.ok:
        raise ValueError("invalid marketplace catalog: " + "; ".join(catalog_result.errors))
    if distribution is not None:
        distribution_result = verify_marketplace_distribution(distribution, catalog=catalog, root=root, key=key)
        if not distribution_result.ok:
            raise ValueError("invalid marketplace distribution: " + "; ".join(distribution_result.errors))

    timestamp = issued_at or utc_now()
    issued = parse_rfc3339(timestamp)
    retention = parse_rfc3339(retention_until)
    if retention <= issued:
        raise ValueError("retention_until must be after issued_at")

    for field, value in {
        "author_name": author_name,
        "author_ref": author_ref,
        "contact_ref": contact_ref,
        "identity_provider": identity_provider,
        "identity_subject": identity_subject,
        "identity_assurance": identity_assurance,
        "onboarding_status": onboarding_status,
        "agreement_ref": agreement_ref,
        "terms_ref": terms_ref,
        "license_ref": license_ref,
        "ip_attestation_ref": ip_attestation_ref,
        "review_ticket_ref": review_ticket_ref,
        "review_policy_ref": review_policy_ref,
        "reviewer_ref": reviewer_ref,
        "reviewer_role": reviewer_role,
        "revocation_policy_ref": revocation_policy_ref,
        "support_contact_ref": support_contact_ref,
        "security_contact_ref": security_contact_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "retention_until": retention_until,
    }.items():
        _require_text(value, field)

    selected_assets = _selected_assets(catalog, asset_ids)
    if not selected_assets:
        raise ValueError("at least one governed marketplace asset is required")

    body = {
        "schema": MARKETPLACE_AUTHOR_SCHEMA,
        "mode": mode,
        "issued_at": timestamp,
        "catalog": _catalog_binding(catalog),
        "distribution": _distribution_binding(distribution) if distribution is not None else None,
        "author": {
            "name": author_name,
            "subject_ref": author_ref,
            "kind": author_kind,
            "organization": author_organization,
            "contact_ref": contact_ref,
        },
        "identity": {
            "provider": identity_provider,
            "subject": identity_subject,
            "assurance": identity_assurance,
            "onboarding_status": onboarding_status,
        },
        "agreements": {
            "agreement_ref": agreement_ref,
            "terms_ref": terms_ref,
            "license_ref": license_ref,
            "ip_attestation_ref": ip_attestation_ref,
        },
        "review": {
            "ticket_ref": review_ticket_ref,
            "policy_ref": review_policy_ref,
            "reviewer_ref": reviewer_ref,
            "reviewer_role": reviewer_role,
            "status": onboarding_status,
        },
        "assets": selected_assets,
        "billing": {
            "mode": billing_mode,
            "billing_account_ref": billing_account_ref,
            "entitlement_policy_ref": entitlement_policy_ref,
            "payout_account": _redacted_ref(payout_account_ref),
            "revenue_share_bps": revenue_share_bps,
            "tax_form_ref": tax_form_ref,
        },
        "operations": {
            "revocation_policy_ref": revocation_policy_ref,
            "support_contact_ref": support_contact_ref,
            "security_contact_ref": security_contact_ref,
            "evidence_refs": sorted(evidence_refs or []),
        },
        "audit_log": {
            "audit_log_ref": audit_log_ref,
            "root": audit_log_root,
            "retention_until": retention_until,
        },
        "source_artifacts": _source_artifacts(catalog, distribution),
        "controls": _controls(
            mode=mode,
            onboarding_status=onboarding_status,
            billing_mode=billing_mode,
            distribution=distribution,
        ),
        "limitations": [
            "This receipt binds a marketplace catalog to recorded author onboarding, review, licensing, entitlement, billing, and audit evidence.",
            "It does not contain raw payout account data, tax documents, marketplace credentials, or customer proof-pack payloads.",
            "Production marketplaces should preserve identity-provider events, signed agreements, review artifacts, entitlement checks, invoices, payout records, tax documents, and revocation events in immutable audit storage.",
        ],
    }
    governance_id = content_hash(body)
    return {
        **body,
        "governance_id": governance_id,
        "signatures": [sign_value({"governance_id": governance_id, "marketplace_author": body}, key)],
    }


def verify_marketplace_author_governance(
    receipt: dict[str, Any],
    *,
    catalog: dict[str, Any] | None = None,
    distribution: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> MarketplaceAuthorVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != MARKETPLACE_AUTHOR_SCHEMA:
        errors.append(f"unsupported marketplace author governance schema: {receipt.get('schema')}")
    body = without_keys(receipt, "governance_id", "signatures")
    if receipt.get("governance_id") != content_hash(body):
        errors.append("governance_id does not match canonical marketplace author body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("marketplace author governance receipt missing signature")
    else:
        signed_value = {"governance_id": receipt.get("governance_id"), "marketplace_author": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("marketplace author governance signature invalid")

    mode = receipt.get("mode")
    if mode not in MARKETPLACE_AUTHOR_MODES:
        errors.append("marketplace author governance mode is unsupported")
    elif mode == "local-reference":
        warnings.append("marketplace author governance is local-reference; hosted marketplace enforcement is not claimed")

    try:
        issued = parse_rfc3339(str(receipt.get("issued_at") or ""))
    except ValueError as exc:
        errors.append(f"marketplace author issued_at invalid: {exc}")
        issued = None

    _verify_author(receipt.get("author"), errors)
    _verify_identity(receipt.get("identity"), mode, errors)
    _verify_agreements(receipt.get("agreements"), errors)
    _verify_review(receipt.get("review"), mode, errors)
    _verify_assets(receipt.get("assets"), errors)
    _verify_billing(receipt.get("billing"), errors)
    _verify_operations(receipt.get("operations"), errors)
    _verify_audit(receipt.get("audit_log"), issued, errors)

    source_artifacts = receipt.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("marketplace author source_artifacts are required")

    if catalog is None:
        warnings.append("source marketplace catalog not supplied; catalog hash was not replayed")
    else:
        catalog_result = verify_marketplace_catalog(catalog, root=root)
        if not catalog_result.ok:
            errors.extend(f"source catalog invalid: {error}" for error in catalog_result.errors)
        warnings.extend(f"source catalog: {warning}" for warning in catalog_result.warnings)
        if receipt.get("catalog") != _catalog_binding(catalog):
            errors.append("marketplace author catalog binding mismatch")
        try:
            expected_assets = _selected_assets(catalog, [asset.get("asset_id") for asset in receipt.get("assets", []) if isinstance(asset, dict) and asset.get("asset_id")])
            if receipt.get("assets") != expected_assets:
                errors.append("marketplace author asset bindings do not match source catalog")
        except ValueError as exc:
            errors.append(str(exc))

    if distribution is None:
        if receipt.get("distribution"):
            warnings.append("source marketplace distribution not supplied; distribution hash was not replayed")
    elif catalog is None:
        errors.append("source catalog is required when source distribution is supplied")
    else:
        distribution_result = verify_marketplace_distribution(distribution, catalog=catalog, root=root, key=key)
        if not distribution_result.ok:
            errors.extend(f"source distribution invalid: {error}" for error in distribution_result.errors)
        warnings.extend(f"source distribution: {warning}" for warning in distribution_result.warnings)
        if receipt.get("distribution") != _distribution_binding(distribution):
            errors.append("marketplace author distribution binding mismatch")

    supplied_sources = _source_artifacts(catalog, distribution)
    if supplied_sources and receipt.get("source_artifacts") != supplied_sources:
        errors.append("marketplace author source_artifacts do not match supplied source artifacts")

    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("marketplace author controls are required")
    _check_no_secret_values(receipt, errors)
    return MarketplaceAuthorVerification(ok=not errors, errors=errors, warnings=warnings)


def append_marketplace_author_governance(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    catalog: dict[str, Any] | None = None,
    distribution: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_marketplace_author_governance(receipt, catalog=catalog, distribution=distribution, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid marketplace author governance: " + "; ".join(result.errors))
    payload = {
        "governance_id": receipt["governance_id"],
        "governance_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "issued_at": receipt.get("issued_at"),
        "catalog": receipt.get("catalog"),
        "distribution": receipt.get("distribution"),
        "author": receipt.get("author"),
        "identity": receipt.get("identity"),
        "review": receipt.get("review"),
        "assets": receipt.get("assets"),
        "billing": receipt.get("billing"),
        "operations": receipt.get("operations"),
        "audit_log": receipt.get("audit_log"),
        "source_artifacts": receipt.get("source_artifacts"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(MARKETPLACE_AUTHOR_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def _catalog_binding(catalog: dict[str, Any]) -> dict[str, Any]:
    assets = catalog.get("assets", [])
    return {
        "catalog_id": catalog.get("catalog_id"),
        "catalog_hash": content_hash(catalog),
        "schema": catalog.get("schema"),
        "publisher": catalog.get("publisher"),
        "status": catalog.get("status"),
        "asset_count": len(assets) if isinstance(assets, list) else 0,
        "aggregate": catalog.get("aggregate"),
    }


def _distribution_binding(distribution: dict[str, Any] | None) -> dict[str, Any] | None:
    if distribution is None:
        return None
    return {
        "distribution_id": distribution.get("distribution_id"),
        "distribution_hash": content_hash(distribution),
        "schema": distribution.get("schema"),
        "distribution_ref": distribution.get("distribution_ref"),
        "channel": distribution.get("channel"),
        "subscriber": distribution.get("subscriber"),
        "asset_count": len(distribution.get("assets", [])) if isinstance(distribution.get("assets"), list) else 0,
    }


def _selected_assets(catalog: dict[str, Any], asset_ids: list[str] | None) -> list[dict[str, Any]]:
    assets = [asset for asset in catalog.get("assets", []) if isinstance(asset, dict)]
    if asset_ids:
        selected = set(asset_ids)
        missing = selected - {asset.get("asset_id") for asset in assets}
        if missing:
            raise ValueError(f"governed marketplace assets not found: {', '.join(sorted(missing))}")
        assets = [asset for asset in assets if asset.get("asset_id") in selected]
    return [
        {
            "asset_id": asset.get("asset_id"),
            "type": asset.get("type"),
            "path": asset.get("path"),
            "id": asset.get("id"),
            "version": asset.get("version"),
            "author": asset.get("author"),
            "publisher": asset.get("publisher"),
            "verticals": asset.get("verticals", []),
            "regulations": asset.get("regulations", []),
            "risk_class": asset.get("risk_class"),
            "content_hash": asset.get("content_hash"),
            "certification": asset.get("certification"),
        }
        for asset in assets
    ]


def _source_artifacts(catalog: dict[str, Any] | None, distribution: dict[str, Any] | None) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if catalog is not None:
        artifacts.append(
            {
                "type": "marketplace-catalog",
                "id": catalog.get("catalog_id"),
                "schema": catalog.get("schema"),
                "hash": content_hash(catalog),
            }
        )
    if distribution is not None:
        artifacts.append(
            {
                "type": "marketplace-distribution",
                "id": distribution.get("distribution_id"),
                "schema": distribution.get("schema"),
                "hash": content_hash(distribution),
            }
        )
    return artifacts


def _controls(*, mode: str, onboarding_status: str, billing_mode: str, distribution: dict[str, Any] | None) -> list[dict[str, str]]:
    author_status = "governed" if onboarding_status == "approved" and mode != "local-reference" else "planned-production"
    return [
        {
            "id": "author-identity-onboarding",
            "status": author_status,
            "description": "Author identity, organization, contact, provider subject, and assurance metadata are bound.",
        },
        {
            "id": "catalog-review-approval",
            "status": author_status,
            "description": "Marketplace review ticket, reviewer, policy reference, and approval state are bound.",
        },
        {
            "id": "licensing-ip-attestation",
            "status": "governed" if onboarding_status == "approved" else "planned-production",
            "description": "Author agreement, marketplace terms, license, and IP attestation references are bound.",
        },
        {
            "id": "entitlement-billing-payout",
            "status": "governed" if billing_mode in {"entitlement-recorded", "billing-ready"} else "planned-production",
            "description": "Billing account, entitlement policy, redacted payout account, revenue share, and tax-form references are bound.",
        },
        {
            "id": "distribution-binding",
            "status": "governed" if distribution is not None else "planned-production",
            "description": "Optional marketplace distribution receipt binding is replayable.",
        },
        {
            "id": "support-security-revocation",
            "status": "governed" if onboarding_status == "approved" else "planned-production",
            "description": "Support contact, security contact, and revocation policy references are bound.",
        },
    ]


def _verify_author(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace author author must be an object")
        return
    for field in ("name", "subject_ref", "kind", "contact_ref"):
        if not value.get(field):
            errors.append(f"marketplace author author.{field} is required")
    if value.get("kind") not in MARKETPLACE_AUTHOR_KINDS:
        errors.append("marketplace author author.kind is unsupported")


def _verify_identity(value: Any, mode: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace author identity must be an object")
        return
    for field in ("provider", "subject", "assurance", "onboarding_status"):
        if not value.get(field):
            errors.append(f"marketplace author identity.{field} is required")
    if mode in {"platform-governed", "partner-governed"} and value.get("onboarding_status") != "approved":
        errors.append("marketplace author identity.onboarding_status must be approved for governed modes")


def _verify_agreements(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace author agreements must be an object")
        return
    for field in ("agreement_ref", "terms_ref", "license_ref", "ip_attestation_ref"):
        if not value.get(field):
            errors.append(f"marketplace author agreements.{field} is required")


def _verify_review(value: Any, mode: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace author review must be an object")
        return
    for field in ("ticket_ref", "policy_ref", "reviewer_ref", "reviewer_role", "status"):
        if not value.get(field):
            errors.append(f"marketplace author review.{field} is required")
    if mode in {"platform-governed", "partner-governed"} and value.get("status") != "approved":
        errors.append("marketplace author review.status must be approved for governed modes")


def _verify_assets(value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append("marketplace author assets are required")
        return
    seen: set[str] = set()
    for asset in value:
        if not isinstance(asset, dict):
            errors.append("marketplace author asset must be an object")
            continue
        asset_id = asset.get("asset_id")
        if not asset_id:
            errors.append("marketplace author asset missing asset_id")
        elif asset_id in seen:
            errors.append(f"duplicate marketplace author asset id: {asset_id}")
        else:
            seen.add(asset_id)
        if asset.get("type") not in SUPPORTED_ASSET_TYPES:
            errors.append(f"unsupported marketplace author asset type: {asset.get('type')}")
        if not asset.get("content_hash"):
            errors.append(f"marketplace author asset {asset_id or asset.get('path')} missing content_hash")


def _verify_billing(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace author billing must be an object")
        return
    mode = value.get("mode")
    if mode not in MARKETPLACE_BILLING_MODES:
        errors.append("marketplace author billing.mode is unsupported")
    revenue_share = value.get("revenue_share_bps")
    if not isinstance(revenue_share, int) or revenue_share < 0 or revenue_share > 10000:
        errors.append("marketplace author billing.revenue_share_bps must be between 0 and 10000")
    if mode in {"entitlement-recorded", "billing-ready"}:
        for field in ("billing_account_ref", "entitlement_policy_ref"):
            if not value.get(field):
                errors.append(f"marketplace author billing.{field} is required for {mode}")
        _verify_redacted_ref(value.get("payout_account"), "marketplace author billing.payout_account", errors)


def _verify_operations(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace author operations must be an object")
        return
    for field in ("revocation_policy_ref", "support_contact_ref", "security_contact_ref"):
        if not value.get(field):
            errors.append(f"marketplace author operations.{field} is required")
    if not isinstance(value.get("evidence_refs", []), list):
        errors.append("marketplace author operations.evidence_refs must be a list")


def _verify_audit(value: Any, issued: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace author audit_log must be an object")
        return
    for field in ("audit_log_ref", "root", "retention_until"):
        if not value.get(field):
            errors.append(f"marketplace author audit_log.{field} is required")
    if value.get("root") and not _is_hash_ref(str(value.get("root"))):
        errors.append("marketplace author audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if issued and retention <= issued:
            errors.append("marketplace author audit_log.retention_until must be after issued_at")
    except ValueError as exc:
        errors.append(f"marketplace author audit_log.retention_until invalid: {exc}")


def _status_summary(controls: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"marketplace author secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())
