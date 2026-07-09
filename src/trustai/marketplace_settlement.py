from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .marketplace import verify_marketplace_catalog, verify_marketplace_distribution
from .marketplace_author import verify_marketplace_author_governance

MARKETPLACE_SETTLEMENT_SCHEMA = "trustai.marketplace-settlement/0.1"
MARKETPLACE_SETTLEMENT_ENTRY_TYPE = "marketplace.billing.settlement_recorded"
MARKETPLACE_SETTLEMENT_MODES = {"local-reference", "recorded-provider-response", "provider-settled"}
MARKETPLACE_SETTLEMENT_DECISIONS = {"allowed", "denied"}
MARKETPLACE_INVOICE_STATUSES = {"issued", "paid", "void"}
MARKETPLACE_PAYOUT_STATUSES = {"pending", "paid", "settled", "failed"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential", "idempotency")


@dataclass
class MarketplaceSettlementVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_marketplace_settlement(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("marketplace settlement receipt must contain an object")
    return value


def write_marketplace_settlement(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_marketplace_settlement(
    author_governance: dict[str, Any],
    *,
    catalog: dict[str, Any] | None = None,
    distribution: dict[str, Any] | None = None,
    root: str | Path = ".",
    mode: str = "recorded-provider-response",
    settlement_ref: str | None = None,
    subscriber_ref: str,
    entitlement_check_ref: str,
    entitlement_policy_ref: str | None = None,
    entitlement_decision: str = "allowed",
    entitlement_checked_at: str,
    asset_ids: list[str] | None = None,
    period_start: str,
    period_end: str,
    invoice_ref: str,
    gross_amount_usd: float,
    currency: str = "USD",
    tax_withholding_bps: int = 0,
    invoice_status: str = "issued",
    payout_ref: str,
    payout_provider_ref: str,
    payout_account_ref: str | None = None,
    payout_status: str = "paid",
    payout_executed_at: str,
    payout_trace_ref: str | None = None,
    idempotency_key_ref: str | None = None,
    tax_profile_ref: str,
    tax_jurisdiction: str = "US",
    tax_form_ref: str | None = None,
    tax_document_custody_ref: str,
    tax_document_hash: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    evidence_refs: list[str] | None = None,
    issued_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in MARKETPLACE_SETTLEMENT_MODES:
        raise ValueError(f"mode must be one of {sorted(MARKETPLACE_SETTLEMENT_MODES)}")
    if entitlement_decision not in MARKETPLACE_SETTLEMENT_DECISIONS:
        raise ValueError(f"entitlement_decision must be one of {sorted(MARKETPLACE_SETTLEMENT_DECISIONS)}")
    if invoice_status not in MARKETPLACE_INVOICE_STATUSES:
        raise ValueError(f"invoice_status must be one of {sorted(MARKETPLACE_INVOICE_STATUSES)}")
    if payout_status not in MARKETPLACE_PAYOUT_STATUSES:
        raise ValueError(f"payout_status must be one of {sorted(MARKETPLACE_PAYOUT_STATUSES)}")
    if not isinstance(tax_withholding_bps, int) or tax_withholding_bps < 0 or tax_withholding_bps > 10000:
        raise ValueError("tax_withholding_bps must be an integer between 0 and 10000")
    for field, value in {
        "subscriber_ref": subscriber_ref,
        "entitlement_check_ref": entitlement_check_ref,
        "entitlement_checked_at": entitlement_checked_at,
        "period_start": period_start,
        "period_end": period_end,
        "invoice_ref": invoice_ref,
        "currency": currency,
        "payout_ref": payout_ref,
        "payout_provider_ref": payout_provider_ref,
        "payout_executed_at": payout_executed_at,
        "tax_profile_ref": tax_profile_ref,
        "tax_jurisdiction": tax_jurisdiction,
        "tax_document_custody_ref": tax_document_custody_ref,
        "tax_document_hash": tax_document_hash,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "retention_until": retention_until,
    }.items():
        _require_text(value, field)

    author_result = verify_marketplace_author_governance(
        author_governance,
        catalog=catalog,
        distribution=distribution,
        root=root,
        key=key,
    )
    if not author_result.ok:
        raise ValueError("invalid marketplace author governance: " + "; ".join(author_result.errors))
    billing = author_governance.get("billing", {})
    if billing.get("mode") == "not-claimed":
        raise ValueError("marketplace settlement requires author billing mode to claim entitlement or billing readiness")
    revenue_share_bps = billing.get("revenue_share_bps")
    if not isinstance(revenue_share_bps, int) or revenue_share_bps < 0 or revenue_share_bps > 10000:
        raise ValueError("author governance billing.revenue_share_bps must be between 0 and 10000")

    issued = issued_at or utc_now()
    _validate_time_window(
        issued_at=issued,
        entitlement_checked_at=entitlement_checked_at,
        period_start=period_start,
        period_end=period_end,
        payout_executed_at=payout_executed_at,
        retention_until=retention_until,
    )
    if mode == "provider-settled":
        if entitlement_decision != "allowed":
            raise ValueError("provider-settled marketplace settlement requires allowed entitlement decision")
        if payout_status not in {"paid", "settled"}:
            raise ValueError("provider-settled marketplace settlement requires paid or settled payout status")
        if invoice_status not in {"issued", "paid"}:
            raise ValueError("provider-settled marketplace settlement requires issued or paid invoice status")

    selected_assets = _selected_assets(author_governance, asset_ids)
    if not selected_assets:
        raise ValueError("at least one marketplace asset must be settled")
    entitlement_policy = entitlement_policy_ref or billing.get("entitlement_policy_ref")
    _require_text(entitlement_policy, "entitlement_policy_ref")
    payout_account = payout_account_ref or (billing.get("payout_account") or {}).get("ref")
    _require_text(payout_account, "payout_account_ref")
    tax_form = tax_form_ref or billing.get("tax_form_ref")
    _require_text(tax_form, "tax_form_ref")

    amounts = _settlement_amounts(
        gross_amount_usd=gross_amount_usd,
        revenue_share_bps=revenue_share_bps,
        tax_withholding_bps=tax_withholding_bps,
    )
    body = {
        "schema": MARKETPLACE_SETTLEMENT_SCHEMA,
        "mode": mode,
        "issued_at": issued,
        "settlement": {
            "settlement_ref": settlement_ref or _settlement_ref(author_governance, subscriber_ref, invoice_ref, issued),
            "subscriber_ref": subscriber_ref,
            "period_start": period_start,
            "period_end": period_end,
            "currency": currency,
        },
        "governance": _author_binding(author_governance),
        "entitlement": {
            "check_ref": entitlement_check_ref,
            "policy_ref": entitlement_policy,
            "decision": entitlement_decision,
            "checked_at": entitlement_checked_at,
            "asset_ids": [asset["asset_id"] for asset in selected_assets],
        },
        "invoice": {
            "invoice_ref": invoice_ref,
            "status": invoice_status,
            "gross_amount_usd": amounts["gross_amount_usd"],
            "line_items": _line_items(selected_assets, amounts["gross_amount_usd"]),
        },
        "revenue_share": {
            "author_revenue_share_bps": revenue_share_bps,
            "author_gross_amount_usd": amounts["author_gross_amount_usd"],
            "platform_amount_usd": amounts["platform_amount_usd"],
        },
        "tax": {
            "tax_profile_ref": tax_profile_ref,
            "jurisdiction": tax_jurisdiction,
            "tax_form_ref": tax_form,
            "withholding_bps": tax_withholding_bps,
            "withholding_amount_usd": amounts["tax_withholding_amount_usd"],
            "document_custody_ref": tax_document_custody_ref,
            "document_hash": tax_document_hash,
        },
        "payout": {
            "payout_ref": payout_ref,
            "provider_ref": payout_provider_ref,
            "status": payout_status,
            "executed_at": payout_executed_at,
            "amount_usd": amounts["net_author_amount_usd"],
            "payout_account": _redacted_ref(payout_account),
            "trace_ref": payout_trace_ref,
            "idempotency_key": _redacted_ref(idempotency_key_ref),
        },
        "audit_log": {
            "audit_log_ref": audit_log_ref,
            "root": audit_log_root,
            "retention_until": retention_until,
        },
        "source_artifacts": _source_artifacts(author_governance, catalog, distribution),
        "controls": _controls(
            mode=mode,
            entitlement_decision=entitlement_decision,
            invoice_status=invoice_status,
            payout_status=payout_status,
            tax_document_hash=tax_document_hash,
        ),
        "operations": {
            "evidence_refs": sorted(evidence_refs or []),
        },
        "limitations": [
            "This receipt binds marketplace author governance to entitlement, invoice, payout, tax custody, and settlement audit evidence.",
            "It does not contain raw payout account data, tax documents, provider credentials, or subscriber proof-pack payloads.",
            "Production marketplaces should preserve provider settlement responses, invoices, payout transfer records, entitlement checks, tax documents, and revocation events in immutable audit storage.",
        ],
    }
    settlement_id = content_hash(body)
    return {
        **body,
        "settlement_id": settlement_id,
        "signatures": [sign_value({"settlement_id": settlement_id, "marketplace_settlement": body}, key)],
    }


def verify_marketplace_settlement(
    receipt: dict[str, Any],
    *,
    author_governance: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
    distribution: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> MarketplaceSettlementVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != MARKETPLACE_SETTLEMENT_SCHEMA:
        errors.append(f"unsupported marketplace settlement schema: {receipt.get('schema')}")
    body = without_keys(receipt, "settlement_id", "signatures")
    if receipt.get("settlement_id") != content_hash(body):
        errors.append("settlement_id does not match canonical marketplace settlement body")
    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("marketplace settlement receipt missing signature")
    else:
        signed_value = {"settlement_id": receipt.get("settlement_id"), "marketplace_settlement": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("marketplace settlement signature invalid")

    mode = receipt.get("mode")
    if mode not in MARKETPLACE_SETTLEMENT_MODES:
        errors.append("marketplace settlement mode is unsupported")
    elif mode == "local-reference":
        warnings.append("marketplace settlement is local-reference; live provider settlement is not claimed")

    _verify_settlement(receipt.get("settlement"), errors)
    _verify_entitlement(receipt.get("entitlement"), mode, errors)
    _verify_invoice(receipt.get("invoice"), errors)
    _verify_revenue_share(receipt.get("revenue_share"), errors)
    _verify_tax(receipt.get("tax"), errors)
    _verify_payout(receipt.get("payout"), mode, errors)
    _verify_audit(receipt.get("audit_log"), receipt.get("issued_at"), errors)
    _verify_amounts(receipt, errors)
    _check_no_secret_values(receipt, errors)

    if not isinstance(receipt.get("controls"), list) or not receipt.get("controls"):
        errors.append("marketplace settlement controls are required")
    if not isinstance(receipt.get("source_artifacts"), list) or not receipt.get("source_artifacts"):
        errors.append("marketplace settlement source_artifacts are required")

    if author_governance is None:
        warnings.append("source marketplace author governance not supplied; governance hash was not replayed")
    else:
        author_result = verify_marketplace_author_governance(
            author_governance,
            catalog=catalog,
            distribution=distribution,
            root=root,
            key=key,
        )
        if not author_result.ok:
            errors.extend(f"source author governance invalid: {error}" for error in author_result.errors)
        warnings.extend(f"source author governance: {warning}" for warning in author_result.warnings)
        if receipt.get("governance") != _author_binding(author_governance):
            errors.append("marketplace settlement governance binding mismatch")
        _verify_author_source_binding(receipt, author_governance, errors)

    if catalog is not None:
        catalog_result = verify_marketplace_catalog(catalog, root=root)
        if not catalog_result.ok:
            errors.extend(f"source catalog invalid: {error}" for error in catalog_result.errors)
        warnings.extend(f"source catalog: {warning}" for warning in catalog_result.warnings)
    if distribution is not None:
        if catalog is None:
            errors.append("source catalog is required when source distribution is supplied")
        else:
            distribution_result = verify_marketplace_distribution(distribution, catalog=catalog, root=root, key=key)
            if not distribution_result.ok:
                errors.extend(f"source distribution invalid: {error}" for error in distribution_result.errors)
            warnings.extend(f"source distribution: {warning}" for warning in distribution_result.warnings)

    supplied_sources = _source_artifacts(author_governance, catalog, distribution)
    if supplied_sources and receipt.get("source_artifacts") != supplied_sources:
        errors.append("marketplace settlement source_artifacts do not match supplied source artifacts")
    return MarketplaceSettlementVerification(ok=not errors, errors=errors, warnings=warnings)


def append_marketplace_settlement(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    author_governance: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
    distribution: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_marketplace_settlement(
        receipt,
        author_governance=author_governance,
        catalog=catalog,
        distribution=distribution,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid marketplace settlement: " + "; ".join(result.errors))
    payload = {
        "settlement_id": receipt["settlement_id"],
        "settlement_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "issued_at": receipt.get("issued_at"),
        "settlement": receipt.get("settlement"),
        "governance": receipt.get("governance"),
        "entitlement": receipt.get("entitlement"),
        "invoice": receipt.get("invoice"),
        "revenue_share": receipt.get("revenue_share"),
        "tax": receipt.get("tax"),
        "payout": receipt.get("payout"),
        "audit_log": receipt.get("audit_log"),
        "source_artifacts": receipt.get("source_artifacts"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(MARKETPLACE_SETTLEMENT_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("issued_at"))


def _author_binding(author_governance: dict[str, Any]) -> dict[str, Any]:
    assets = author_governance.get("assets", [])
    return {
        "governance_id": author_governance.get("governance_id"),
        "governance_hash": content_hash(author_governance),
        "schema": author_governance.get("schema"),
        "mode": author_governance.get("mode"),
        "author": author_governance.get("author"),
        "catalog": author_governance.get("catalog"),
        "distribution": author_governance.get("distribution"),
        "billing": author_governance.get("billing"),
        "asset_count": len(assets) if isinstance(assets, list) else 0,
    }


def _source_artifacts(
    author_governance: dict[str, Any] | None,
    catalog: dict[str, Any] | None,
    distribution: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if author_governance is not None:
        artifacts.append(
            {
                "type": "marketplace-author-governance",
                "id": author_governance.get("governance_id"),
                "schema": author_governance.get("schema"),
                "hash": content_hash(author_governance),
            }
        )
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


def _selected_assets(author_governance: dict[str, Any], asset_ids: list[str] | None) -> list[dict[str, Any]]:
    assets = [asset for asset in author_governance.get("assets", []) if isinstance(asset, dict)]
    if asset_ids:
        selected = set(asset_ids)
        missing = selected - {asset.get("asset_id") for asset in assets}
        if missing:
            raise ValueError(f"settlement assets not found in author governance: {', '.join(sorted(missing))}")
        assets = [asset for asset in assets if asset.get("asset_id") in selected]
    return [
        {
            "asset_id": asset.get("asset_id"),
            "type": asset.get("type"),
            "id": asset.get("id"),
            "version": asset.get("version"),
            "content_hash": asset.get("content_hash"),
        }
        for asset in assets
    ]


def _settlement_amounts(*, gross_amount_usd: float, revenue_share_bps: int, tax_withholding_bps: int) -> dict[str, float]:
    gross = _money(gross_amount_usd)
    if gross <= 0:
        raise ValueError("gross_amount_usd must be positive")
    author_gross = _money(gross * revenue_share_bps / 10000)
    platform_amount = _money(gross - author_gross)
    tax_withholding = _money(author_gross * tax_withholding_bps / 10000)
    net_author = _money(author_gross - tax_withholding)
    if net_author < 0:
        raise ValueError("net author payout amount cannot be negative")
    return {
        "gross_amount_usd": gross,
        "author_gross_amount_usd": author_gross,
        "platform_amount_usd": platform_amount,
        "tax_withholding_amount_usd": tax_withholding,
        "net_author_amount_usd": net_author,
    }


def _line_items(assets: list[dict[str, Any]], gross_amount_usd: float) -> list[dict[str, Any]]:
    if not assets:
        return []
    share = _money(gross_amount_usd / len(assets))
    items = []
    allocated = 0.0
    for index, asset in enumerate(assets):
        amount = share if index < len(assets) - 1 else _money(gross_amount_usd - allocated)
        allocated = _money(allocated + amount)
        items.append(
            {
                "asset_id": asset["asset_id"],
                "type": asset.get("type"),
                "amount_usd": amount,
            }
        )
    return items


def _controls(
    *,
    mode: str,
    entitlement_decision: str,
    invoice_status: str,
    payout_status: str,
    tax_document_hash: str,
) -> list[dict[str, str]]:
    live_status = "governed" if mode == "provider-settled" else "recorded-reference"
    return [
        {
            "id": "author-governance-binding",
            "status": "governed",
            "description": "Settlement binds to a signed marketplace author governance receipt.",
        },
        {
            "id": "entitlement-check",
            "status": live_status if entitlement_decision == "allowed" else "blocked",
            "description": "Subscriber entitlement check reference, policy, decision, timestamp, and assets are bound.",
        },
        {
            "id": "invoice-revenue-share",
            "status": live_status if invoice_status in {"issued", "paid"} else "blocked",
            "description": "Invoice amount, line items, author revenue share, platform amount, and tax withholding are deterministic.",
        },
        {
            "id": "payout-execution",
            "status": live_status if payout_status in {"paid", "settled"} else "planned-production",
            "description": "Payout provider, redacted payout account, transfer reference, status, and amount are bound.",
        },
        {
            "id": "tax-document-custody",
            "status": "governed" if _is_hash_ref(tax_document_hash) else "blocked",
            "description": "Tax profile, jurisdiction, form reference, document custody reference, and document hash are bound.",
        },
    ]


def _verify_settlement(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace settlement settlement must be an object")
        return
    for field in ("settlement_ref", "subscriber_ref", "period_start", "period_end", "currency"):
        if not value.get(field):
            errors.append(f"marketplace settlement settlement.{field} is required")
    try:
        if parse_rfc3339(str(value.get("period_end"))) <= parse_rfc3339(str(value.get("period_start"))):
            errors.append("marketplace settlement period_end must be after period_start")
    except ValueError as exc:
        errors.append(f"marketplace settlement period window invalid: {exc}")


def _verify_entitlement(value: Any, mode: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace settlement entitlement must be an object")
        return
    for field in ("check_ref", "policy_ref", "decision", "checked_at"):
        if not value.get(field):
            errors.append(f"marketplace settlement entitlement.{field} is required")
    if value.get("decision") not in MARKETPLACE_SETTLEMENT_DECISIONS:
        errors.append("marketplace settlement entitlement.decision is unsupported")
    if mode == "provider-settled" and value.get("decision") != "allowed":
        errors.append("provider-settled marketplace settlement requires allowed entitlement decision")
    if not isinstance(value.get("asset_ids"), list) or not value.get("asset_ids"):
        errors.append("marketplace settlement entitlement.asset_ids are required")
    try:
        parse_rfc3339(str(value.get("checked_at")))
    except ValueError as exc:
        errors.append(f"marketplace settlement entitlement.checked_at invalid: {exc}")


def _verify_invoice(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace settlement invoice must be an object")
        return
    if not value.get("invoice_ref"):
        errors.append("marketplace settlement invoice.invoice_ref is required")
    if value.get("status") not in MARKETPLACE_INVOICE_STATUSES:
        errors.append("marketplace settlement invoice.status is unsupported")
    if _number(value.get("gross_amount_usd")) <= 0:
        errors.append("marketplace settlement invoice.gross_amount_usd must be positive")
    line_items = value.get("line_items")
    if not isinstance(line_items, list) or not line_items:
        errors.append("marketplace settlement invoice.line_items are required")
    else:
        total = _money(sum(_number(item.get("amount_usd")) for item in line_items if isinstance(item, dict)))
        if total != _money(value.get("gross_amount_usd")):
            errors.append("marketplace settlement invoice line items do not sum to gross amount")


def _verify_revenue_share(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace settlement revenue_share must be an object")
        return
    bps = value.get("author_revenue_share_bps")
    if not isinstance(bps, int) or bps < 0 or bps > 10000:
        errors.append("marketplace settlement revenue_share.author_revenue_share_bps must be between 0 and 10000")
    for field in ("author_gross_amount_usd", "platform_amount_usd"):
        if _number(value.get(field)) < 0:
            errors.append(f"marketplace settlement revenue_share.{field} must be non-negative")


def _verify_tax(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace settlement tax must be an object")
        return
    for field in ("tax_profile_ref", "jurisdiction", "tax_form_ref", "document_custody_ref", "document_hash"):
        if not value.get(field):
            errors.append(f"marketplace settlement tax.{field} is required")
    bps = value.get("withholding_bps")
    if not isinstance(bps, int) or bps < 0 or bps > 10000:
        errors.append("marketplace settlement tax.withholding_bps must be between 0 and 10000")
    if _number(value.get("withholding_amount_usd")) < 0:
        errors.append("marketplace settlement tax.withholding_amount_usd must be non-negative")
    if value.get("document_hash") and not _is_hash_ref(str(value.get("document_hash"))):
        errors.append("marketplace settlement tax.document_hash must be a sha256 reference")


def _verify_payout(value: Any, mode: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace settlement payout must be an object")
        return
    for field in ("payout_ref", "provider_ref", "status", "executed_at", "payout_account"):
        if not value.get(field):
            errors.append(f"marketplace settlement payout.{field} is required")
    if value.get("status") not in MARKETPLACE_PAYOUT_STATUSES:
        errors.append("marketplace settlement payout.status is unsupported")
    if mode == "provider-settled" and value.get("status") not in {"paid", "settled"}:
        errors.append("provider-settled marketplace settlement requires paid or settled payout status")
    if _number(value.get("amount_usd")) < 0:
        errors.append("marketplace settlement payout.amount_usd must be non-negative")
    _verify_redacted_ref(value.get("payout_account"), "marketplace settlement payout.payout_account", errors)
    if value.get("idempotency_key") is not None:
        _verify_redacted_ref(value.get("idempotency_key"), "marketplace settlement payout.idempotency_key", errors)
    try:
        parse_rfc3339(str(value.get("executed_at")))
    except ValueError as exc:
        errors.append(f"marketplace settlement payout.executed_at invalid: {exc}")


def _verify_audit(value: Any, issued_at: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("marketplace settlement audit_log must be an object")
        return
    for field in ("audit_log_ref", "root", "retention_until"):
        if not value.get(field):
            errors.append(f"marketplace settlement audit_log.{field} is required")
    if value.get("root") and not _is_hash_ref(str(value.get("root"))):
        errors.append("marketplace settlement audit_log.root must be a sha256 reference")
    try:
        issued = parse_rfc3339(str(issued_at or ""))
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if retention <= issued:
            errors.append("marketplace settlement audit_log.retention_until must be after issued_at")
    except ValueError as exc:
        errors.append(f"marketplace settlement audit retention invalid: {exc}")


def _verify_amounts(receipt: dict[str, Any], errors: list[str]) -> None:
    invoice = receipt.get("invoice", {}) if isinstance(receipt.get("invoice"), dict) else {}
    revenue_share = receipt.get("revenue_share", {}) if isinstance(receipt.get("revenue_share"), dict) else {}
    tax = receipt.get("tax", {}) if isinstance(receipt.get("tax"), dict) else {}
    payout = receipt.get("payout", {}) if isinstance(receipt.get("payout"), dict) else {}
    bps = revenue_share.get("author_revenue_share_bps")
    tax_bps = tax.get("withholding_bps")
    if not isinstance(bps, int) or not isinstance(tax_bps, int):
        return
    try:
        expected = _settlement_amounts(
            gross_amount_usd=_number(invoice.get("gross_amount_usd")),
            revenue_share_bps=bps,
            tax_withholding_bps=tax_bps,
        )
    except ValueError as exc:
        errors.append(str(exc))
        return
    checks = {
        "revenue_share.author_gross_amount_usd": (revenue_share.get("author_gross_amount_usd"), expected["author_gross_amount_usd"]),
        "revenue_share.platform_amount_usd": (revenue_share.get("platform_amount_usd"), expected["platform_amount_usd"]),
        "tax.withholding_amount_usd": (tax.get("withholding_amount_usd"), expected["tax_withholding_amount_usd"]),
        "payout.amount_usd": (payout.get("amount_usd"), expected["net_author_amount_usd"]),
    }
    for field, (actual, expected_value) in checks.items():
        if _money(actual) != expected_value:
            errors.append(f"marketplace settlement {field} does not match deterministic settlement math")


def _verify_author_source_binding(receipt: dict[str, Any], author_governance: dict[str, Any], errors: list[str]) -> None:
    billing = author_governance.get("billing", {}) if isinstance(author_governance.get("billing"), dict) else {}
    if billing.get("mode") == "not-claimed":
        errors.append("marketplace settlement requires author governance billing mode to claim entitlement or billing readiness")
    if receipt.get("entitlement", {}).get("policy_ref") != billing.get("entitlement_policy_ref"):
        errors.append("marketplace settlement entitlement policy does not match author governance")
    payout_account = receipt.get("payout", {}).get("payout_account")
    if payout_account != billing.get("payout_account"):
        errors.append("marketplace settlement payout account does not match author governance redacted payout account")
    if receipt.get("tax", {}).get("tax_form_ref") != billing.get("tax_form_ref"):
        errors.append("marketplace settlement tax form does not match author governance")
    try:
        source_assets = _selected_assets(author_governance, receipt.get("entitlement", {}).get("asset_ids"))
    except ValueError as exc:
        errors.append(str(exc))
        return
    receipt_asset_ids = receipt.get("entitlement", {}).get("asset_ids", [])
    if [asset["asset_id"] for asset in source_assets] != receipt_asset_ids:
        errors.append("marketplace settlement entitlement assets do not match author governance")


def _validate_time_window(
    *,
    issued_at: str,
    entitlement_checked_at: str,
    period_start: str,
    period_end: str,
    payout_executed_at: str,
    retention_until: str,
) -> None:
    issued = parse_rfc3339(issued_at)
    checked = parse_rfc3339(entitlement_checked_at)
    start = parse_rfc3339(period_start)
    end = parse_rfc3339(period_end)
    payout = parse_rfc3339(payout_executed_at)
    retention = parse_rfc3339(retention_until)
    if end <= start:
        raise ValueError("period_end must be after period_start")
    if checked < start:
        raise ValueError("entitlement_checked_at must be within or after the settlement period")
    if payout < checked:
        raise ValueError("payout_executed_at must be after entitlement_checked_at")
    if issued < payout:
        raise ValueError("issued_at must be at or after payout_executed_at")
    if retention <= issued:
        raise ValueError("retention_until must be after issued_at")


def _settlement_ref(author_governance: dict[str, Any], subscriber_ref: str, invoice_ref: str, issued_at: str) -> str:
    digest = content_hash(
        {
            "governance_id": author_governance.get("governance_id"),
            "subscriber_ref": subscriber_ref,
            "invoice_ref": invoice_ref,
            "issued_at": issued_at,
        }
    )
    return f"marketplace-settlement-{digest[:16]}"


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
                    errors.append(f"marketplace settlement secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _money(value: Any) -> float:
    return round(_number(value) + 0.0, 2)


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())

