from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

UNDERWRITING_QUOTE_SCHEMA = "trustai.underwriting-quote/0.1"
UNDERWRITING_QUOTE_ENTRY_TYPE = "insurer.underwriting_quote.issued"
INSURER_TELEMETRY_SCHEMA = "trustai.insurer-risk-telemetry/0.1"


@dataclass
class UnderwritingQuoteVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_underwriting_quote(
    telemetry: dict[str, Any],
    *,
    underwriter: str,
    product: str = "ai-liability",
    coverage_limit_usd: float = 1_000_000,
    base_premium_usd: float = 25_000,
    term_start: str,
    term_end: str,
    expires_at: str,
    quote_ref: str | None = None,
    issued_at: str | None = None,
    mode: str = "local-reference",
    key: str | None = None,
) -> dict[str, Any]:
    issued = issued_at or utc_now()
    _validate_inputs(
        telemetry,
        issued_at=issued,
        expires_at=expires_at,
        term_start=term_start,
        term_end=term_end,
        coverage_limit_usd=coverage_limit_usd,
        base_premium_usd=base_premium_usd,
    )
    telemetry_summary = _telemetry_summary(telemetry)
    discount = _discount_for(telemetry)
    quoted = round(float(base_premium_usd) * (1 - discount), 2)
    body = {
        "schema": UNDERWRITING_QUOTE_SCHEMA,
        "issued_at": issued,
        "expires_at": expires_at,
        "underwriter": {
            "name": underwriter,
            "mode": mode,
            "production_replacement": "credentialed underwriter API response with partner authentication",
        },
        "applicant_risk": telemetry_summary,
        "quote": {
            "quote_ref": quote_ref or _quote_ref(underwriter, telemetry_summary, issued),
            "product": product,
            "currency": "USD",
            "coverage_limit_usd": float(coverage_limit_usd),
            "base_premium_usd": float(base_premium_usd),
            "discount_percent": round(discount * 100, 2),
            "quoted_premium_usd": quoted,
            "term_start": term_start,
            "term_end": term_end,
            "status": "quoted",
            "discount_reason": _discount_reason(telemetry),
        },
        "risk_evidence": {
            "telemetry_hash": content_hash(telemetry),
            "telemetry_schema": telemetry.get("schema"),
            "consent_id": telemetry.get("consent", {}).get("consent_id"),
            "consent_active": telemetry.get("consent", {}).get("status", {}).get("active"),
            "pack_id": telemetry.get("pack_id"),
            "contract_id": telemetry.get("contract_id"),
            "chain_root": telemetry.get("signals", {}).get("chain_root"),
        },
        "controls": _controls(),
        "limitations": [
            "This is a local underwriting quote receipt over consented TrustAI telemetry.",
            "It does not claim live insurer binding authority, admitted-carrier pricing, or partner authentication.",
            "Production deployments should replace the local quote algorithm with signed underwriter API responses and policy-system references.",
        ],
    }
    quote_id = content_hash(body)
    return {
        **body,
        "quote_id": quote_id,
        "signatures": [sign_value({"quote_id": quote_id, "quote": body}, key)],
    }


def verify_underwriting_quote(
    quote: dict[str, Any],
    *,
    telemetry: dict[str, Any] | None = None,
    now: str | None = None,
    key: str | None = None,
) -> UnderwritingQuoteVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if quote.get("schema") != UNDERWRITING_QUOTE_SCHEMA:
        errors.append(f"unsupported underwriting quote schema: {quote.get('schema')}")

    body = without_keys(quote, "quote_id", "signatures")
    expected_quote_id = content_hash(body)
    if quote.get("quote_id") != expected_quote_id:
        errors.append("quote_id does not match canonical quote body")

    signatures = quote.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("underwriting quote missing signature")
    else:
        signed_value = {"quote_id": quote.get("quote_id"), "quote": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("underwriting quote signature invalid")

    try:
        issued_dt = parse_rfc3339(str(quote.get("issued_at")))
        expires_dt = parse_rfc3339(str(quote.get("expires_at")))
        if expires_dt <= issued_dt:
            errors.append("underwriting quote expires_at must be after issued_at")
        if now and parse_rfc3339(now) > expires_dt:
            warnings.append("underwriting quote is expired at verification time")
    except Exception as exc:
        errors.append(f"invalid underwriting quote time window: {exc}")

    quote_terms = quote.get("quote", {})
    _verify_quote_terms(quote_terms, errors)
    evidence = quote.get("risk_evidence", {})
    if evidence.get("telemetry_schema") != INSURER_TELEMETRY_SCHEMA:
        errors.append(f"unsupported risk telemetry schema: {evidence.get('telemetry_schema')}")
    if evidence.get("consent_active") is not True:
        errors.append("underwriting quote requires active consented insurer telemetry")
    if not evidence.get("pack_id"):
        errors.append("underwriting quote risk evidence missing pack_id")

    if telemetry is None:
        warnings.append("source insurer telemetry not supplied; verified quote binding only")
    else:
        _verify_source_telemetry(quote, telemetry, errors)

    return UnderwritingQuoteVerification(ok=not errors, errors=errors, warnings=warnings)


def append_underwriting_quote(
    chain: EvidenceChain,
    quote: dict[str, Any],
    *,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_underwriting_quote(quote, key=key)
    if not result.ok:
        raise ValueError("invalid underwriting quote: " + "; ".join(result.errors))
    payload = {
        "quote_id": quote["quote_id"],
        "quote_hash": content_hash(quote),
        "underwriter": quote.get("underwriter"),
        "applicant_risk": quote.get("applicant_risk"),
        "quote": quote.get("quote"),
        "risk_evidence": quote.get("risk_evidence"),
        "limitations": quote.get("limitations", []),
    }
    return chain.append(UNDERWRITING_QUOTE_ENTRY_TYPE, payload, key=key, timestamp=quote.get("issued_at"))


def load_underwriting_quote(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("underwriting quote must contain an object")
    return value


def write_underwriting_quote(path: str | Path, quote: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(quote, indent=2, sort_keys=True), encoding="utf-8")


def _validate_inputs(
    telemetry: dict[str, Any],
    *,
    issued_at: str,
    expires_at: str,
    term_start: str,
    term_end: str,
    coverage_limit_usd: float,
    base_premium_usd: float,
) -> None:
    if telemetry.get("schema") != INSURER_TELEMETRY_SCHEMA:
        raise ValueError(f"unsupported insurer telemetry schema: {telemetry.get('schema')}")
    if telemetry.get("consent", {}).get("status", {}).get("active") is not True:
        raise ValueError("underwriting quote requires active consented insurer telemetry")
    parse_rfc3339(issued_at)
    parse_rfc3339(expires_at)
    term_start_dt = parse_rfc3339(term_start)
    term_end_dt = parse_rfc3339(term_end)
    if term_end_dt <= term_start_dt:
        raise ValueError("term_end must be after term_start")
    if float(coverage_limit_usd) <= 0:
        raise ValueError("coverage_limit_usd must be positive")
    if float(base_premium_usd) <= 0:
        raise ValueError("base_premium_usd must be positive")


def _telemetry_summary(telemetry: dict[str, Any]) -> dict[str, Any]:
    return {
        "pack_id": telemetry.get("pack_id"),
        "contract_id": telemetry.get("contract_id"),
        "agent": telemetry.get("agent", {}),
        "gate_outcome": telemetry.get("gate_outcome"),
        "risk_score": telemetry.get("risk_score"),
        "risk_tier": telemetry.get("risk_tier"),
        "frameworks": telemetry.get("signals", {}).get("frameworks", []),
    }


def _discount_for(telemetry: dict[str, Any]) -> float:
    score = float(telemetry.get("risk_score", 0))
    tier = str(telemetry.get("risk_tier", "")).lower()
    outcome = telemetry.get("gate_outcome")
    if outcome != "passed":
        return 0.0
    if tier == "low" and score >= 90:
        return 0.15
    if tier == "low":
        return 0.10
    if tier == "medium":
        return 0.05
    return 0.0


def _discount_reason(telemetry: dict[str, Any]) -> str:
    discount = _discount_for(telemetry)
    if discount <= 0:
        return "No premium credit: proof-pack risk telemetry did not meet discount threshold."
    return (
        "Premium credit applied because consented TrustAI telemetry shows a passed gate, "
        f"{telemetry.get('risk_tier')} risk tier, and risk score {telemetry.get('risk_score')}."
    )


def _quote_ref(underwriter: str, telemetry_summary: dict[str, Any], issued_at: str) -> str:
    digest = content_hash({"underwriter": underwriter, "telemetry": telemetry_summary, "issued_at": issued_at})
    return f"trustai-quote-{digest[:16]}"


def _verify_quote_terms(terms: dict[str, Any], errors: list[str]) -> None:
    try:
        base = float(terms.get("base_premium_usd"))
        quoted = float(terms.get("quoted_premium_usd"))
        discount_percent = float(terms.get("discount_percent"))
        coverage = float(terms.get("coverage_limit_usd"))
    except (TypeError, ValueError):
        errors.append("underwriting quote monetary fields must be numeric")
        return
    if base <= 0:
        errors.append("base_premium_usd must be positive")
    if quoted < 0:
        errors.append("quoted_premium_usd must be non-negative")
    if coverage <= 0:
        errors.append("coverage_limit_usd must be positive")
    expected = round(base * (1 - discount_percent / 100), 2)
    if quoted != expected:
        errors.append("quoted_premium_usd does not match base premium and discount")
    try:
        if parse_rfc3339(str(terms.get("term_end"))) <= parse_rfc3339(str(terms.get("term_start"))):
            errors.append("quote term_end must be after term_start")
    except Exception as exc:
        errors.append(f"invalid quote term window: {exc}")


def _verify_source_telemetry(quote: dict[str, Any], telemetry: dict[str, Any], errors: list[str]) -> None:
    if telemetry.get("schema") != INSURER_TELEMETRY_SCHEMA:
        errors.append(f"unsupported source telemetry schema: {telemetry.get('schema')}")
    if telemetry.get("consent", {}).get("status", {}).get("active") is not True:
        errors.append("source telemetry consent is not active")
    evidence = quote.get("risk_evidence", {})
    expected_hash = content_hash(telemetry)
    if evidence.get("telemetry_hash") != expected_hash:
        errors.append("risk evidence telemetry_hash mismatch")
    expected_summary = _telemetry_summary(telemetry)
    if quote.get("applicant_risk") != expected_summary:
        errors.append("applicant_risk does not match source telemetry")
    expected_discount = round(_discount_for(telemetry) * 100, 2)
    if quote.get("quote", {}).get("discount_percent") != expected_discount:
        errors.append("discount_percent does not match source telemetry")


def _controls() -> list[dict[str, str]]:
    return [
        {
            "id": "consented-telemetry-binding",
            "status": "implemented-reference",
            "description": "Quote requires active consented insurer telemetry and records its canonical hash.",
        },
        {
            "id": "premium-discount-rule",
            "status": "implemented-reference",
            "description": "Local deterministic discount schedule is derived from gate outcome, risk tier, and risk score.",
        },
        {
            "id": "underwriter-response-signature",
            "status": "local-reference",
            "description": "Quote is locally signed as a stand-in for a credentialed underwriter API response.",
        },
        {
            "id": "partner-authentication",
            "status": "planned-production",
            "description": "Replace local signing with partner-authenticated underwriter API credentials.",
        },
    ]
