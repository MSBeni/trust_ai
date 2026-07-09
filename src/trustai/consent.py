from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now
from .chain import EvidenceChain

CONSENT_GRANTED_ENTRY_TYPE = "consent.granted"
CONSENT_REVOKED_ENTRY_TYPE = "consent.revoked"
INSURER_SCOPE = "proof-pack-risk-telemetry"


def load_consent(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("consent file must contain an object")
    validate_consent(value)
    return value


def validate_consent(consent: dict[str, Any]) -> None:
    for field in ("consent_id", "granted_to", "scope", "granted_at"):
        if not consent.get(field):
            raise ValueError(f"consent missing required field: {field}")
    parse_rfc3339(consent["granted_at"])
    if consent.get("expires_at"):
        parse_rfc3339(consent["expires_at"])
    if consent["scope"] != INSURER_SCOPE:
        raise ValueError(f"unsupported consent scope: {consent['scope']}")


def append_consent_grant(
    chain: EvidenceChain,
    consent: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    validate_consent(consent)
    payload = {
        "consent_hash": content_hash(consent),
        "consent": consent,
        "consent_id": consent["consent_id"],
        "scope": consent["scope"],
        "granted_to": consent["granted_to"],
        "pack_ids": consent.get("pack_ids", []),
        "contract_ids": consent.get("contract_ids", []),
        "expires_at": consent.get("expires_at"),
    }
    return chain.append(CONSENT_GRANTED_ENTRY_TYPE, payload, key=key, timestamp=consent["granted_at"])


def append_consent_revocation(
    chain: EvidenceChain,
    consent_id: str,
    reason: str,
    key: str | None = None,
    revoked_at: str | None = None,
) -> dict[str, Any]:
    timestamp = revoked_at or utc_now()
    parse_rfc3339(timestamp)
    payload = {
        "consent_id": consent_id,
        "reason": reason,
        "revoked_at": timestamp,
    }
    return chain.append(CONSENT_REVOKED_ENTRY_TYPE, payload, key=key, timestamp=timestamp)


def consent_status(
    chain: EvidenceChain,
    consent_id: str,
    scope: str = INSURER_SCOPE,
    pack_id: str | None = None,
    contract_id: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now_dt = parse_rfc3339(now) if now else None
    grant_entry = None
    revoke_entry = None
    for entry in chain.entries:
        payload = entry.get("payload", {})
        if payload.get("consent_id") != consent_id:
            continue
        if entry.get("entry_type") == CONSENT_GRANTED_ENTRY_TYPE:
            grant_entry = entry
        elif entry.get("entry_type") == CONSENT_REVOKED_ENTRY_TYPE:
            revoke_entry = entry

    checks: list[dict[str, Any]] = []
    if grant_entry is None:
        return {
            "active": False,
            "reason": "missing consent grant",
            "checks": [{"name": "grant_present", "passed": False}],
        }
    consent = grant_entry["payload"]["consent"]
    checks.append({"name": "grant_present", "passed": True, "entry_id": grant_entry["entry_id"]})

    scope_ok = consent.get("scope") == scope
    checks.append({"name": "scope", "passed": scope_ok, "actual": consent.get("scope"), "expected": scope})

    pack_ids = consent.get("pack_ids") or []
    pack_ok = not pack_id or not pack_ids or pack_id in pack_ids
    checks.append({"name": "pack_id", "passed": pack_ok, "actual": pack_id, "allowed": pack_ids})

    contract_ids = consent.get("contract_ids") or []
    contract_ok = not contract_id or not contract_ids or contract_id in contract_ids
    checks.append({"name": "contract_id", "passed": contract_ok, "actual": contract_id, "allowed": contract_ids})

    expires_at = consent.get("expires_at")
    expiry_ok = True
    if expires_at and now_dt is not None:
        expiry_ok = parse_rfc3339(expires_at) >= now_dt
    checks.append({"name": "expiry", "passed": expiry_ok, "expires_at": expires_at})

    revoked = revoke_entry is not None and (
        grant_entry is None or revoke_entry.get("index", -1) > grant_entry.get("index", -1)
    )
    checks.append(
        {
            "name": "not_revoked",
            "passed": not revoked,
            "revocation_entry_id": revoke_entry.get("entry_id") if revoke_entry else None,
        }
    )

    active = all(check["passed"] for check in checks)
    reason = "active" if active else "consent constraints failed"
    return {
        "active": active,
        "reason": reason,
        "consent_id": consent_id,
        "grant_entry_id": grant_entry["entry_id"],
        "revocation_entry_id": revoke_entry.get("entry_id") if revoke_entry else None,
        "checks": checks,
    }
