from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339
from .chain import EvidenceChain
from .contracts import contract_hash

APPROVAL_SCHEMA = "trustai.human-approval/0.1"
APPROVAL_ENTRY_TYPE = "human_approval.granted"


def load_approval(path: str | Path) -> dict[str, Any]:
    return normalize_approval(json.loads(Path(path).read_text(encoding="utf-8")))


def normalize_approval(approval: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(approval, dict):
        raise ValueError("approval must be an object")
    required = ("role", "approver", "approved_at")
    missing = [field for field in required if not approval.get(field)]
    if missing:
        raise ValueError(f"approval missing required fields: {', '.join(missing)}")
    parse_rfc3339(approval["approved_at"])
    normalized = json.loads(json.dumps(approval, sort_keys=True))
    normalized.setdefault("schema", APPROVAL_SCHEMA)
    normalized.setdefault("source", "manual")
    return normalized


def append_approval(
    chain: EvidenceChain,
    contract: dict[str, Any],
    approval: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    normalized = normalize_approval(approval)
    digest = contract_hash(contract)
    payload = {
        "approval_hash": content_hash(normalized),
        "contract_id": contract["id"],
        "contract_hash": digest,
        "agent": contract["agent"],
        "approval": normalized,
    }
    return chain.append(APPROVAL_ENTRY_TYPE, payload, key=key, timestamp=normalized["approved_at"])


def approval_entries_for_contract(entries: list[dict[str, Any]], digest: str) -> list[dict[str, Any]]:
    return [
        entry
        for entry in entries
        if entry.get("entry_type") == APPROVAL_ENTRY_TYPE and entry.get("payload", {}).get("contract_hash") == digest
    ]


def approvals_from_entries(entries: list[dict[str, Any]], digest: str) -> list[dict[str, Any]]:
    approvals: list[dict[str, Any]] = []
    for entry in approval_entries_for_contract(entries, digest):
        approval = entry.get("payload", {}).get("approval")
        if isinstance(approval, dict):
            approvals.append({**approval, "approval_entry_id": entry.get("entry_id")})
    return approvals
