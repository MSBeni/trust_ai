from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import EvidenceChain
from .contracts import contract_hash

INCIDENT_ENTRY_TYPE = "incident.recorded"
DEMOTION_ENTRY_TYPE = "promotion_gate.demoted"
ROLLBACK_ENTRY_TYPE = "promotion_gate.rolled_back"


def load_incident(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("incident file must contain an object")
    for field in ("id", "severity", "summary"):
        if not value.get(field):
            raise ValueError(f"incident missing required field: {field}")
    return value


def append_incident(
    chain: EvidenceChain,
    incident: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    timestamp = incident.get("detected_at") or utc_now()
    payload = {
        "incident_hash": content_hash(incident),
        "contract_hash": incident.get("contract_hash"),
        "agent": incident.get("agent", {}),
        "incident": incident,
    }
    return chain.append(INCIDENT_ENTRY_TYPE, payload, key=key, timestamp=timestamp)


def append_demotion(
    chain: EvidenceChain,
    contract: dict[str, Any],
    reason: str,
    triggering_entry_id: str | None = None,
    from_environment: str = "prod",
    to_environment: str = "shadow",
    key: str | None = None,
) -> dict[str, Any]:
    payload = {
        "contract_id": contract["id"],
        "contract_hash": contract_hash(contract),
        "agent": contract["agent"],
        "from_environment": from_environment,
        "to_environment": to_environment,
        "reason": reason,
        "triggering_entry_id": triggering_entry_id,
        "decided_at": utc_now(),
    }
    return chain.append(DEMOTION_ENTRY_TYPE, payload, key=key, timestamp=payload["decided_at"])


def append_rollback(
    chain: EvidenceChain,
    contract: dict[str, Any],
    target_agent_version: str,
    reason: str,
    triggering_entry_id: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    payload = {
        "contract_id": contract["id"],
        "contract_hash": contract_hash(contract),
        "agent": contract["agent"],
        "target_agent_version": target_agent_version,
        "reason": reason,
        "triggering_entry_id": triggering_entry_id,
        "decided_at": utc_now(),
    }
    return chain.append(ROLLBACK_ENTRY_TYPE, payload, key=key, timestamp=payload["decided_at"])
