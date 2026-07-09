from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now
from .chain import EvidenceChain

AGENT_INVENTORY_ENTRY_TYPE = "agent.inventory.discovered"
DELEGATION_ENTRY_TYPE = "agent.delegation.evidenced"


def load_inventory(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("inventory file must contain an object")
    agents = value.get("agents")
    if not isinstance(agents, list) or not agents:
        raise ValueError("inventory requires a non-empty agents list")
    return value


def load_delegation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("delegation file must contain an object")
    return normalize_delegation(value)


def normalize_agent(agent: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(agent, dict):
        raise ValueError("agent inventory item must be an object")
    required = ("name", "version", "owner", "risk_class")
    missing = [field for field in required if not agent.get(field)]
    if missing:
        raise ValueError(f"agent missing required fields: {', '.join(missing)}")
    normalized = json.loads(json.dumps(agent, sort_keys=True))
    normalized.setdefault("governed", False)
    normalized.setdefault("source", "manual")
    return normalized


def normalize_delegation(delegation: dict[str, Any]) -> dict[str, Any]:
    required = ("timestamp", "parent_agent", "child_agent", "contract_hash", "reason")
    missing = [field for field in required if not delegation.get(field)]
    if missing:
        raise ValueError(f"delegation missing required fields: {', '.join(missing)}")
    parse_rfc3339(delegation["timestamp"])
    for field in ("parent_agent", "child_agent"):
        agent = delegation[field]
        if not isinstance(agent, dict) or not agent.get("name") or not agent.get("version"):
            raise ValueError(f"{field} must include name and version")
    return json.loads(json.dumps(delegation, sort_keys=True))


def append_inventory(
    chain: EvidenceChain,
    inventory: dict[str, Any],
    key: str | None = None,
) -> list[dict[str, Any]]:
    observed_at = inventory.get("observed_at") or utc_now()
    parse_rfc3339(observed_at)
    entries: list[dict[str, Any]] = []
    for agent in inventory["agents"]:
        normalized = normalize_agent(agent)
        payload = {
            "observed_at": observed_at,
            "source": inventory.get("source", normalized.get("source", "manual")),
            "agent_hash": content_hash(normalized),
            "agent": normalized,
        }
        entries.append(chain.append(AGENT_INVENTORY_ENTRY_TYPE, payload, key=key, timestamp=observed_at))
    return entries


def append_delegation(
    chain: EvidenceChain,
    delegation: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    normalized = normalize_delegation(delegation)
    payload = {
        "contract_hash": normalized["contract_hash"],
        "delegation_hash": content_hash(normalized),
        "delegation": normalized,
    }
    return chain.append(DELEGATION_ENTRY_TYPE, payload, key=key, timestamp=normalized["timestamp"])
