from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now

IDENTITY_INVENTORY_SCHEMA = "trustai.identity-inventory/0.1"
SUPPORTED_IDENTITY_PROVIDERS = {"okta", "entra", "servicenow"}


def load_identity_inventory(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return identity_payload_to_inventory(value)


def identity_payload_to_inventory(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("identity inventory payload must be an object")
    observed_at = payload.get("observed_at") or payload.get("observedAt") or utc_now()
    records = _records(payload)
    agents = [_identity_record_to_agent(record, default_provider=payload.get("provider")) for record in records]
    if not agents:
        raise ValueError("identity inventory payload did not produce agents")
    return {
        "schema": IDENTITY_INVENTORY_SCHEMA,
        "source": payload.get("source", "identity-provider-export"),
        "observed_at": observed_at,
        "agents": agents,
    }


def _records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("records"), list):
        return [record for record in payload["records"] if isinstance(record, dict)]
    if isinstance(payload.get("agents"), list):
        return [record for record in payload["agents"] if isinstance(record, dict)]
    records: list[dict[str, Any]] = []
    for provider in SUPPORTED_IDENTITY_PROVIDERS:
        value = payload.get(provider)
        if isinstance(value, dict):
            for key in ("records", "agents", "items", "resources", "value"):
                if isinstance(value.get(key), list):
                    records.extend({**record, "provider": provider} for record in value[key] if isinstance(record, dict))
        elif isinstance(value, list):
            records.extend({**record, "provider": provider} for record in value if isinstance(record, dict))
    return records


def _identity_record_to_agent(record: dict[str, Any], default_provider: Any = None) -> dict[str, Any]:
    provider = str(record.get("provider") or record.get("identity_provider") or default_provider or "").lower()
    provider = provider.replace("azure_ad", "entra").replace("microsoft_entra", "entra")
    if provider not in SUPPORTED_IDENTITY_PROVIDERS:
        raise ValueError(f"unsupported identity provider: {provider or 'missing'}")
    if provider == "okta":
        return _okta_agent(record)
    if provider == "entra":
        return _entra_agent(record)
    return _servicenow_agent(record)


def _okta_agent(record: dict[str, Any]) -> dict[str, Any]:
    profile = _dict(record.get("profile"))
    return _agent(
        record,
        provider="okta",
        identity_id=_first(record, "id", "agentId", "client_id"),
        name=_first(profile, "displayName", "name", "label") or _first(record, "displayName", "name", "label"),
        version=_first(profile, "agentVersion", "version", "appVersion") or _first(record, "version"),
        owner=_first(profile, "owner", "ownerTeam", "team") or _first(record, "owner"),
        risk_class=_first(profile, "riskClass", "risk_class") or _first(record, "risk_class", "riskClass"),
        environment=_first(profile, "environment", "env") or _first(record, "environment", "status"),
        governed=_bool(_first(profile, "governed", "trustaiGoverned") or record.get("governed")),
        contract_id=_first(profile, "contractId", "contract_id") or _first(record, "contract_id"),
    )


def _entra_agent(record: dict[str, Any]) -> dict[str, Any]:
    tags = _tags(record.get("tags"))
    owner = _owner(record.get("owners")) or _first(record, "owner", "ownerTeam") or tags.get("owner")
    return _agent(
        record,
        provider="entra",
        identity_id=_first(record, "id", "appId", "servicePrincipalId"),
        name=_first(record, "displayName", "name", "appDisplayName"),
        version=_first(record, "version", "agentVersion") or tags.get("version"),
        owner=owner,
        risk_class=_first(record, "risk_class", "riskClass") or tags.get("risk_class"),
        environment=_first(record, "environment") or tags.get("environment"),
        governed=_bool(record.get("governed") if "governed" in record else tags.get("governed")),
        contract_id=_first(record, "contract_id", "contractId") or tags.get("contract_id"),
    )


def _servicenow_agent(record: dict[str, Any]) -> dict[str, Any]:
    owner = _name_or_value(record.get("owned_by")) or _name_or_value(record.get("assignment_group"))
    return _agent(
        record,
        provider="servicenow",
        identity_id=_first(record, "sys_id", "id", "agent_id"),
        name=_first(record, "name", "display_name", "u_agent_name"),
        version=_first(record, "version", "u_agent_version"),
        owner=owner or _first(record, "owner", "owner_team"),
        risk_class=_first(record, "risk_class", "u_risk_class"),
        environment=_first(record, "environment", "install_status", "u_environment"),
        governed=_bool(_first(record, "governed", "u_governed")),
        contract_id=_first(record, "contract_id", "u_contract_id"),
    )


def _agent(
    record: dict[str, Any],
    *,
    provider: str,
    identity_id: Any,
    name: Any,
    version: Any,
    owner: Any,
    risk_class: Any,
    environment: Any,
    governed: bool,
    contract_id: Any,
) -> dict[str, Any]:
    raw_hash = content_hash(record)
    agent = {
        "name": str(name or identity_id or f"{provider}-agent-{raw_hash[:8]}"),
        "version": str(version or f"identity:{raw_hash[:16]}"),
        "owner": str(owner or "unknown"),
        "risk_class": str(risk_class or "unclassified"),
        "environment": str(environment or "unknown"),
        "governed": governed,
        "source": f"identity:{provider}",
        "identity_provider": provider,
        "identity_id": str(identity_id or raw_hash[:16]),
        "identity_record_hash": raw_hash,
    }
    if contract_id:
        agent["contract_id"] = str(contract_id)
        agent["governed"] = True
    return agent


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if isinstance(mapping, dict) and mapping.get(key) not in (None, ""):
            return mapping[key]
    return None


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _tags(value: Any) -> dict[str, str]:
    tags: dict[str, str] = {}
    if not isinstance(value, list):
        return tags
    for item in value:
        if not isinstance(item, str):
            continue
        if ":" in item:
            key, tag_value = item.split(":", 1)
        elif "=" in item:
            key, tag_value = item.split("=", 1)
        else:
            continue
        tags[key.strip()] = tag_value.strip()
    return tags


def _owner(value: Any) -> str | None:
    if isinstance(value, list) and value:
        return _name_or_value(value[0])
    return _name_or_value(value)


def _name_or_value(value: Any) -> str | None:
    if isinstance(value, dict):
        return _first(value, "displayName", "name", "userPrincipalName", "email", "value")
    if isinstance(value, str) and value:
        return value
    return None
