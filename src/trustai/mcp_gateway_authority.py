from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .external_evidence import AUTHORITY_KINDS
from .mcp_gateway import MCP_TRANSCRIPT_CHAIN_SCHEMA, build_mcp_transcript_chain

MCP_GATEWAY_AUTHORITY_SCHEMA = "trustai.mcp-gateway-production-authority-dossier/0.1"
MCP_GATEWAY_AUTHORITY_ENTRY_TYPE = "mcp.gateway_authority_recorded"
MCP_GATEWAY_AUTHORITY_MODES = {"local-dossier", "proxy-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {"id": "production-mcp-proxy-worker-fleet", "title": "Continuously operated MCP proxy worker fleet", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "mcp-tool-server-registry", "title": "Production MCP tool-server registry, allowlist, and version inventory", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
    {"id": "mcp-session-authentication", "title": "MCP session authentication, identity propagation, and actor binding", "authority_kinds": ["identity-provider", "provider-api", "hosted-service"]},
    {"id": "tool-call-request-response-replay", "title": "Retained MCP tool-call request and response replay artifacts", "authority_kinds": ["hosted-service", "cloud-object-lock", "customer"]},
    {"id": "immutable-mcp-audit-logs", "title": "Immutable MCP proxy, tool server, and policy audit logs", "authority_kinds": ["hosted-service", "cloud-object-lock", "customer"]},
    {"id": "scheduler-queue-lease-checkpoint", "title": "Production scheduler, queue, lease, checkpoint, cursor, and dead-letter exports", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "policy-and-contract-enforcement", "title": "Runtime policy and verification-contract enforcement at the MCP proxy boundary", "authority_kinds": ["hosted-service", "provider-api", "customer"]},
    {"id": "network-egress-and-tenant-controls", "title": "Tenant isolation, network egress, rate limit, and request signing controls", "authority_kinds": ["hosted-service", "provider-api"]},
    {"id": "credential-custody-and-kms", "title": "MCP proxy credential custody and KMS/HSM enforcement evidence", "authority_kinds": ["kms-hsm", "hosted-service", "provider-api"]},
    {"id": "observability-and-alerting", "title": "Production MCP proxy metrics, alerting, and observability exports", "authority_kinds": ["hosted-service", "provider-api", "cloud-object-lock"]},
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class McpGatewayAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0


def load_mcp_gateway_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("MCP gateway authority dossier must contain an object")
    return value


def write_mcp_gateway_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_mcp_gateway_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError("authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]")
    requirement_id, authority_kind, evidence_ref, evidence_hash, description = [part.strip() for part in parts]
    description_parts = [part.strip() for part in description.split(";")]
    metadata: dict[str, Any] = {}
    allowed_metadata = {"issuer", "subject", "source_uri", "issued_at", "expires_at"}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("authority evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in allowed_metadata:
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


def build_mcp_gateway_authority_dossier(
    transcript_calls: list[dict[str, Any]],
    *,
    mode: str = "proxy-dossier",
    environment: str | None = None,
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in MCP_GATEWAY_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(MCP_GATEWAY_AUTHORITY_MODES)}")
    for value, field in ((dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    records = build_mcp_transcript_chain(transcript_calls)
    if not records:
        raise ValueError("MCP gateway authority requires at least one MCP tool call")
    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    summary = _summary(evidence_items)
    binding = _transcript_binding(transcript_calls, records)
    body: dict[str, Any] = {
        "schema": MCP_GATEWAY_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment or "local",
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "transcript_binding": binding,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "summary": summary,
        "controls": _controls(mode, binding, evidence_items, summary),
        "limitations": [
            "This dossier binds a verified MCP transcript hash chain to an explicit production-authority evidence checklist.",
            "It records authority references, hashes, freshness windows, and missing live-evidence categories for production MCP proxy operation.",
            "It does not claim continuously operated production MCP proxy authority unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    signed_value = {"dossier_id": dossier_id, "mcp_gateway_authority": body}
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value(signed_value, key)]}


def verify_mcp_gateway_authority_dossier(
    dossier: dict[str, Any],
    *,
    transcript_calls: list[dict[str, Any]] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> McpGatewayAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != MCP_GATEWAY_AUTHORITY_SCHEMA:
        errors.append(f"unsupported MCP gateway authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    expected_id = content_hash(body)
    if dossier.get("dossier_id") != expected_id:
        errors.append("dossier_id does not match canonical MCP gateway authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("MCP gateway authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "mcp_gateway_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("MCP gateway authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in MCP_GATEWAY_AUTHORITY_MODES:
        errors.append("MCP gateway authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"MCP gateway authority mode is {mode}; live production MCP proxy authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"MCP gateway authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"MCP gateway authority {field} is required")

    _verify_transcript_binding(dossier.get("transcript_binding"), transcript_calls, errors, warnings)
    _verify_required_authority(dossier.get("required_production_authority"), errors)
    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("MCP gateway authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("MCP gateway authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        freshness_status = _verify_authority_evidence_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh)
        freshness_counts[freshness_status] += 1

    evidence_dicts = [item for item in evidence if isinstance(item, dict)]
    expected_summary = _summary(evidence_dicts)
    if dossier.get("summary") != expected_summary:
        errors.append("MCP gateway authority summary does not match authority evidence")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("MCP gateway authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("MCP gateway authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every MCP gateway authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every MCP gateway authority evidence item to be fresh")
    binding_for_controls = dossier.get("transcript_binding") if isinstance(dossier.get("transcript_binding"), dict) else {}
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("MCP gateway authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), binding_for_controls, evidence_dicts, expected_summary):
        errors.append("MCP gateway authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)

    return McpGatewayAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
    )


def append_mcp_gateway_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    transcript_calls: list[dict[str, Any]],
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    result = verify_mcp_gateway_authority_dossier(
        dossier,
        transcript_calls=transcript_calls,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid MCP gateway authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "transcript_binding": dossier.get("transcript_binding"),
        "summary": dossier.get("summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {
                "requirement_id": item.get("requirement_id"),
                "authority_kind": item.get("authority_kind"),
                "evidence_ref": item.get("evidence_ref"),
                "evidence_hash": item.get("evidence_hash"),
                "evidence_id": item.get("evidence_id"),
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
            }
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(MCP_GATEWAY_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _transcript_binding(calls: list[dict[str, Any]], records: list[dict[str, Any]]) -> dict[str, Any]:
    normalized_calls = [record["tool_call"] for record in records]
    timestamps = [call.get("timestamp") for call in normalized_calls if call.get("timestamp")]
    agents = []
    seen_agents: set[str] = set()
    for call in normalized_calls:
        agent = call.get("agent", {}) if isinstance(call.get("agent"), dict) else {}
        agent_ref = f"{agent.get('name')}@{agent.get('version')}"
        if agent_ref not in seen_agents:
            seen_agents.add(agent_ref)
            agents.append({"name": agent.get("name"), "version": agent.get("version"), "risk_class": call.get("risk_class")})
    return {
        "transcript_schema": MCP_TRANSCRIPT_CHAIN_SCHEMA,
        "transcript_hash": content_hash(normalized_calls),
        "source_transcript_hash": content_hash(calls),
        "call_count": len(records),
        "session_ids": sorted({str(call.get("session_id")) for call in normalized_calls}),
        "tool_names": sorted({str(call.get("tool_name")) for call in normalized_calls}),
        "contract_hashes": sorted({str(call.get("contract_hash")) for call in normalized_calls}),
        "agent_bindings": agents,
        "first_timestamp": min(timestamps) if timestamps else None,
        "last_timestamp": max(timestamps) if timestamps else None,
        "transcript_roots": sorted({str(record.get("transcript_root")) for record in records}),
        "tool_call_records": [
            {
                "sequence": record.get("sequence"),
                "request_id": record["tool_call"].get("request_id"),
                "tool_name": record["tool_call"].get("tool_name"),
                "tool_call_hash": record.get("tool_call_hash"),
                "request_hash": record.get("request_hash"),
                "response_hash": record.get("response_hash"),
                "previous_transcript_node_hash": record.get("previous_transcript_node_hash"),
                "transcript_node_hash": record.get("transcript_node_hash"),
                "transcript_root": record.get("transcript_root"),
            }
            for record in records
        ],
    }


def _verify_transcript_binding(
    binding: Any,
    transcript_calls: list[dict[str, Any]] | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    if not isinstance(binding, dict):
        errors.append("MCP gateway transcript_binding is required")
        return
    required_fields = (
        "transcript_schema",
        "transcript_hash",
        "source_transcript_hash",
        "call_count",
        "session_ids",
        "tool_names",
        "contract_hashes",
        "agent_bindings",
        "first_timestamp",
        "last_timestamp",
        "transcript_roots",
        "tool_call_records",
    )
    for field in required_fields:
        if binding.get(field) in (None, "", []):
            errors.append(f"MCP gateway transcript_binding.{field} is required")
    if binding.get("transcript_schema") != MCP_TRANSCRIPT_CHAIN_SCHEMA:
        errors.append("MCP gateway transcript_binding.transcript_schema is unsupported")
    call_count = binding.get("call_count")
    if not isinstance(call_count, int) or call_count <= 0:
        errors.append("MCP gateway transcript_binding.call_count must be a positive integer")
    records = binding.get("tool_call_records")
    if not isinstance(records, list) or not records:
        errors.append("MCP gateway transcript_binding.tool_call_records must be a non-empty list")
    else:
        if isinstance(call_count, int) and len(records) != call_count:
            errors.append("MCP gateway transcript_binding.tool_call_records count must match call_count")
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                errors.append(f"MCP gateway transcript_binding.tool_call_records[{index}] must be an object")
                continue
            for field in ("sequence", "request_id", "tool_name", "tool_call_hash", "request_hash", "response_hash", "transcript_node_hash", "transcript_root"):
                if record.get(field) in (None, "", []):
                    errors.append(f"MCP gateway transcript_binding.tool_call_records[{index}].{field} is required")
            if index > 0 and record.get("previous_transcript_node_hash") in (None, "", []):
                errors.append(f"MCP gateway transcript_binding.tool_call_records[{index}].previous_transcript_node_hash is required")
    if transcript_calls is None:
        warnings.append("MCP gateway transcript source not supplied; transcript binding hashes were not replayed")
        return
    try:
        records = build_mcp_transcript_chain(transcript_calls)
    except (TypeError, ValueError) as exc:
        errors.append(f"MCP gateway transcript source invalid: {exc}")
        return
    expected = _transcript_binding(transcript_calls, records)
    if binding != expected:
        errors.append("MCP gateway transcript_binding does not match supplied transcript source")


def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported MCP gateway authority requirement: {requirement_id}")
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in requirement["authority_kinds"]:
        raise ValueError(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    built = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description,
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
    now,
    require_fresh: bool,
) -> str:
    try:
        expected = _build_authority_evidence_item(item)
    except ValueError as exc:
        errors.append(f"invalid MCP gateway authority evidence: {exc}")
        return "missing"
    if item != expected:
        errors.append("MCP gateway authority evidence_id does not match evidence body")
    issued_at = item.get("issued_at")
    expires_at = item.get("expires_at")
    if not issued_at or not expires_at:
        if require_fresh:
            errors.append(f"MCP gateway authority evidence {item.get('requirement_id')} freshness metadata missing")
        return "missing"
    issued = parse_rfc3339(str(issued_at))
    expires = parse_rfc3339(str(expires_at))
    if issued > expires:
        errors.append(f"MCP gateway authority evidence {item.get('requirement_id')} issued_at is after expires_at")
        return "stale"
    if now < issued or now > expires:
        message = f"MCP gateway authority evidence {item.get('requirement_id')} is outside its freshness window"
        if require_fresh:
            errors.append(message)
        else:
            warnings.append(message)
        return "stale"
    return "fresh"


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("MCP gateway authority required_production_authority does not match the required checklist")


def _summary(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({item.get("requirement_id") for item in evidence_items if item.get("requirement_id")})
    missing = [req_id for req_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if req_id not in covered]
    return {
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
        "authority_evidence_count": len(evidence_items),
    }


def _controls(mode: str, binding: dict[str, Any], evidence_items: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    freshness = _freshness_summary(evidence_items)
    missing = summary.get("missing_requirement_count", 0)
    production_ready = mode == "production-dossier" and not missing and freshness["missing"] == 0
    return [
        {
            "id": "mcp-transcript-chain-bound",
            "status": "passed" if binding.get("call_count", 0) > 0 and binding.get("transcript_roots") else "failed",
            "detail": "Dossier binds the normalized MCP transcript hash chain, root, request hashes, and response hashes.",
        },
        {
            "id": "authority-evidence-checklist-covered",
            "status": "passed" if not missing else "deferred",
            "detail": f"{summary.get('covered_requirement_count', 0)}/{summary.get('required_requirement_count', 0)} MCP gateway production authority categories are covered.",
        },
        {
            "id": "freshness-windows-tracked",
            "status": "passed" if evidence_items and freshness["missing"] == 0 else "deferred",
            "detail": f"windowed={freshness['windowed']} missing_freshness={freshness['missing']}",
        },
        {
            "id": "production-mode-gated",
            "status": "passed" if production_ready else "deferred",
            "detail": "Production authority is claimed only when every MCP gateway category is covered with timestamped evidence windows.",
        },
        {
            "id": "raw-secret-exclusion",
            "status": "passed",
            "detail": "Dossier stores redacted references, hashes, and roots instead of raw MCP proxy credentials or session tokens.",
        },
    ]


def _freshness_summary(evidence_items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"windowed": 0, "missing": 0}
    for item in evidence_items:
        if item.get("issued_at") and item.get("expires_at"):
            counts["windowed"] += 1
        else:
            counts["missing"] += 1
    return counts


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]):
    value = now or dossier.get("generated_at") or utc_now()
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"freshness reference time invalid: {exc}")
        return parse_rfc3339(utc_now())


def _status_summary(controls: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return summary


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            nested_path = f"{path}.{key_text}"
            if any(marker in key_text.lower() for marker in SECRET_KEY_MARKERS) and not _allowed_secret_reference_key(key_text):
                if isinstance(nested, str) and not _is_redacted_reference(nested):
                    errors.append(f"raw secret-like value is not allowed at {nested_path}")
            _check_no_secret_values(nested, errors, nested_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _check_no_secret_values(nested, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str) -> bool:
    lowered = key.lower()
    return lowered.endswith(("_ref", "_hash", "_root", "_id")) or lowered in {"credential-custody-and-kms"}


def _is_redacted_reference(value: str) -> bool:
    return value.startswith(("env:", "vault:", "kms:", "secret-ref:", "sha256:", "hash:"))


def _require_text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")