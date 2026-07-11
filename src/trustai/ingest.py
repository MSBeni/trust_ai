from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339
from .chain import EvidenceChain

INGEST_ENTRY_TYPE = "otel_genai.event.ingested"
OTLP_SCHEMA_URL = "opentelemetry.otlp.traces/1.0"
_HEX_CHARS = set("0123456789abcdefABCDEF")


def load_events(path: str | Path) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, dict) and "events" in value:
        value = value["events"]
    if not isinstance(value, list):
        raise ValueError("event file must contain a list or an object with an events list")
    return [normalize_event(event) for event in value]


def load_otlp_traces(path: str | Path) -> list[dict[str, Any]]:
    return otlp_traces_to_events(json.loads(Path(path).read_text(encoding="utf-8")))


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    required = ("trace_id", "span_id", "timestamp", "event_name", "agent", "contract_hash")
    missing = [field for field in required if not event.get(field)]
    if missing:
        raise ValueError(f"event missing required fields: {', '.join(missing)}")
    parse_rfc3339(event["timestamp"])
    trace_id = _canonical_hex(event["trace_id"], field="trace_id", length=32)
    span_id = _canonical_hex(event["span_id"], field="span_id", length=16)
    parent_span_id = event.get("parent_span_id")
    if parent_span_id not in (None, ""):
        parent_span_id = _canonical_hex(parent_span_id, field="parent_span_id", length=16)
    contract_hash = _canonical_hex(event["contract_hash"], field="contract_hash", length=64)
    if not isinstance(event["event_name"], str) or not event["event_name"].strip():
        raise ValueError("event.event_name must be a non-empty string")
    agent = event["agent"]
    if not isinstance(agent, dict) or not agent.get("name") or not agent.get("version"):
        raise ValueError("event.agent must include name and version")
    normalized = json.loads(json.dumps(event, sort_keys=True))
    normalized["trace_id"] = trace_id
    normalized["span_id"] = span_id
    if parent_span_id:
        normalized["parent_span_id"] = parent_span_id
    normalized["contract_hash"] = contract_hash
    normalized.setdefault("schema_url", "opentelemetry.semconv.gen_ai/1.0")
    normalized.setdefault("attributes", {})
    return normalized


def _canonical_hex(value: Any, *, field: str, length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"event.{field} must be a {length}-character hexadecimal string")
    if len(value) != length or any(char not in _HEX_CHARS for char in value):
        raise ValueError(f"event.{field} must be a {length}-character hexadecimal string")
    if set(value) <= {"0"}:
        raise ValueError(f"event.{field} must not be all zeros")
    return value.lower()


def _otlp_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        raw = value["intValue"]
        if isinstance(raw, str):
            try:
                return int(raw)
            except ValueError:
                return raw
        return raw
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "bytesValue" in value:
        return value["bytesValue"]
    if "arrayValue" in value:
        return [_otlp_value(item.get("value", item)) for item in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return _otlp_attributes(value["kvlistValue"].get("values", []))
    return value


def _otlp_attributes(attributes: list[dict[str, Any]] | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for attribute in attributes or []:
        key = attribute.get("key")
        if key:
            parsed[key] = _otlp_value(attribute.get("value", {}))
    return parsed


def _otlp_timestamp(value: Any) -> str:
    if value in (None, ""):
        raise ValueError("OTLP span/event missing timestamp")
    nanos = int(value)
    seconds, nanoseconds = divmod(nanos, 1_000_000_000)
    micros = nanoseconds // 1000
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=micros).isoformat().replace("+00:00", "Z")


def _first_attr(*sources: dict[str, Any], names: str) -> Any:
    for source in sources:
        for name in names.split("|"):
            if source.get(name) not in (None, ""):
                return source[name]
    return None


def _without_empty(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "")}


def _otlp_event(
    *,
    resource_attrs: dict[str, Any],
    scope_attrs: dict[str, Any],
    span: dict[str, Any],
    span_attrs: dict[str, Any],
    span_event: dict[str, Any] | None = None,
    schema_url: str | None = None,
) -> dict[str, Any]:
    event_attrs = _otlp_attributes(span_event.get("attributes") if span_event else None)
    combined = {
        **resource_attrs,
        **scope_attrs,
        **span_attrs,
        **event_attrs,
    }
    contract_hash = _first_attr(combined, names="trustai.contract_hash|contract_hash|contract.hash")
    agent_name = _first_attr(combined, names="trustai.agent.name|agent.name|service.name")
    agent_version = _first_attr(combined, names="trustai.agent.version|agent.version|service.version")
    timestamp = _otlp_timestamp(
        span_event.get("timeUnixNano") if span_event else span.get("startTimeUnixNano") or span.get("endTimeUnixNano")
    )
    event_name = span_event.get("name") if span_event else span.get("name")
    attributes = _without_empty(
        {
            **combined,
            "otel.span.name": span.get("name"),
            "otel.span.kind": span.get("kind"),
            "otel.event.name": span_event.get("name") if span_event else None,
            "otel.status.code": span.get("status", {}).get("code"),
        }
    )
    normalized = {
        "trace_id": span.get("traceId"),
        "span_id": span.get("spanId"),
        "parent_span_id": span.get("parentSpanId"),
        "timestamp": timestamp,
        "event_name": event_name,
        "contract_hash": contract_hash,
        "agent": {
            "name": agent_name,
            "version": agent_version,
        },
        "risk_class": _first_attr(combined, names="trustai.risk_class|risk_class|action.risk_class"),
        "schema_url": schema_url or OTLP_SCHEMA_URL,
        "attributes": attributes,
    }
    return normalize_event(_without_empty(normalized))


def otlp_traces_to_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("OTLP payload must be an object")
    events: list[dict[str, Any]] = []
    for resource_span in payload.get("resourceSpans", []):
        resource_attrs = _otlp_attributes(resource_span.get("resource", {}).get("attributes", []))
        resource_schema = resource_span.get("schemaUrl")
        for scope_span in resource_span.get("scopeSpans", []):
            scope = scope_span.get("scope", {})
            scope_attrs = _otlp_attributes(scope.get("attributes", []))
            if scope.get("name"):
                scope_attrs["otel.scope.name"] = scope["name"]
            if scope.get("version"):
                scope_attrs["otel.scope.version"] = scope["version"]
            schema_url = scope_span.get("schemaUrl") or resource_schema or OTLP_SCHEMA_URL
            for span in scope_span.get("spans", []):
                span_attrs = _otlp_attributes(span.get("attributes", []))
                span_events = span.get("events", [])
                if span_events:
                    for span_event in span_events:
                        events.append(
                            _otlp_event(
                                resource_attrs=resource_attrs,
                                scope_attrs=scope_attrs,
                                span=span,
                                span_attrs=span_attrs,
                                span_event=span_event,
                                schema_url=schema_url,
                            )
                        )
                else:
                    events.append(
                        _otlp_event(
                            resource_attrs=resource_attrs,
                            scope_attrs=scope_attrs,
                            span=span,
                            span_attrs=span_attrs,
                            schema_url=schema_url,
                        )
                    )
    if not events:
        raise ValueError("OTLP payload did not contain any spans or span events")
    return events


def append_events(
    chain: EvidenceChain,
    events: list[dict[str, Any]],
    key: str | None = None,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for event in events:
        normalized = normalize_event(event)
        payload = {
            "event_hash": content_hash(normalized),
            "contract_hash": normalized["contract_hash"],
            "trace_id": normalized["trace_id"],
            "span_id": normalized["span_id"],
            "event": normalized,
        }
        entries.append(chain.append(INGEST_ENTRY_TYPE, payload, key=key, timestamp=normalized["timestamp"]))
    return entries


def append_otlp_traces(
    chain: EvidenceChain,
    payload: dict[str, Any],
    key: str | None = None,
) -> list[dict[str, Any]]:
    return append_events(chain, otlp_traces_to_events(payload), key=key)
