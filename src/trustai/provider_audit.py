from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .delivery import verify_provider_delivery
from .provider_webhook import verify_provider_webhook_receipt

PROVIDER_AUDIT_CORRELATION_SCHEMA = "trustai.provider-audit-correlation/0.1"
PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE = "provider_audit.correlated"


@dataclass
class ProviderAuditCorrelationVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_provider_audit_log(path: str | Path) -> Any:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, (dict, list)):
        raise ValueError("provider audit log must contain an object or array")
    return value


def load_provider_audit_correlation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider audit correlation must contain an object")
    return value


def write_provider_audit_correlation(path: str | Path, correlation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(correlation, indent=2, sort_keys=True), encoding="utf-8")


def build_provider_audit_correlation(
    audit_log: Any,
    *,
    webhook_receipt: dict[str, Any] | None = None,
    delivery_receipt: dict[str, Any] | None = None,
    provider: str | None = None,
    correlated_at: str | None = None,
    audit_log_ref: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    events = _normalize_audit_events(audit_log)
    if not events:
        raise ValueError("provider audit log must contain at least one event")

    sources = _source_summaries(webhook_receipt=webhook_receipt, delivery_receipt=delivery_receipt)
    if not sources:
        raise ValueError("at least one provider webhook or delivery receipt is required")

    normalized_provider = _derive_provider(provider, sources)
    timestamp = correlated_at or utc_now()
    parse_rfc3339(timestamp)

    matches = _correlate_sources(sources, events)
    missing = [source["source_type"] for source in sources if source["source_id"] not in {match["source_id"] for match in matches}]
    if missing:
        raise ValueError("provider audit log did not match source receipts: " + ", ".join(sorted(missing)))

    body = {
        "schema": PROVIDER_AUDIT_CORRELATION_SCHEMA,
        "provider": normalized_provider,
        "correlated_at": timestamp,
        "audit_log_ref": audit_log_ref,
        "audit_log": {
            "hash": content_hash(audit_log),
            "event_count": len(events),
        },
        "source_receipts": sources,
        "matches": matches,
        "limitations": [
            "Correlation is based on a provider audit export supplied to the verifier; hosted provider retrieval is not claimed.",
            "The receipt stores audit event hashes and match criteria, not raw provider audit rows or provider credentials.",
        ],
    }
    correlation_id = content_hash(body)
    return {
        **body,
        "correlation_id": correlation_id,
        "signatures": [sign_value({"correlation_id": correlation_id, "provider_audit_correlation": body}, key)],
    }


def verify_provider_audit_correlation(
    correlation: dict[str, Any],
    *,
    audit_log: Any | None = None,
    webhook_receipt: dict[str, Any] | None = None,
    delivery_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> ProviderAuditCorrelationVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if correlation.get("schema") != PROVIDER_AUDIT_CORRELATION_SCHEMA:
        errors.append(f"unsupported provider audit correlation schema: {correlation.get('schema')}")

    body = without_keys(correlation, "correlation_id", "signatures")
    expected_correlation_id = content_hash(body)
    if correlation.get("correlation_id") != expected_correlation_id:
        errors.append("correlation_id does not match canonical provider audit correlation body")

    signatures = correlation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("provider audit correlation must include at least one signature")
    else:
        signed_value = {
            "correlation_id": correlation.get("correlation_id"),
            "provider_audit_correlation": body,
        }
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("provider audit correlation signature verification failed")

    try:
        parse_rfc3339(str(correlation.get("correlated_at") or ""))
    except ValueError as exc:
        errors.append(f"provider audit correlation correlated_at invalid: {exc}")

    provider = _normalize_provider(correlation.get("provider"))
    if not provider:
        errors.append("provider audit correlation provider is required")

    source_receipts = correlation.get("source_receipts", [])
    if not isinstance(source_receipts, list) or not source_receipts:
        errors.append("provider audit correlation source_receipts must contain at least one receipt summary")
        source_receipts = []

    matches = correlation.get("matches", [])
    if not isinstance(matches, list) or not matches:
        errors.append("provider audit correlation matches must contain at least one match")
        matches = []

    if audit_log is None:
        warnings.append("provider audit log was not supplied; audit log hash and event matches were not replayed")
        events: list[dict[str, Any]] | None = None
    else:
        try:
            events = _normalize_audit_events(audit_log)
        except ValueError as exc:
            errors.append(f"provider audit log invalid: {exc}")
            events = None
        audit_record = correlation.get("audit_log", {})
        if not isinstance(audit_record, dict):
            errors.append("provider audit correlation audit_log must be an object")
            audit_record = {}
        if audit_record.get("hash") != content_hash(audit_log):
            errors.append("provider audit log hash does not match supplied audit log")
        if events is not None and audit_record.get("event_count") != len(events):
            errors.append("provider audit log event_count does not match supplied audit log")
        if events is not None:
            errors.extend(_audit_match_errors(matches, events))

    supplied_sources = _source_summaries(webhook_receipt=webhook_receipt, delivery_receipt=delivery_receipt)
    if not supplied_sources:
        warnings.append("source receipts were not supplied; source receipt hashes and criteria were not replayed")
    else:
        source_type_map = {source["source_type"]: source for source in supplied_sources}
        for source in supplied_sources:
            if source.get("provider") != provider:
                errors.append(f"{source['source_type']} provider does not match correlation provider")
        for expected in supplied_sources:
            actual = _find_source_summary(source_receipts, expected["source_type"])
            if actual is None:
                errors.append(f"correlation is missing {expected['source_type']} source summary")
            elif actual != expected:
                errors.append(f"{expected['source_type']} source summary does not match supplied receipt")
        for actual in source_receipts:
            source_type = actual.get("source_type")
            if source_type not in source_type_map:
                warnings.append(f"{source_type} source receipt was not supplied for replay")

        if webhook_receipt is not None:
            webhook_result = verify_provider_webhook_receipt(webhook_receipt, key=key)
            if not webhook_result.ok:
                errors.extend(f"webhook receipt invalid: {error}" for error in webhook_result.errors)
        if delivery_receipt is not None:
            delivery_result = verify_provider_delivery(delivery_receipt, key=key)
            if not delivery_result.ok:
                errors.extend(f"delivery receipt invalid: {error}" for error in delivery_result.errors)

        if events is not None:
            try:
                expected_matches = _correlate_sources(supplied_sources, events)
            except ValueError as exc:
                errors.append(f"source receipt audit correlation replay failed: {exc}")
            else:
                if matches != expected_matches:
                    errors.append("provider audit correlation matches do not match supplied audit log and source receipts")

    return ProviderAuditCorrelationVerification(ok=not errors, errors=errors, warnings=warnings)


def append_provider_audit_correlation(
    chain: EvidenceChain,
    correlation: dict[str, Any],
    *,
    audit_log: Any | None = None,
    webhook_receipt: dict[str, Any] | None = None,
    delivery_receipt: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_provider_audit_correlation(
        correlation,
        audit_log=audit_log,
        webhook_receipt=webhook_receipt,
        delivery_receipt=delivery_receipt,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid provider audit correlation: " + "; ".join(result.errors))
    payload = {
        "correlation_id": correlation["correlation_id"],
        "correlation_hash": content_hash(correlation),
        "provider": correlation.get("provider"),
        "correlated_at": correlation.get("correlated_at"),
        "audit_log": correlation.get("audit_log"),
        "audit_log_ref": correlation.get("audit_log_ref"),
        "source_receipts": correlation.get("source_receipts"),
        "matches": correlation.get("matches"),
    }
    return chain.append(PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE, payload, key=key, timestamp=correlation.get("correlated_at"))


def _normalize_audit_events(audit_log: Any) -> list[dict[str, Any]]:
    if isinstance(audit_log, list):
        raw_events = audit_log
    elif isinstance(audit_log, dict):
        raw_events = audit_log.get("events") or audit_log.get("audit_events") or audit_log.get("records")
        if raw_events is None:
            raw_events = [audit_log]
    else:
        raise ValueError("provider audit log must contain an object or array")
    if not isinstance(raw_events, list):
        raise ValueError("provider audit log events must be an array")
    events: list[dict[str, Any]] = []
    for event in raw_events:
        if not isinstance(event, dict):
            raise ValueError("provider audit log events must contain objects")
        events.append(event)
    return events


def _source_summaries(
    *,
    webhook_receipt: dict[str, Any] | None = None,
    delivery_receipt: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    if webhook_receipt is not None:
        webhook = webhook_receipt.get("webhook", {}) if isinstance(webhook_receipt.get("webhook"), dict) else {}
        payload = webhook_receipt.get("payload", {}) if isinstance(webhook_receipt.get("payload"), dict) else {}
        sources.append(
            {
                "source_type": "provider_webhook",
                "source_id": webhook_receipt.get("receipt_id"),
                "source_hash": content_hash(webhook_receipt),
                "provider": _normalize_provider(webhook_receipt.get("provider")),
                "received_at": webhook_receipt.get("received_at"),
                "event": webhook.get("event"),
                "delivery_id": webhook.get("delivery_id"),
                "payload_sha256": _normalize_hash(payload.get("sha256")),
            }
        )
    if delivery_receipt is not None:
        request = delivery_receipt.get("request", {}) if isinstance(delivery_receipt.get("request"), dict) else {}
        sources.append(
            {
                "source_type": "provider_delivery",
                "source_id": delivery_receipt.get("delivery_id"),
                "source_hash": content_hash(delivery_receipt),
                "provider": _normalize_provider(delivery_receipt.get("provider")),
                "delivered_at": delivery_receipt.get("delivered_at"),
                "mode": delivery_receipt.get("mode"),
                "payload_hash": _normalize_hash(delivery_receipt.get("payload_hash")),
                "target_url": delivery_receipt.get("target_url"),
                "request": {
                    "method": request.get("method"),
                    "path": request.get("path"),
                    "body_hash": _normalize_hash(request.get("body_hash")),
                },
            }
        )
    return sources


def _derive_provider(provider: str | None, sources: list[dict[str, Any]]) -> str:
    normalized = _normalize_provider(provider)
    source_providers = {_normalize_provider(source.get("provider")) for source in sources if _normalize_provider(source.get("provider"))}
    if normalized:
        if source_providers and source_providers != {normalized}:
            raise ValueError("provider does not match source receipt providers")
        return normalized
    if len(source_providers) == 1:
        return next(iter(source_providers))
    raise ValueError("provider is required when source receipts do not share one provider")


def _correlate_sources(sources: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for source in sources:
        match = _best_event_match(source, events)
        if match is not None:
            matches.append(match)
    return matches


def _best_event_match(source: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidates: list[tuple[int, int, dict[str, Any]]] = []
    for index, event in enumerate(events):
        normalized = _normalize_event(event)
        criteria = _source_event_criteria(source, normalized)
        if criteria is None:
            continue
        candidates.append(
            (
                len([criterion for criterion in criteria if criterion.get("strength") == "strong"]),
                len(criteria),
                {
                    "source_type": source["source_type"],
                    "source_id": source.get("source_id"),
                    "audit_event_index": index,
                    "audit_event_hash": content_hash(event),
                    "criteria": criteria,
                },
            )
        )
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], -item[1], item[2]["audit_event_index"]))
    return candidates[0][2]


def _source_event_criteria(source: dict[str, Any], event: dict[str, Any]) -> list[dict[str, Any]] | None:
    criteria: list[dict[str, Any]] = []
    if not _match_optional(event.get("provider"), source.get("provider")):
        return None
    _add_criterion(criteria, "provider", source.get("provider"), "context")

    if source["source_type"] == "provider_webhook":
        if not _match_optional(event.get("event"), source.get("event")):
            return None
        if event.get("event") and source.get("event"):
            _add_criterion(criteria, "event", source.get("event"), "context")
        strong_fields = (
            ("delivery_id", "delivery_id"),
            ("payload_sha256", "payload_sha256"),
            ("receipt_id", "source_id"),
        )
    elif source["source_type"] == "provider_delivery":
        request = source.get("request", {}) if isinstance(source.get("request"), dict) else {}
        if not _match_optional(event.get("target_url"), source.get("target_url")):
            return None
        if event.get("target_url") and source.get("target_url"):
            _add_criterion(criteria, "target_url", source.get("target_url"), "context")
        if not _match_optional(event.get("request_path"), request.get("path")):
            return None
        if event.get("request_path") and request.get("path"):
            _add_criterion(criteria, "request_path", request.get("path"), "context")
        strong_fields = (
            ("delivery_receipt_id", "source_id"),
            ("payload_hash", "payload_hash"),
            ("request_body_hash", "request.body_hash"),
        )
    else:
        return None

    strong_count = 0
    for event_key, source_key in strong_fields:
        expected = _source_value(source, source_key)
        actual = event.get(event_key)
        if not _match_optional(actual, expected):
            return None
        if actual and expected:
            _add_criterion(criteria, event_key, expected, "strong")
            strong_count += 1
    if strong_count == 0:
        return None
    return criteria


def _audit_match_errors(matches: list[Any], events: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for index, match in enumerate(matches):
        if not isinstance(match, dict):
            errors.append(f"provider audit match {index} must be an object")
            continue
        event_index = match.get("audit_event_index")
        if not isinstance(event_index, int) or event_index < 0 or event_index >= len(events):
            errors.append(f"provider audit match {index} audit_event_index is out of range")
            continue
        if match.get("audit_event_hash") != content_hash(events[event_index]):
            errors.append(f"provider audit match {index} audit_event_hash does not match supplied audit event")
        criteria = match.get("criteria")
        if not isinstance(criteria, list) or not criteria:
            errors.append(f"provider audit match {index} criteria must contain at least one criterion")
    return errors


def _find_source_summary(sources: list[Any], source_type: str) -> dict[str, Any] | None:
    for source in sources:
        if isinstance(source, dict) and source.get("source_type") == source_type:
            return source
    return None


def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": _normalize_provider(_first_value(event, ("provider",), ("provider_name",), ("service",))),
        "event": _first_value(event, ("event",), ("event_type",), ("event_name",), ("hook_event",), ("webhook", "event")),
        "delivery_id": _first_value(
            event,
            ("delivery_id",),
            ("webhook_delivery_id",),
            ("webhook_id",),
            ("x_github_delivery",),
            ("x-github-delivery",),
            ("webhook", "delivery_id"),
        ),
        "receipt_id": _first_value(event, ("receipt_id",), ("webhook_receipt_id",), ("webhook", "receipt_id")),
        "delivery_receipt_id": _first_value(event, ("delivery_receipt_id",), ("provider_delivery_id",), ("delivery", "delivery_id")),
        "payload_sha256": _normalize_hash(
            _first_value(event, ("payload_sha256",), ("payload_hash",), ("body_sha256",), ("payload", "sha256"))
        ),
        "payload_hash": _normalize_hash(_first_value(event, ("provider_payload_hash",), ("delivery", "payload_hash"))),
        "request_body_hash": _normalize_hash(_first_value(event, ("request_body_hash",), ("request", "body_hash"))),
        "target_url": _first_value(event, ("target_url",), ("url",), ("endpoint",), ("request", "target_url")),
        "request_path": _first_value(event, ("request_path",), ("path",), ("request", "path")),
    }


def _first_value(event: dict[str, Any], *paths: tuple[str, ...]) -> str | None:
    for path in paths:
        value: Any = event
        for part in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if value is not None:
            return str(value)
    return None


def _source_value(source: dict[str, Any], path: str) -> str | None:
    value: Any = source
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return str(value) if value is not None else None


def _match_optional(actual: str | None, expected: str | None) -> bool:
    if actual is None or actual == "":
        return True
    if expected is None or expected == "":
        return True
    return actual == expected


def _add_criterion(criteria: list[dict[str, Any]], field: str, value: Any, strength: str) -> None:
    if value is None or value == "":
        return
    criteria.append({"field": field, "value": str(value), "strength": strength})


def _normalize_provider(provider: Any) -> str | None:
    if provider is None:
        return None
    normalized = str(provider).strip().lower()
    return normalized or None


def _normalize_hash(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    for prefix in ("sha256:", "sha256="):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
    return normalized or None
