from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .provider_webhook import provider_webhook_identity

PROVIDER_WEBHOOK_STORE_SCHEMA = "trustai.provider-webhook-store/0.1"
PROVIDER_WEBHOOK_RECORD_SCHEMA = "trustai.provider-webhook-record/0.1"


def load_provider_webhook_store(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {"schema": PROVIDER_WEBHOOK_STORE_SCHEMA, "webhooks": []}
    value = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("provider webhook store must contain an object")
    if value.get("schema") != PROVIDER_WEBHOOK_STORE_SCHEMA:
        raise ValueError(f"provider webhook store schema must be {PROVIDER_WEBHOOK_STORE_SCHEMA}")
    if not isinstance(value.get("webhooks"), list):
        raise ValueError("provider webhook store webhooks must be a list")
    return value


def write_provider_webhook_store(path: str | Path, store: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(store, indent=2, sort_keys=True), encoding="utf-8")


def find_provider_webhook_record(
    path: str | Path,
    provider: str,
    body: bytes | str,
    headers: dict[str, Any],
    secret: str,
) -> dict[str, Any] | None:
    identity = provider_webhook_identity(provider, body, headers, secret)
    store = load_provider_webhook_store(path)
    for record in store.get("webhooks", []):
        if isinstance(record, dict) and record.get("dedup_key") == identity["dedup_key"]:
            return record
    return None


def store_provider_webhook_record(
    path: str | Path,
    receipt: dict[str, Any],
    entry: dict[str, Any],
    body: bytes | str,
    headers: dict[str, Any],
    secret: str,
    *,
    stored_at: str | None = None,
) -> dict[str, Any]:
    identity = provider_webhook_identity(str(receipt.get("provider") or ""), body, headers, secret)
    payload = receipt.get("payload", {}) if isinstance(receipt.get("payload"), dict) else {}
    webhook = receipt.get("webhook", {}) if isinstance(receipt.get("webhook"), dict) else {}
    if payload.get("sha256") != identity["payload_sha256"]:
        raise ValueError("provider webhook store payload hash does not match receipt")
    if webhook.get("event") != identity["event"]:
        raise ValueError("provider webhook store event does not match receipt")
    if webhook.get("delivery_id") != identity.get("delivery_id"):
        raise ValueError("provider webhook store delivery_id does not match receipt")
    if not receipt.get("receipt_id"):
        raise ValueError("provider webhook store requires receipt_id")
    if not entry.get("entry_id"):
        raise ValueError("provider webhook store requires entry_id")

    record = {
        "schema": PROVIDER_WEBHOOK_RECORD_SCHEMA,
        "dedup_key": identity["dedup_key"],
        "provider": identity["provider"],
        "event": identity["event"],
        "delivery_id": identity.get("delivery_id"),
        "payload_sha256": identity["payload_sha256"],
        "verification_method": identity["verification_method"],
        "verification_value_hash": identity["verification_value_hash"],
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "entry_id": entry["entry_id"],
        "entry_hash": content_hash(entry),
        "first_seen_at": stored_at or receipt.get("received_at") or utc_now(),
    }
    record["record_id"] = content_hash(record)
    store = load_provider_webhook_store(path)
    records = [
        item
        for item in store.get("webhooks", [])
        if isinstance(item, dict) and item.get("dedup_key") != record["dedup_key"]
    ]
    records.append(record)
    store["webhooks"] = records
    write_provider_webhook_store(path, store)
    return record
