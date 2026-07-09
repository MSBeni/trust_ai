from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .timestamping import issue_timestamp_token, verify_timestamp_token

ANCHOR_ENTRY_TYPE = "chain.anchor.published"
ANCHOR_SCHEMA = "trustai.chain-anchor/0.1"


def build_anchor(chain: EvidenceChain, key: str | None = None) -> dict[str, Any]:
    tree = chain.tree()
    body = {
        "schema": ANCHOR_SCHEMA,
        "tenant_id": chain.tenant_id,
        "tree": tree,
        "published_at": utc_now(),
    }
    body["anchor_id"] = content_hash(body)
    body["timestamp_token"] = issue_timestamp_token(
        {"anchor_id": body["anchor_id"], "tree": tree},
        key=key,
    )
    body["signature"] = sign_value({"anchor": {k: v for k, v in body.items() if k != "signature"}}, key=key)
    return body


def verify_anchor(anchor: dict[str, Any], key: str | None = None) -> list[str]:
    errors: list[str] = []
    if anchor.get("schema") != ANCHOR_SCHEMA:
        errors.append("unsupported anchor schema")
    signature = anchor.get("signature")
    unsigned = {k: v for k, v in anchor.items() if k != "signature"}
    expected_anchor_id = content_hash({k: v for k, v in unsigned.items() if k not in {"anchor_id", "timestamp_token"}})
    if anchor.get("anchor_id") != expected_anchor_id:
        errors.append("anchor_id mismatch")
    if not isinstance(signature, dict) or not verify_value({"anchor": unsigned}, signature, key=key):
        errors.append("anchor signature invalid")
    token = anchor.get("timestamp_token")
    if not isinstance(token, dict) or not verify_timestamp_token(
        {"anchor_id": anchor.get("anchor_id"), "tree": anchor.get("tree")},
        token,
        key=key,
    ):
        errors.append("anchor timestamp token invalid")
    return errors


def append_anchor(chain: EvidenceChain, key: str | None = None) -> dict[str, Any]:
    anchor = build_anchor(chain, key=key)
    return chain.append(ANCHOR_ENTRY_TYPE, anchor, key=key, timestamp=anchor["published_at"])


def write_anchor(path: str | Path, anchor_entry: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(anchor_entry, indent=2, sort_keys=True), encoding="utf-8")
