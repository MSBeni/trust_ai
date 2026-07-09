from __future__ import annotations

import os
from typing import Any

from .canonical import content_hash, utc_now
from .crypto import sign_value, verify_value

TIMESTAMP_TOKEN_SCHEMA = "trustai.timestamp-token/0.1"
DEFAULT_TSA_KEY = "trustai-local-tsa-key-change-me"


def tsa_key(explicit_key: str | None = None) -> str:
    return explicit_key or os.getenv("TRUSTAI_TSA_KEY") or DEFAULT_TSA_KEY


def tsa_id() -> str:
    return os.getenv("TRUSTAI_TSA_ID", "local-tsa")


def issue_timestamp_token(message: Any, key: str | None = None, issued_at: str | None = None) -> dict[str, Any]:
    unsigned = {
        "schema": TIMESTAMP_TOKEN_SCHEMA,
        "tsa_id": tsa_id(),
        "issued_at": issued_at or utc_now(),
        "message_hash": content_hash(message),
    }
    unsigned["serial"] = content_hash(unsigned)
    return {
        **unsigned,
        "signature": sign_value({"timestamp_token": unsigned}, key=tsa_key(key), provider="local-tsa"),
    }


def verify_timestamp_token(message: Any, token: dict[str, Any], key: str | None = None) -> bool:
    if not isinstance(token, dict):
        return False
    if token.get("schema") != TIMESTAMP_TOKEN_SCHEMA:
        return False
    signature = token.get("signature")
    if not isinstance(signature, dict):
        return False
    unsigned = {item: value for item, value in token.items() if item != "signature"}
    expected_serial = content_hash({item: value for item, value in unsigned.items() if item != "serial"})
    if token.get("serial") != expected_serial:
        return False
    if token.get("message_hash") != content_hash(message):
        return False
    return verify_value({"timestamp_token": unsigned}, signature, key=tsa_key(key))
