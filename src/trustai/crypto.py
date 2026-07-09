from __future__ import annotations

import hmac
import os
from hashlib import sha256
from typing import Any

from .canonical import canonical_bytes

DEFAULT_SIGNING_KEY = "trustai-local-dev-key-change-me"


def signing_key(explicit_key: str | None = None) -> str:
    return explicit_key or os.getenv("TRUSTAI_SIGNING_KEY") or DEFAULT_SIGNING_KEY


def key_id() -> str:
    return os.getenv("TRUSTAI_KEY_ID", "local-dev")


def sign_bytes(data: bytes, key: str | None = None) -> str:
    return hmac.new(signing_key(key).encode("utf-8"), data, sha256).hexdigest()


def sign_value(value: Any, key: str | None = None, provider: str | None = None) -> dict[str, str]:
    return {
        "schema": "trustai.signature/0.1",
        "alg": "HMAC-SHA256",
        "key_id": key_id(),
        "provider": provider or os.getenv("TRUSTAI_SIGNING_PROVIDER", "local-dev"),
        "value": sign_bytes(canonical_bytes(value), key),
    }


def verify_value(value: Any, signature: dict[str, str], key: str | None = None) -> bool:
    if signature.get("alg") != "HMAC-SHA256":
        return False
    expected = sign_bytes(canonical_bytes(value), key)
    return hmac.compare_digest(expected, signature.get("value", ""))
