from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import ChainVerification, EvidenceChain, compute_entry_id, entry_core
from .crypto import DEFAULT_SIGNING_KEY, verify_value
from .merkle import inclusion_proof, merkle_root, verify_inclusion
from .timestamping import DEFAULT_TSA_KEY, TIMESTAMP_TOKEN_SCHEMA

KEYRING_SCHEMA = "trustai.keyring/0.1"


@dataclass
class KeyringVerification:
    ok: bool
    errors: list[str]


def local_dev_keyring(tenant_id: str = "local") -> dict[str, Any]:
    return {
        "schema": KEYRING_SCHEMA,
        "tenant_id": tenant_id,
        "keys": [
            {
                "key_id": "local-dev",
                "provider": "local-kms",
                "alg": "HMAC-SHA256",
                "secret": DEFAULT_SIGNING_KEY,
                "status": "active",
                "usages": ["evidence-signing"],
            },
            {
                "key_id": "local-dev",
                "provider": "local-dev",
                "alg": "HMAC-SHA256",
                "secret": DEFAULT_SIGNING_KEY,
                "status": "active",
                "usages": ["artifact-signing"],
            },
            {
                "key_id": "local-dev",
                "provider": "local-tsa",
                "alg": "HMAC-SHA256",
                "secret": DEFAULT_TSA_KEY,
                "status": "active",
                "usages": ["timestamping"],
            },
        ],
    }


def rotate_local_keyring(
    keyring: dict[str, Any],
    *,
    key_id: str,
    secret: str,
    artifact_secret: str | None = None,
    tsa_secret: str | None = None,
    retire_existing: bool = True,
    rotated_at: str | None = None,
) -> dict[str, Any]:
    validate_keyring(keyring)
    if not key_id:
        raise ValueError("key_id is required")
    if not secret:
        raise ValueError("secret is required")
    rotated = json.loads(json.dumps(keyring, sort_keys=True))
    keys = rotated.setdefault("keys", [])
    providers = {"local-kms", "local-dev", "local-tsa"}
    if any(key.get("key_id") == key_id and key.get("provider") in providers for key in keys):
        raise ValueError(f"key_id already exists in local keyring: {key_id}")

    now = rotated_at or utc_now()
    retired: list[dict[str, Any]] = []
    if retire_existing:
        for key in keys:
            if key.get("provider") in providers and key.get("status", "active") == "active":
                key["status"] = "retired"
                key["retired_at"] = now
                retired.append({"key_id": key.get("key_id"), "provider": key.get("provider")})

    keys.extend(
        [
            {
                "key_id": key_id,
                "provider": "local-kms",
                "alg": "HMAC-SHA256",
                "secret": secret,
                "status": "active",
                "activated_at": now,
                "usages": ["evidence-signing"],
            },
            {
                "key_id": key_id,
                "provider": "local-dev",
                "alg": "HMAC-SHA256",
                "secret": artifact_secret or secret,
                "status": "active",
                "activated_at": now,
                "usages": ["artifact-signing"],
            },
            {
                "key_id": key_id,
                "provider": "local-tsa",
                "alg": "HMAC-SHA256",
                "secret": tsa_secret or secret,
                "status": "active",
                "activated_at": now,
                "usages": ["timestamping"],
            },
        ]
    )
    rotated.setdefault("rotations", []).append(
        {
            "rotated_at": now,
            "new_key_id": key_id,
            "retired": retired,
            "providers": sorted(providers),
        }
    )
    validate_keyring(rotated)
    return rotated


def load_keyring(path: str | Path) -> dict[str, Any]:
    keyring = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_keyring(keyring)
    return keyring


def write_keyring(path: str | Path, keyring: dict[str, Any]) -> None:
    validate_keyring(keyring)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(keyring, indent=2, sort_keys=True), encoding="utf-8")


def validate_keyring(keyring: dict[str, Any]) -> None:
    if keyring.get("schema") != KEYRING_SCHEMA:
        raise ValueError(f"unsupported keyring schema: {keyring.get('schema')}")
    keys = keyring.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("keyring must include at least one key")
    seen = set()
    for index, key in enumerate(keys):
        for field in ("key_id", "provider", "alg", "secret"):
            if not key.get(field):
                raise ValueError(f"keys[{index}] missing required field: {field}")
        if key["alg"] != "HMAC-SHA256":
            raise ValueError(f"keys[{index}] unsupported alg: {key['alg']}")
        if key.get("status", "active") not in {"active", "retired", "revoked"}:
            raise ValueError(f"keys[{index}] unsupported status: {key.get('status')}")
        marker = (key["key_id"], key["provider"])
        if marker in seen:
            raise ValueError(f"duplicate key entry for key_id/provider: {marker}")
        seen.add(marker)


def _resolve_key(keyring: dict[str, Any], signature: dict[str, Any]) -> dict[str, Any] | None:
    key_id = signature.get("key_id")
    provider = signature.get("provider")
    for key in keyring.get("keys", []):
        status = key.get("status", "active")
        if key.get("key_id") == key_id and key.get("provider") == provider and status in {"active", "retired"}:
            return key
    return None


def verify_value_with_keyring(value: Any, signature: dict[str, Any], keyring: dict[str, Any]) -> bool:
    if not isinstance(signature, dict):
        return False
    key = _resolve_key(keyring, signature)
    if key is None:
        return False
    return verify_value(value, signature, key=key["secret"])


def _timestamp_message(entry_id: str, core: dict[str, Any]) -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "entry_timestamp": core.get("timestamp"),
        "payload_hash": core.get("payload_hash"),
    }


def verify_timestamp_token_with_keyring(message: Any, token: dict[str, Any], keyring: dict[str, Any]) -> bool:
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
    return verify_value_with_keyring({"timestamp_token": unsigned}, signature, keyring)


def verify_entry_with_keyring(entry: dict[str, Any], keyring: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    core = entry_core(entry)
    expected_entry_id = compute_entry_id(core)
    if entry.get("entry_id") != expected_entry_id:
        errors.append(f"entry {entry.get('index')} id mismatch")

    expected_payload_hash = content_hash(core.get("payload"))
    if core.get("payload_hash") != expected_payload_hash:
        errors.append(f"entry {entry.get('index')} payload hash mismatch")

    timestamp_token = entry.get("timestamp_token")
    signature = entry.get("signature")
    signature_payload: dict[str, Any] = {"entry_id": entry.get("entry_id"), "core": core}
    if timestamp_token is not None:
        if not verify_timestamp_token_with_keyring(_timestamp_message(entry.get("entry_id", ""), core), timestamp_token, keyring):
            errors.append(f"entry {entry.get('index')} timestamp token invalid")
        signature_payload["timestamp_token"] = timestamp_token

    if not isinstance(signature, dict) or not verify_value_with_keyring(signature_payload, signature, keyring):
        errors.append(f"entry {entry.get('index')} signature invalid")
    return errors


def verify_chain_with_keyring(chain: EvidenceChain, keyring: dict[str, Any]) -> ChainVerification:
    errors: list[str] = []
    expected_previous = None
    for expected_index, entry in enumerate(chain.entries):
        if entry.get("index") != expected_index:
            errors.append(f"entry index mismatch at position {expected_index}")
        if entry.get("previous_entry_id") != expected_previous:
            errors.append(f"entry {expected_index} previous pointer mismatch")
        errors.extend(verify_entry_with_keyring(entry, keyring))
        expected_previous = entry.get("entry_id")

    ids = chain.entry_ids()
    root = merkle_root(ids)
    errors.extend(chain.verify_declared_tree_header())
    for entry in chain.entries:
        proof = inclusion_proof(ids, entry["index"])
        if not verify_inclusion(entry["entry_id"], proof, root):
            errors.append(f"entry {entry['index']} inclusion proof failed")
    return ChainVerification(ok=not errors, errors=errors)
