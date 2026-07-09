from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .crypto import sign_value, verify_value
from .merkle import inclusion_proof, merkle_root, verify_inclusion
from .timestamping import issue_timestamp_token, verify_timestamp_token

CHAIN_SPEC_VERSION = "trustai.evidence-chain/0.1"


@dataclass
class ChainVerification:
    ok: bool
    errors: list[str]


def entry_core(entry: dict[str, Any]) -> dict[str, Any]:
    return without_keys(entry, "entry_id", "signature", "timestamp_token")


def compute_entry_id(core: dict[str, Any]) -> str:
    return content_hash(core)


def _timestamp_message(entry_id: str, core: dict[str, Any]) -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "entry_timestamp": core.get("timestamp"),
        "payload_hash": core.get("payload_hash"),
    }


def verify_entry(entry: dict[str, Any], key: str | None = None) -> list[str]:
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
        if not verify_timestamp_token(_timestamp_message(entry.get("entry_id", ""), core), timestamp_token, key=key):
            errors.append(f"entry {entry.get('index')} timestamp token invalid")
        signature_payload["timestamp_token"] = timestamp_token

    if not isinstance(signature, dict) or not verify_value(signature_payload, signature, key):
        errors.append(f"entry {entry.get('index')} signature invalid")
    return errors


class EvidenceChain:
    def __init__(self, path: Path, tenant_id: str, entries: list[dict[str, Any]] | None = None):
        self.path = path
        self.tenant_id = tenant_id
        self.entries = entries or []

    @classmethod
    def load(cls, path: str | Path, tenant_id: str = "local") -> "EvidenceChain":
        chain_path = Path(path)
        if not chain_path.exists():
            return cls(chain_path, tenant_id, [])

        data = json.loads(chain_path.read_text(encoding="utf-8"))
        if data.get("spec_version") != CHAIN_SPEC_VERSION:
            raise ValueError(f"unsupported chain spec version: {data.get('spec_version')}")
        return cls(chain_path, data["tenant_id"], data.get("entries", []))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "spec_version": CHAIN_SPEC_VERSION,
            "tenant_id": self.tenant_id,
            "tree": self.tree(),
            "entries": self.entries,
        }
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def tree(self) -> dict[str, Any]:
        ids = [entry["entry_id"] for entry in self.entries]
        return {"size": len(ids), "root": merkle_root(ids)}

    def append(
        self,
        entry_type: str,
        payload: dict[str, Any],
        key: str | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        frozen_payload = json.loads(json.dumps(payload, sort_keys=True))
        previous_entry_id = self.entries[-1]["entry_id"] if self.entries else None
        core = {
            "index": len(self.entries),
            "tenant_id": self.tenant_id,
            "entry_type": entry_type,
            "timestamp": timestamp or utc_now(),
            "previous_entry_id": previous_entry_id,
            "payload_hash": content_hash(frozen_payload),
            "payload": frozen_payload,
        }
        entry_id = compute_entry_id(core)
        timestamp_token = issue_timestamp_token(_timestamp_message(entry_id, core), key=key)
        entry = {
            **core,
            "entry_id": entry_id,
            "timestamp_token": timestamp_token,
            "signature": sign_value(
                {"entry_id": entry_id, "core": core, "timestamp_token": timestamp_token},
                key,
                provider="local-kms",
            ),
        }
        self.entries.append(entry)
        return entry

    def entry_ids(self) -> list[str]:
        return [entry["entry_id"] for entry in self.entries]

    def find_entry(self, entry_id: str) -> dict[str, Any] | None:
        for entry in self.entries:
            if entry.get("entry_id") == entry_id:
                return entry
        return None

    def find_first(self, entry_type: str, payload_key: str, payload_value: Any) -> dict[str, Any] | None:
        for entry in self.entries:
            payload = entry.get("payload", {})
            if entry.get("entry_type") == entry_type and payload.get(payload_key) == payload_value:
                return entry
        return None

    def proof_for(self, entry: dict[str, Any]) -> dict[str, Any]:
        index = entry["index"]
        ids = self.entry_ids()
        tree = self.tree()
        return {
            "entry_id": entry["entry_id"],
            "index": index,
            "tree_size": tree["size"],
            "tree_root": tree["root"],
            "audit_path": inclusion_proof(ids, index),
        }

    def verify_all(self, key: str | None = None) -> ChainVerification:
        errors: list[str] = []
        expected_previous = None
        for expected_index, entry in enumerate(self.entries):
            if entry.get("index") != expected_index:
                errors.append(f"entry index mismatch at position {expected_index}")
            if entry.get("previous_entry_id") != expected_previous:
                errors.append(f"entry {expected_index} previous pointer mismatch")
            errors.extend(verify_entry(entry, key))
            expected_previous = entry.get("entry_id")

        ids = self.entry_ids()
        root = merkle_root(ids)
        for entry in self.entries:
            proof = inclusion_proof(ids, entry["index"])
            if not verify_inclusion(entry["entry_id"], proof, root):
                errors.append(f"entry {entry['index']} inclusion proof failed")
        return ChainVerification(ok=not errors, errors=errors)
