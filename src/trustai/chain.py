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
    def __init__(
        self,
        path: Path,
        tenant_id: str,
        entries: list[dict[str, Any]] | None = None,
        declared_tree: Any | None = None,
        declared_tree_required: bool = False,
    ):
        self.path = path
        self.tenant_id = tenant_id
        self.entries = entries or []
        self.declared_tree = declared_tree
        self._declared_tree_required = declared_tree_required or declared_tree is not None

    @classmethod
    def load(cls, path: str | Path, tenant_id: str = "local") -> "EvidenceChain":
        chain_path = Path(path)
        if not chain_path.exists():
            return cls(chain_path, tenant_id, [])

        data = json.loads(chain_path.read_text(encoding="utf-8"))
        if data.get("spec_version") != CHAIN_SPEC_VERSION:
            raise ValueError(f"unsupported chain spec version: {data.get('spec_version')}")
        return cls(
            chain_path,
            data["tenant_id"],
            data.get("entries", []),
            declared_tree=data.get("tree"),
            declared_tree_required=True,
        )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tree = self.tree()
        data = {
            "spec_version": CHAIN_SPEC_VERSION,
            "tenant_id": self.tenant_id,
            "tree": tree,
            "entries": self.entries,
        }
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        self.declared_tree = tree
        self._declared_tree_required = True

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
        self.declared_tree = None
        self._declared_tree_required = False
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
        tree = self.tree()
        if self.declared_tree is None:
            if self._declared_tree_required:
                errors.append("declared chain tree missing")
        elif not isinstance(self.declared_tree, dict):
            errors.append("declared chain tree must be an object")
        else:
            declared_size = self.declared_tree.get("size")
            declared_root = self.declared_tree.get("root")
            if type(declared_size) is not int or declared_size != tree["size"]:
                errors.append("declared chain tree size mismatch")
            if not isinstance(declared_root, str) or declared_root != tree["root"]:
                errors.append("declared chain tree root mismatch")

        root = tree["root"]
        for entry in self.entries:
            proof = inclusion_proof(ids, entry["index"])
            if not verify_inclusion(entry["entry_id"], proof, root):
                errors.append(f"entry {entry['index']} inclusion proof failed")
        return ChainVerification(ok=not errors, errors=errors)
