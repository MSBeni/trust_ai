from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .anchor import ANCHOR_ENTRY_TYPE, verify_anchor
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain, verify_entry
from .crypto import sign_value, verify_value
from .merkle import merkle_root

ANCHOR_PROVIDER_SCHEMA = "trustai.anchor-provider-receipt/0.1"
ANCHOR_PROVIDER_ENTRY_TYPE = "chain.anchor.provider_published"
ANCHOR_PROVIDER_MODES = {"local-reference", "recorded-public-log", "provider-anchored", "blockchain-anchored"}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class AnchorProviderVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_anchor_provider_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("anchor provider receipt must contain an object")
    return value


def write_anchor_provider_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def build_anchor_provider_receipt(
    anchor_entry: dict[str, Any],
    *,
    source_chain: EvidenceChain | None = None,
    mode: str = "provider-anchored",
    environment: str = "local",
    provider: str,
    endpoint: str,
    publication_ref: str,
    request_hash: str,
    response_status: int,
    response_hash: str,
    public_log_ref: str,
    public_log_root: str,
    public_log_size: int,
    public_log_entry_ref: str,
    inclusion_proof_hash: str | None = None,
    consistency_proof_hash: str | None = None,
    blockchain_network: str | None = None,
    blockchain_tx_ref: str | None = None,
    blockchain_block_ref: str | None = None,
    witness_refs: list[str] | None = None,
    actor_ref: str,
    credential_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    retention_until: str,
    evidence_refs: list[str] | None = None,
    published_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in ANCHOR_PROVIDER_MODES:
        raise ValueError(f"mode must be one of {sorted(ANCHOR_PROVIDER_MODES)}")
    if not isinstance(response_status, int):
        raise ValueError("response_status must be an integer")
    if not isinstance(public_log_size, int) or public_log_size <= 0:
        raise ValueError("public_log_size must be a positive integer")
    for field, value in {
        "provider": provider,
        "endpoint": endpoint,
        "publication_ref": publication_ref,
        "request_hash": request_hash,
        "response_hash": response_hash,
        "public_log_ref": public_log_ref,
        "public_log_root": public_log_root,
        "public_log_entry_ref": public_log_entry_ref,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "retention_until": retention_until,
    }.items():
        _require_text(value, field)
    if mode == "blockchain-anchored" and (not blockchain_network or not blockchain_tx_ref):
        raise ValueError("blockchain-anchored mode requires blockchain_network and blockchain_tx_ref")

    anchor_errors = _anchor_entry_errors(anchor_entry, key=key)
    if anchor_errors:
        raise ValueError("invalid anchor entry: " + "; ".join(anchor_errors))
    if source_chain is not None:
        chain_errors = _source_chain_errors(source_chain, anchor_entry, key=key)
        if chain_errors:
            raise ValueError("invalid source chain: " + "; ".join(chain_errors))

    timestamp = published_at or utc_now()
    parse_rfc3339(timestamp)
    if parse_rfc3339(retention_until) <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after published_at")

    source = _source_record(anchor_entry, source_chain)
    provider_record = {
        "provider": provider,
        "endpoint": endpoint,
        "publication_ref": publication_ref,
        "request_hash": request_hash,
        "response_status": response_status,
        "response_hash": response_hash,
        "accepted": 200 <= response_status < 300,
    }
    public_log = {
        "log_ref": public_log_ref,
        "root": public_log_root,
        "size": public_log_size,
        "entry_ref": public_log_entry_ref,
        "inclusion_proof_hash": inclusion_proof_hash,
        "consistency_proof_hash": consistency_proof_hash,
        "witness_refs": sorted(witness_refs or []),
    }
    blockchain = {
        "network": blockchain_network,
        "transaction_ref": blockchain_tx_ref,
        "block_ref": blockchain_block_ref,
    }
    audit_log = {
        "audit_log_ref": audit_log_ref,
        "root": audit_log_root,
        "retention_until": retention_until,
    }
    operation = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    body: dict[str, Any] = {
        "schema": ANCHOR_PROVIDER_SCHEMA,
        "mode": mode,
        "environment": environment,
        "published_at": timestamp,
        "source": source,
        "provider": provider_record,
        "public_log": public_log,
        "blockchain": blockchain,
        "operation": operation,
        "audit_log": audit_log,
        "source_artifacts": _source_artifacts(anchor_entry, source_chain),
        "controls": _controls(
            mode=mode,
            provider_record=provider_record,
            public_log=public_log,
            blockchain=blockchain,
            audit_log=audit_log,
        ),
        "limitations": [
            "This receipt binds a signed TrustAI chain anchor to recorded external/public anchoring evidence.",
            "It records provider endpoint, request hash, response hash, public-log root, inclusion proof hash, optional blockchain references, audit-log root, and redacted credential references.",
            "It does not contain raw provider credentials, request bodies, response bodies, or customer proof-pack payloads.",
            "Production deployments should preserve provider-native request/response bodies, public-log inclusion proofs, consistency proofs, witness signatures, and immutable audit-log exports.",
        ],
    }
    receipt_id = content_hash(body)
    return {
        **body,
        "receipt_id": receipt_id,
        "signatures": [sign_value({"receipt_id": receipt_id, "anchor_provider": body}, key)],
    }


def verify_anchor_provider_receipt(
    receipt: dict[str, Any],
    anchor_entry: dict[str, Any] | None = None,
    *,
    source_chain: EvidenceChain | None = None,
    key: str | None = None,
) -> AnchorProviderVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != ANCHOR_PROVIDER_SCHEMA:
        errors.append(f"unsupported anchor provider receipt schema: {receipt.get('schema')}")
    body = without_keys(receipt, "receipt_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("receipt_id") != expected_id:
        errors.append("receipt_id does not match canonical anchor provider receipt body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("anchor provider receipt must include at least one signature")
    else:
        signed_value = {"receipt_id": receipt.get("receipt_id"), "anchor_provider": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("anchor provider receipt signature verification failed")

    try:
        published = parse_rfc3339(str(receipt.get("published_at") or ""))
    except ValueError as exc:
        errors.append(f"anchor provider published_at invalid: {exc}")
        published = None

    mode = receipt.get("mode")
    if mode not in ANCHOR_PROVIDER_MODES:
        errors.append("anchor provider mode is unsupported")
    elif mode != "provider-anchored":
        warnings.append(f"anchor provider mode is {mode}; live provider anchoring is not fully claimed")

    source = receipt.get("source", {})
    _verify_source(source, errors)
    provider = receipt.get("provider", {})
    _verify_provider(provider, mode, errors, warnings)
    public_log = receipt.get("public_log", {})
    _verify_public_log(public_log, errors)
    blockchain = receipt.get("blockchain", {})
    _verify_blockchain(blockchain, mode, errors)
    _verify_operation(receipt.get("operation"), errors)
    _verify_audit_log(receipt.get("audit_log"), published, errors)

    controls = receipt.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("anchor provider controls are required")
    source_artifacts = receipt.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or not source_artifacts:
        errors.append("anchor provider source_artifacts must contain anchor source")

    supplied_sources = _source_artifacts(anchor_entry, source_chain)
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("anchor provider source_artifacts do not match supplied source artifacts")
        expected_source = _source_record(anchor_entry, source_chain)
        if receipt.get("source") != expected_source:
            errors.append("anchor provider source record does not match supplied artifacts")

    if anchor_entry is not None:
        anchor_errors = _anchor_entry_errors(anchor_entry, key=key)
        errors.extend(f"anchor entry invalid: {error}" for error in anchor_errors)
        if source_chain is not None:
            chain_errors = _source_chain_errors(source_chain, anchor_entry, key=key)
            errors.extend(f"source chain invalid: {error}" for error in chain_errors)
    else:
        warnings.append("anchor entry was not supplied; anchor payload signature was not replayed")

    if source_chain is None and source.get("source_chain_hash"):
        warnings.append("source chain was not supplied; anchor entry inclusion in source chain was not replayed")

    _check_no_secret_values(receipt, errors)
    return AnchorProviderVerification(ok=not errors, errors=errors, warnings=warnings)


def append_anchor_provider_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    anchor_entry: dict[str, Any] | None = None,
    *,
    source_chain: EvidenceChain | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_anchor_provider_receipt(receipt, anchor_entry, source_chain=source_chain, key=key)
    if not result.ok:
        raise ValueError("invalid anchor provider receipt: " + "; ".join(result.errors))
    payload = {
        "receipt_id": receipt["receipt_id"],
        "receipt_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "environment": receipt.get("environment"),
        "published_at": receipt.get("published_at"),
        "source": receipt.get("source"),
        "provider": receipt.get("provider"),
        "public_log": receipt.get("public_log"),
        "blockchain": receipt.get("blockchain"),
        "operation": receipt.get("operation"),
        "audit_log": receipt.get("audit_log"),
        "source_artifacts": receipt.get("source_artifacts"),
        "control_summary": _status_summary(receipt.get("controls", [])),
    }
    return chain.append(ANCHOR_PROVIDER_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("published_at"))


def _anchor_entry_errors(anchor_entry: dict[str, Any], *, key: str | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(anchor_entry, dict):
        return ["anchor entry must be an object"]
    if anchor_entry.get("entry_type") != ANCHOR_ENTRY_TYPE:
        errors.append("anchor entry_type must be chain.anchor.published")
    errors.extend(verify_entry(anchor_entry, key=key))
    payload = anchor_entry.get("payload", {})
    if not isinstance(payload, dict):
        errors.append("anchor entry payload must be an object")
    else:
        errors.extend(f"payload {error}" for error in verify_anchor(payload, key=key))
    return errors


def _source_chain_errors(source_chain: EvidenceChain, anchor_entry: dict[str, Any], *, key: str | None = None) -> list[str]:
    errors: list[str] = []
    result = source_chain.verify_all(key=key)
    errors.extend(result.errors)
    anchor_id = anchor_entry.get("entry_id")
    found = source_chain.find_entry(anchor_id) if anchor_id else None
    if found is None:
        errors.append("anchor entry is not present in supplied source chain")
    elif content_hash(found) != content_hash(anchor_entry):
        errors.append("anchor entry does not match supplied source chain entry")
    payload = anchor_entry.get("payload", {})
    if isinstance(payload, dict):
        anchor_index = anchor_entry.get("index")
        if not isinstance(anchor_index, int):
            errors.append("anchor entry index must be an integer")
            return errors
        anchored_ids = source_chain.entry_ids()[:anchor_index]
        source_tree = {"size": len(anchored_ids), "root": merkle_root(anchored_ids)}
        anchor_tree = payload.get("tree", {})
        if anchor_tree != source_tree:
            errors.append("anchor payload tree does not match supplied source chain prefix tree")
    return errors


def _source_record(anchor_entry: dict[str, Any] | None, source_chain: EvidenceChain | None) -> dict[str, Any]:
    payload = anchor_entry.get("payload", {}) if isinstance(anchor_entry, dict) else {}
    anchor_tree = payload.get("tree", {}) if isinstance(payload, dict) else {}
    source_tree = source_chain.tree() if source_chain is not None else None
    return {
        "anchor_entry_id": anchor_entry.get("entry_id") if isinstance(anchor_entry, dict) else None,
        "anchor_entry_hash": content_hash(anchor_entry) if isinstance(anchor_entry, dict) else None,
        "anchor_id": payload.get("anchor_id") if isinstance(payload, dict) else None,
        "anchor_tenant_id": payload.get("tenant_id") if isinstance(payload, dict) else None,
        "anchor_tree_root": anchor_tree.get("root") if isinstance(anchor_tree, dict) else None,
        "anchor_tree_size": anchor_tree.get("size") if isinstance(anchor_tree, dict) else None,
        "anchor_published_at": payload.get("published_at") if isinstance(payload, dict) else None,
        "source_chain_hash": content_hash({"tenant_id": source_chain.tenant_id, "tree": source_tree, "entries": source_chain.entries}) if source_chain is not None else None,
        "source_chain_tree_root": source_tree.get("root") if isinstance(source_tree, dict) else None,
        "source_chain_tree_size": source_tree.get("size") if isinstance(source_tree, dict) else None,
    }


def _source_artifacts(anchor_entry: dict[str, Any] | None, source_chain: EvidenceChain | None) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if isinstance(anchor_entry, dict):
        payload = anchor_entry.get("payload", {}) if isinstance(anchor_entry.get("payload"), dict) else {}
        artifacts.append(
            {
                "type": "chain-anchor-entry",
                "id": anchor_entry.get("entry_id"),
                "schema": payload.get("schema"),
                "hash": content_hash(anchor_entry),
            }
        )
    if source_chain is not None:
        artifacts.append(
            {
                "type": "source-evidence-chain",
                "id": source_chain.tenant_id,
                "schema": "trustai.evidence-chain/0.1",
                "hash": content_hash({"tenant_id": source_chain.tenant_id, "tree": source_chain.tree(), "entries": source_chain.entries}),
            }
        )
    return artifacts


def _controls(
    *,
    mode: str,
    provider_record: dict[str, Any],
    public_log: dict[str, Any],
    blockchain: dict[str, Any],
    audit_log: dict[str, Any],
) -> list[dict[str, str]]:
    return [
        {
            "id": "source-anchor-binding",
            "status": "provider-anchored",
            "description": "Signed TrustAI anchor entry and optional source evidence chain are bound by canonical hash.",
        },
        {
            "id": "external-provider-publication",
            "status": "provider-anchored" if provider_record.get("accepted") and _is_https(provider_record.get("endpoint")) else "planned-production",
            "description": "Provider endpoint, publication reference, request hash, response status, and response hash are bound.",
        },
        {
            "id": "public-log-inclusion",
            "status": "provider-anchored" if public_log.get("entry_ref") and public_log.get("inclusion_proof_hash") else "planned-production",
            "description": "Public log root, size, entry reference, inclusion proof hash, and optional consistency proof hash are bound.",
        },
        {
            "id": "witness-or-blockchain-cross-anchor",
            "status": "provider-anchored" if public_log.get("witness_refs") or (blockchain.get("network") and blockchain.get("transaction_ref")) else "planned-production",
            "description": "Optional witness references or blockchain transaction references are bound.",
        },
        {
            "id": "anchor-provider-audit-retention",
            "status": "provider-anchored" if audit_log.get("root") else "planned-production",
            "description": "Provider anchoring audit-log root and retention timestamp are bound.",
        },
        {
            "id": "provider-mode",
            "status": "provider-anchored" if mode == "provider-anchored" else "planned-production",
            "description": "Receipt mode records whether this is local reference evidence or a provider-anchored publication record.",
        },
    ]


def _verify_source(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("anchor provider source must be an object")
        return
    for field in ("anchor_entry_id", "anchor_entry_hash", "anchor_id", "anchor_tenant_id", "anchor_tree_root", "anchor_tree_size", "anchor_published_at"):
        if value.get(field) in (None, ""):
            errors.append(f"anchor provider source.{field} is required")


def _verify_provider(value: Any, mode: str | None, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("anchor provider provider must be an object")
        return
    for field in ("provider", "endpoint", "publication_ref", "request_hash", "response_status", "response_hash"):
        if value.get(field) in (None, ""):
            errors.append(f"anchor provider provider.{field} is required")
    if value.get("endpoint") and not _is_https(value.get("endpoint")):
        errors.append("anchor provider provider.endpoint must be https")
    for field in ("request_hash", "response_hash"):
        if value.get(field) and not _is_hash_ref(str(value.get(field))):
            errors.append(f"anchor provider provider.{field} must be a sha256 reference")
    status = value.get("response_status")
    if not isinstance(status, int):
        errors.append("anchor provider provider.response_status must be an integer")
    elif not 200 <= status < 300:
        if mode in {"provider-anchored", "blockchain-anchored"}:
            errors.append("anchor provider provider.response_status must be 2xx for anchored modes")
        else:
            warnings.append(f"anchor provider response status is {status}")
    if value.get("accepted") != (isinstance(status, int) and 200 <= status < 300):
        errors.append("anchor provider provider.accepted does not match response_status")


def _verify_public_log(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("anchor provider public_log must be an object")
        return
    for field in ("log_ref", "root", "size", "entry_ref"):
        if value.get(field) in (None, ""):
            errors.append(f"anchor provider public_log.{field} is required")
    if value.get("root") and not _is_hash_ref(str(value.get("root"))):
        errors.append("anchor provider public_log.root must be a sha256 reference")
    if not isinstance(value.get("size"), int) or value.get("size") <= 0:
        errors.append("anchor provider public_log.size must be a positive integer")
    for field in ("inclusion_proof_hash", "consistency_proof_hash"):
        if value.get(field) and not _is_hash_ref(str(value.get(field))):
            errors.append(f"anchor provider public_log.{field} must be a sha256 reference")


def _verify_blockchain(value: Any, mode: str | None, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("anchor provider blockchain must be an object")
        return
    if mode == "blockchain-anchored":
        if not value.get("network"):
            errors.append("anchor provider blockchain.network is required for blockchain-anchored mode")
        if not value.get("transaction_ref"):
            errors.append("anchor provider blockchain.transaction_ref is required for blockchain-anchored mode")


def _verify_operation(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("anchor provider operation must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("anchor provider operation.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "anchor provider operation.credential", errors)


def _verify_audit_log(value: Any, published: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("anchor provider audit_log must be an object")
        return
    for field in ("audit_log_ref", "root", "retention_until"):
        if not value.get(field):
            errors.append(f"anchor provider audit_log.{field} is required")
    if value.get("root") and not _is_hash_ref(str(value.get("root"))):
        errors.append("anchor provider audit_log.root must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if published and retention <= published:
            errors.append("anchor provider audit_log.retention_until must be after published_at")
    except ValueError as exc:
        errors.append(f"anchor provider audit_log.retention_until invalid: {exc}")


def _status_summary(controls: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"anchor provider secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_https(value: Any) -> bool:
    return isinstance(value, str) and urlparse(value).scheme == "https"


def _is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


