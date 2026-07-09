from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approvals import APPROVAL_ENTRY_TYPE
from .canonical import content_hash, without_keys
from .chain import compute_entry_id, entry_core, verify_entry
from .contracts import CONTRACT_ENTRY_TYPE, contract_hash
from .crypto import verify_value
from .gate import EVAL_ENTRY_TYPE, GATE_ENTRY_TYPE, evaluate_contract
from .keyring import verify_entry_with_keyring, verify_value_with_keyring
from .merkle import verify_inclusion
from .mcp_gateway import MCP_TOOL_CALL_ENTRY_TYPE, verify_mcp_transcript_entries
from .proofpack import PROOF_PACK_SPEC_VERSION
from .shadow import SHADOW_REPLAY_ENTRY_TYPE, verify_temporal_holdout_manifest


@dataclass
class VerificationResult:
    ok: bool
    errors: list[str]
    warnings: list[str]
    decision: str | None = None


def load_proof_pack(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_proof_pack(
    proof_pack: dict[str, Any],
    key: str | None = None,
    keyring: dict[str, Any] | None = None,
) -> VerificationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if proof_pack.get("spec_version") != PROOF_PACK_SPEC_VERSION:
        errors.append(f"unsupported proof pack spec_version: {proof_pack.get('spec_version')}")

    pack_body = without_keys(proof_pack, "pack_id", "signatures")
    expected_pack_id = content_hash(pack_body)
    if proof_pack.get("pack_id") != expected_pack_id:
        errors.append("pack_id does not match canonical pack body")

    signatures = proof_pack.get("signatures", [])
    if not signatures:
        errors.append("proof pack missing signature")
    elif keyring is not None:
        if not verify_value_with_keyring({"pack_id": proof_pack.get("pack_id"), "pack": pack_body}, signatures[0], keyring):
            errors.append("proof pack signature invalid")
    elif not verify_value({"pack_id": proof_pack.get("pack_id"), "pack": pack_body}, signatures[0], key):
        errors.append("proof pack signature invalid")

    chain = proof_pack.get("chain", {})
    tree = chain.get("tree", {})
    root = tree.get("root")
    entries = chain.get("entries", [])
    proofs = chain.get("inclusion_proofs", {})
    entry_by_type: dict[str, dict[str, Any]] = {}
    approval_entries: list[dict[str, Any]] = []
    shadow_entries: list[dict[str, Any]] = []
    mcp_entries: list[dict[str, Any]] = []

    if not root:
        errors.append("chain tree root missing")
    if not isinstance(entries, list) or not entries:
        errors.append("proof pack must include selected chain entries")
    else:
        for entry in entries:
            entry_errors = verify_entry_with_keyring(entry, keyring) if keyring is not None else verify_entry(entry, key)
            errors.extend(entry_errors)
            core = entry_core(entry)
            if entry.get("entry_id") != compute_entry_id(core):
                errors.append(f"entry {entry.get('index')} canonical id mismatch")
            proof = proofs.get(entry.get("entry_id"), {})
            audit_path = proof.get("audit_path", [])
            if proof.get("entry_id") != entry.get("entry_id"):
                errors.append(f"entry {entry.get('index')} proof entry_id mismatch")
            if proof.get("index") != entry.get("index"):
                errors.append(f"entry {entry.get('index')} proof index mismatch")
            if proof.get("tree_root") != root:
                errors.append(f"entry {entry.get('index')} proof tree root mismatch")
            if proof.get("tree_size") != tree.get("size"):
                errors.append(f"entry {entry.get('index')} proof tree size mismatch")
            if root and not verify_inclusion(entry.get("entry_id", ""), audit_path, root):
                errors.append(f"entry {entry.get('index')} inclusion proof invalid")
            entry_type = entry.get("entry_type", "")
            entry_by_type[entry_type] = entry
            if entry_type == APPROVAL_ENTRY_TYPE:
                approval_entries.append(entry)
            if entry_type == SHADOW_REPLAY_ENTRY_TYPE:
                shadow_entries.append(entry)
            if entry_type == MCP_TOOL_CALL_ENTRY_TYPE:
                mcp_entries.append(entry)

    contract_entry = entry_by_type.get(CONTRACT_ENTRY_TYPE)
    eval_entry = entry_by_type.get(EVAL_ENTRY_TYPE)
    gate_entry = entry_by_type.get(GATE_ENTRY_TYPE)
    if not contract_entry:
        errors.append("missing contract registration entry")
    if not eval_entry:
        errors.append("missing eval entry")
    if not gate_entry:
        errors.append("missing gate entry")

    contract_body = proof_pack.get("contract", {}).get("body")
    if not isinstance(contract_body, dict):
        errors.append("contract body missing")
        contract_digest = None
    else:
        contract_digest = contract_hash(contract_body)
        if proof_pack.get("contract", {}).get("hash") != contract_digest:
            errors.append("packed contract hash does not match contract body")

    if contract_entry and eval_entry and gate_entry and contract_digest:
        if not (contract_entry["index"] < eval_entry["index"] < gate_entry["index"]):
            errors.append("chain ordering must be contract registration < eval < gate")

        if proof_pack.get("contract", {}).get("chain_entry_id") != contract_entry.get("entry_id"):
            errors.append("packed contract chain_entry_id mismatch")
        if proof_pack.get("eval", {}).get("chain_entry_id") != eval_entry.get("entry_id"):
            errors.append("packed eval chain_entry_id mismatch")
        if proof_pack.get("eval", {}).get("results_hash") != eval_entry.get("payload", {}).get("results_hash"):
            errors.append("packed eval results_hash mismatch")

        if contract_entry["payload"].get("contract_hash") != contract_digest:
            errors.append("contract entry hash does not match packed contract")
        if eval_entry["payload"].get("contract_hash") != contract_digest:
            errors.append("eval entry references a different contract hash")
        if gate_entry["payload"].get("contract_hash") != contract_digest:
            errors.append("gate entry references a different contract hash")

        results = eval_entry["payload"].get("results")
        if isinstance(results, dict):
            if eval_entry["payload"].get("results_hash") != content_hash(results):
                errors.append("eval results hash mismatch")
            recomputed = evaluate_contract(contract_body, results, approval_entries=approval_entries)
            stored = gate_entry["payload"].get("decision", {})
            comparable_keys = ("outcome", "passed", "checks", "holdout", "approvals", "results_hash")
            for key_name in comparable_keys:
                if stored.get(key_name) != recomputed.get(key_name):
                    errors.append(f"gate decision mismatch for {key_name}")
            packed_decision = proof_pack.get("gate_decision", {})
            for key_name in comparable_keys + ("contract_entry_id", "eval_entry_id"):
                if packed_decision.get(key_name) != stored.get(key_name):
                    errors.append(f"packed gate decision mismatch for {key_name}")
            if packed_decision.get("gate_entry_id") != gate_entry.get("entry_id"):
                errors.append("packed gate decision gate_entry_id mismatch")
        else:
            errors.append("eval entry results missing")

    if contract_digest and isinstance(contract_body, dict):
        for shadow_entry in shadow_entries:
            payload = shadow_entry.get("payload", {})
            if not isinstance(payload, dict):
                errors.append(f"shadow replay entry {shadow_entry.get('index')} payload missing")
                continue
            if payload.get("contract_hash") != contract_digest:
                errors.append(f"shadow replay entry {shadow_entry.get('index')} references a different contract hash")
            manifest = payload.get("temporal_holdout_manifest")
            replay = payload.get("replay")
            summary = payload.get("temporal_holdout")
            if not isinstance(manifest, dict):
                errors.append(f"shadow replay entry {shadow_entry.get('index')} missing temporal_holdout_manifest")
                continue
            if not isinstance(replay, dict):
                errors.append(f"shadow replay entry {shadow_entry.get('index')} missing replay payload")
                continue
            if not isinstance(summary, dict):
                errors.append(f"shadow replay entry {shadow_entry.get('index')} missing temporal_holdout summary")
                summary = {}
            holdout_result = verify_temporal_holdout_manifest(
                manifest,
                contract=contract_body,
                replay=replay,
                key=key,
                keyring=keyring,
            )
            errors.extend(
                f"shadow replay entry {shadow_entry.get('index')} temporal holdout: {error}"
                for error in holdout_result.errors
            )
            warnings.extend(
                f"shadow replay entry {shadow_entry.get('index')} temporal holdout: {warning}"
                for warning in holdout_result.warnings
            )
            expected_summary = {
                "manifest_id": manifest.get("manifest_id"),
                "manifest_hash": content_hash(manifest),
                "records_root": manifest.get("records_root"),
                "record_count": manifest.get("record_count"),
                "passed": manifest.get("passed"),
            }
            for field, expected in expected_summary.items():
                if summary.get(field) != expected:
                    errors.append(
                        f"shadow replay entry {shadow_entry.get('index')} temporal_holdout summary mismatch for {field}"
                    )
    if contract_digest and mcp_entries:
        mcp_result = verify_mcp_transcript_entries(mcp_entries, contract_hash=contract_digest)
        errors.extend(mcp_result.errors)
        warnings.extend(mcp_result.warnings)
    decision = proof_pack.get("gate_decision", {}).get("outcome")
    if decision and decision != "passed":
        warnings.append(f"proof pack is valid but gate outcome is {decision}")

    return VerificationResult(ok=not errors, errors=errors, warnings=warnings, decision=decision)
