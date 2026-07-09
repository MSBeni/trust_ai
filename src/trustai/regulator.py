from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain, verify_entry
from .crypto import sign_value, verify_value
from .merkle import verify_inclusion

REGULATOR_DISCLOSURE_SCHEMA = "trustai.regulator-disclosure/0.1"

DEFAULT_DISCLOSURE_ENTRY_TYPES = (
    "verification_contract.registered",
    "eval.completed",
    "promotion_gate.decided",
    "runtime.attested",
    "shadow_replay.completed",
    "soak_report.completed",
    "policy.decision",
    "incident.recorded",
    "promotion_gate.demoted",
    "promotion_gate.rolled_back",
    "chain.anchor.published",
)


@dataclass
class RegulatorVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    disclosed_entry_count: int = 0


def _source_pack_summary(proof_pack: dict[str, Any]) -> dict[str, Any]:
    decision = proof_pack.get("gate_decision", {})
    return {
        "pack_id": proof_pack.get("pack_id"),
        "spec_version": proof_pack.get("spec_version"),
        "issued_at": proof_pack.get("issued_at"),
        "contract_hash": proof_pack.get("contract", {}).get("hash"),
        "contract_id": decision.get("contract_id"),
        "agent": decision.get("agent", {}),
        "gate_outcome": decision.get("outcome"),
        "gate_decision_hash": content_hash(decision) if decision else None,
        "pack_chain_tree": proof_pack.get("chain", {}).get("tree", {}),
    }


def _select_entries(
    chain: EvidenceChain,
    include_entry_types: list[str] | None,
    include_entry_ids: list[str] | None,
) -> list[dict[str, Any]]:
    types = set(include_entry_types or DEFAULT_DISCLOSURE_ENTRY_TYPES)
    ids = set(include_entry_ids or [])
    selected = []
    for entry in chain.entries:
        if entry.get("entry_type") in types or entry.get("entry_id") in ids:
            selected.append(entry)
    return selected


def build_regulator_disclosure(
    chain: EvidenceChain,
    proof_pack: dict[str, Any],
    audience: str = "regulator",
    purpose: str = "EU AI Act Annex III technical documentation",
    include_entry_types: list[str] | None = None,
    include_entry_ids: list[str] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    selected_entries = _select_entries(chain, include_entry_types, include_entry_ids)
    proofs = {entry["entry_id"]: chain.proof_for(entry) for entry in selected_entries}
    body = {
        "schema": REGULATOR_DISCLOSURE_SCHEMA,
        "issued_at": utc_now(),
        "audience": audience,
        "purpose": purpose,
        "selection": {
            "entry_types": include_entry_types or list(DEFAULT_DISCLOSURE_ENTRY_TYPES),
            "entry_ids": include_entry_ids or [],
            "disclosed_entry_count": len(selected_entries),
            "omitted_entry_count": max(0, len(chain.entries) - len(selected_entries)),
        },
        "source_proof_pack": _source_pack_summary(proof_pack),
        "chain": {
            "tenant_id": chain.tenant_id,
            "tree": chain.tree(),
            "entries": selected_entries,
            "inclusion_proofs": proofs,
        },
    }
    disclosure_id = content_hash(body)
    return {
        **body,
        "disclosure_id": disclosure_id,
        "signatures": [sign_value({"disclosure_id": disclosure_id, "disclosure": body}, key)],
    }


def verify_regulator_disclosure(disclosure: dict[str, Any], key: str | None = None) -> RegulatorVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if disclosure.get("schema") != REGULATOR_DISCLOSURE_SCHEMA:
        errors.append(f"unsupported disclosure schema: {disclosure.get('schema')}")

    body = without_keys(disclosure, "disclosure_id", "signatures")
    expected_disclosure_id = content_hash(body)
    if disclosure.get("disclosure_id") != expected_disclosure_id:
        errors.append("disclosure_id does not match canonical disclosure body")

    signatures = disclosure.get("signatures", [])
    if not signatures:
        errors.append("regulator disclosure missing signature")
    elif not verify_value(
        {"disclosure_id": disclosure.get("disclosure_id"), "disclosure": body},
        signatures[0],
        key,
    ):
        errors.append("regulator disclosure signature invalid")

    source = disclosure.get("source_proof_pack", {})
    if not source.get("pack_id"):
        warnings.append("source proof pack id missing")

    chain = disclosure.get("chain", {})
    tree = chain.get("tree", {})
    root = tree.get("root")
    size = tree.get("size")
    entries = chain.get("entries", [])
    proofs = chain.get("inclusion_proofs", {})

    if not root:
        errors.append("disclosure chain tree root missing")
    if not isinstance(entries, list) or not entries:
        errors.append("regulator disclosure must include at least one chain entry")
        entries = []

    last_index = -1
    for entry in entries:
        errors.extend(verify_entry(entry, key=key))
        index = entry.get("index")
        if not isinstance(index, int):
            errors.append(f"entry {entry.get('entry_id')} index missing")
            continue
        if isinstance(size, int) and index >= size:
            errors.append(f"entry {index} is outside disclosed tree size")
        if index <= last_index:
            warnings.append("disclosed entries are not in ascending chain order")
        last_index = index

        proof = proofs.get(entry.get("entry_id"), {})
        audit_path = proof.get("audit_path", [])
        if proof.get("entry_id") != entry.get("entry_id"):
            errors.append(f"entry {index} proof entry_id mismatch")
        if proof.get("index") != index:
            errors.append(f"entry {index} proof index mismatch")
        if proof.get("tree_root") != root:
            errors.append(f"entry {index} proof tree root mismatch")
        if proof.get("tree_size") != size:
            errors.append(f"entry {index} proof tree size mismatch")
        if root and not verify_inclusion(entry.get("entry_id", ""), audit_path, root):
            errors.append(f"entry {index} inclusion proof invalid")

    selection = disclosure.get("selection", {})
    expected_count = selection.get("disclosed_entry_count")
    if isinstance(expected_count, int) and expected_count != len(entries):
        errors.append("selection disclosed_entry_count does not match entries")

    return RegulatorVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        disclosed_entry_count=len(entries),
    )


def load_regulator_disclosure(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_regulator_disclosure(path: str | Path, disclosure: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(disclosure, indent=2, sort_keys=True), encoding="utf-8")
