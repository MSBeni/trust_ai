from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain, verify_entry
from .contracts import CONTRACT_ENTRY_TYPE
from .crypto import sign_value, verify_value
from .gate import EVAL_ENTRY_TYPE, GATE_ENTRY_TYPE
from .merkle import verify_inclusion
from .tree_header import verify_packed_tree_header
from .proofpack import PROOF_PACK_SPEC_VERSION

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
    if not isinstance(source, dict):
        errors.append("source proof pack summary must be an object")
        source = {}
    elif not source.get("pack_id"):
        warnings.append("source proof pack id missing")

    chain = disclosure.get("chain", {})
    if not isinstance(chain, dict):
        errors.append("regulator disclosure chain must be an object")
        chain = {}
    tree = chain.get("tree", {})
    root = tree.get("root") if isinstance(tree, dict) else None
    size = tree.get("size") if isinstance(tree, dict) else None
    entries = chain.get("entries", [])
    proofs = chain.get("inclusion_proofs", {})
    errors.extend(verify_packed_tree_header(tree, entries, label="disclosure chain"))
    if not isinstance(proofs, dict):
        errors.append("disclosure chain inclusion_proofs must be an object")
        proofs = {}

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

    _verify_source_proof_pack_summary(source, entries, tree, errors)

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


def _verify_source_proof_pack_summary(
    source: dict[str, Any],
    entries: list[Any],
    disclosure_tree: Any,
    errors: list[str],
) -> None:
    if not source:
        return
    if source.get("spec_version") != PROOF_PACK_SPEC_VERSION:
        errors.append("source proof pack spec_version mismatch")

    source_tree = source.get("pack_chain_tree")
    errors.extend(verify_packed_tree_header(source_tree, [], label="source proof pack chain"))
    source_tree_size = source_tree.get("size") if isinstance(source_tree, dict) else None
    disclosure_tree_size = disclosure_tree.get("size") if isinstance(disclosure_tree, dict) else None
    if type(source_tree_size) is int and type(disclosure_tree_size) is int and source_tree_size > disclosure_tree_size:
        errors.append("source proof pack tree size exceeds disclosed chain tree size")

    source_hash = source.get("contract_hash")
    contract_entry = _find_entry_for_contract(entries, CONTRACT_ENTRY_TYPE, source_hash)
    eval_entry = _find_entry_for_contract(entries, EVAL_ENTRY_TYPE, source_hash)
    gate_entry = _find_entry_for_contract(entries, GATE_ENTRY_TYPE, source_hash)
    if contract_entry is None:
        errors.append("source proof pack contract entry is not disclosed")
    if eval_entry is None:
        errors.append("source proof pack eval entry is not disclosed")
    if gate_entry is None:
        errors.append("source proof pack gate entry is not disclosed")
    if contract_entry is None or eval_entry is None or gate_entry is None:
        return

    if not (contract_entry.get("index") < eval_entry.get("index") < gate_entry.get("index")):
        errors.append("source proof pack disclosed entries are not ordered contract < eval < gate")
    if type(source_tree_size) is int and gate_entry.get("index", source_tree_size) >= source_tree_size:
        errors.append("source proof pack tree size is before disclosed gate entry")

    contract_payload = contract_entry.get("payload", {}) if isinstance(contract_entry.get("payload"), dict) else {}
    eval_payload = eval_entry.get("payload", {}) if isinstance(eval_entry.get("payload"), dict) else {}
    gate_payload = gate_entry.get("payload", {}) if isinstance(gate_entry.get("payload"), dict) else {}
    decision = gate_payload.get("decision", {}) if isinstance(gate_payload.get("decision"), dict) else {}

    if source.get("contract_hash") != contract_payload.get("contract_hash"):
        errors.append("source proof pack contract_hash does not match disclosed contract entry")
    if source.get("contract_id") != contract_payload.get("contract_id"):
        errors.append("source proof pack contract_id does not match disclosed contract entry")
    if source.get("agent") != contract_payload.get("agent"):
        errors.append("source proof pack agent does not match disclosed contract entry")

    for label, payload in (("eval", eval_payload), ("gate", gate_payload)):
        if payload.get("contract_hash") != source.get("contract_hash"):
            errors.append(f"source proof pack contract_hash does not match disclosed {label} entry")
        if payload.get("contract_id") != source.get("contract_id"):
            errors.append(f"source proof pack contract_id does not match disclosed {label} entry")
        if payload.get("agent") != source.get("agent"):
            errors.append(f"source proof pack agent does not match disclosed {label} entry")

    if decision.get("contract_hash") != source.get("contract_hash"):
        errors.append("source proof pack contract_hash does not match disclosed gate decision")
    if decision.get("contract_id") != source.get("contract_id"):
        errors.append("source proof pack contract_id does not match disclosed gate decision")
    if decision.get("agent") != source.get("agent"):
        errors.append("source proof pack agent does not match disclosed gate decision")
    if decision.get("outcome") != source.get("gate_outcome"):
        errors.append("source proof pack gate_outcome does not match disclosed gate decision")
    expected_pack_decision = {**decision, "gate_entry_id": gate_entry.get("entry_id")}
    if content_hash(expected_pack_decision) != source.get("gate_decision_hash"):
        errors.append("source proof pack gate_decision_hash does not match disclosed gate decision")
    if decision.get("contract_entry_id") != contract_entry.get("entry_id"):
        errors.append("source proof pack gate decision contract_entry_id does not match disclosed contract entry")
    if decision.get("eval_entry_id") != eval_entry.get("entry_id"):
        errors.append("source proof pack gate decision eval_entry_id does not match disclosed eval entry")
    if decision.get("gate_entry_id") not in (None, gate_entry.get("entry_id")):
        errors.append("source proof pack gate decision gate_entry_id does not match disclosed gate entry")


def _find_entry_for_contract(entries: list[Any], entry_type: str, contract_hash: Any) -> dict[str, Any] | None:
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("entry_type") != entry_type:
            continue
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            continue
        if payload.get("contract_hash") == contract_hash:
            return entry
    return None

def load_regulator_disclosure(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_regulator_disclosure(path: str | Path, disclosure: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(disclosure, indent=2, sort_keys=True), encoding="utf-8")
