from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import EvidenceChain
from .contracts import contract_hash, find_contract_registration
from .crypto import sign_value
from .frameworks import default_framework_mappings
from .gate import EVAL_ENTRY_TYPE, GATE_ENTRY_TYPE
from .pdf import write_text_pdf
from .registry import DELEGATION_GRAPH_ENTRY_TYPE

PROOF_PACK_SPEC_VERSION = "trustai.proof-pack/0.1"
PROOF_PACK_CONTEXT = "https://trustai.dev/spec/proof-pack/v0.1"


def _require_chain_entry(chain: EvidenceChain, entry: dict[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise ValueError(f"{label} must be an evidence chain entry")
    entry_id = entry.get("entry_id")
    if not entry_id:
        raise ValueError(f"{label} missing entry_id")
    chain_entry = chain.find_entry(str(entry_id))
    if chain_entry is None:
        raise ValueError(f"{label} is not part of the supplied evidence chain")
    if content_hash(chain_entry) != content_hash(entry):
        raise ValueError(f"{label} does not match the supplied evidence chain entry")
    return chain_entry


def _validate_compile_inputs(
    *,
    contract: dict[str, Any],
    digest: str,
    contract_entry: dict[str, Any],
    eval_entry: dict[str, Any],
    gate_entry: dict[str, Any],
    decision: dict[str, Any],
) -> None:
    if eval_entry.get("entry_type") != EVAL_ENTRY_TYPE:
        raise ValueError("eval_entry must be an eval.completed chain entry")
    if gate_entry.get("entry_type") != GATE_ENTRY_TYPE:
        raise ValueError("gate_entry must be a promotion_gate.decided chain entry")
    if not (contract_entry.get("index") < eval_entry.get("index") < gate_entry.get("index")):
        raise ValueError("proof pack entries must be ordered contract registration < eval < gate")

    eval_payload = eval_entry.get("payload", {}) if isinstance(eval_entry.get("payload"), dict) else {}
    gate_payload = gate_entry.get("payload", {}) if isinstance(gate_entry.get("payload"), dict) else {}
    stored_decision = gate_payload.get("decision", {}) if isinstance(gate_payload.get("decision"), dict) else {}
    if not isinstance(decision, dict):
        raise ValueError("decision must be the gate decision object")

    for label, payload in (("eval_entry", eval_payload), ("gate_entry", gate_payload)):
        if payload.get("contract_hash") != digest:
            raise ValueError(f"{label} contract_hash does not match contract")
        if payload.get("contract_id") != contract.get("id"):
            raise ValueError(f"{label} contract_id does not match contract")
        if payload.get("agent") != contract.get("agent"):
            raise ValueError(f"{label} agent does not match contract")

    results = eval_payload.get("results")
    if not isinstance(results, dict):
        raise ValueError("eval_entry results payload is required")
    if eval_payload.get("results_hash") != content_hash(results):
        raise ValueError("eval_entry results_hash does not match results")

    required_decision_fields = (
        "contract_id",
        "contract_hash",
        "agent",
        "outcome",
        "passed",
        "checks",
        "holdout",
        "approvals",
        "results_hash",
        "contract_entry_id",
        "eval_entry_id",
    )
    for field in required_decision_fields:
        if decision.get(field) != stored_decision.get(field):
            raise ValueError(f"decision {field} does not match gate entry")
    if decision.get("gate_entry_id") != gate_entry.get("entry_id"):
        raise ValueError("decision gate_entry_id does not match gate entry")

def _payload_contract_hash(entry: dict[str, Any]) -> str | None:
    payload = entry.get("payload", {})
    if not isinstance(payload, dict):
        return None
    if payload.get("contract_hash"):
        return payload.get("contract_hash")
    filters = payload.get("filters")
    if isinstance(filters, dict) and filters.get("contract_hash"):
        return filters.get("contract_hash")
    summary = payload.get("summary")
    if isinstance(summary, dict):
        contract_hashes = summary.get("contract_hashes")
        if isinstance(contract_hashes, list) and len(contract_hashes) == 1 and contract_hashes[0]:
            return contract_hashes[0]
    graph = payload.get("delegation_graph")
    if isinstance(graph, dict):
        graph_filters = graph.get("filters")
        if isinstance(graph_filters, dict) and graph_filters.get("contract_hash"):
            return graph_filters.get("contract_hash")
    decision = payload.get("decision")
    if isinstance(decision, dict):
        return decision.get("contract_hash")
    return None


def _graph_source_entry_ids(entry: dict[str, Any]) -> list[str]:
    if entry.get("entry_type") != DELEGATION_GRAPH_ENTRY_TYPE:
        return []
    graph = entry.get("payload", {}).get("delegation_graph")
    if not isinstance(graph, dict):
        return []
    entry_ids: list[str] = []
    for node in graph.get("nodes", []):
        if isinstance(node, dict):
            source = node.get("source_entry")
            if isinstance(source, dict) and source.get("entry_id"):
                entry_ids.append(str(source["entry_id"]))
    for edge in graph.get("edges", []):
        if isinstance(edge, dict):
            source = edge.get("source_entry")
            if isinstance(source, dict) and source.get("entry_id"):
                entry_ids.append(str(source["entry_id"]))
    return entry_ids


def _related_entries(chain: EvidenceChain, digest: str, required: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for entry in chain.entries:
        if _payload_contract_hash(entry) == digest:
            selected[entry["entry_id"]] = entry
    for entry in required:
        selected[entry["entry_id"]] = entry

    changed = True
    while changed:
        changed = False
        for entry in list(selected.values()):
            for entry_id in _graph_source_entry_ids(entry):
                if entry_id in selected:
                    continue
                source_entry = chain.find_entry(entry_id)
                if source_entry is not None:
                    selected[entry_id] = source_entry
                    changed = True
    return sorted(selected.values(), key=lambda item: item["index"])


def compile_proof_pack(
    chain: EvidenceChain,
    contract: dict[str, Any],
    eval_entry: dict[str, Any],
    gate_entry: dict[str, Any],
    decision: dict[str, Any],
    out_path: str | Path | None = None,
    pdf_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    digest = contract_hash(contract)
    contract_entry = find_contract_registration(chain, digest)
    if contract_entry is None:
        raise ValueError("cannot compile proof pack without a contract registration entry")

    eval_entry = _require_chain_entry(chain, eval_entry, "eval_entry")
    gate_entry = _require_chain_entry(chain, gate_entry, "gate_entry")
    _validate_compile_inputs(
        contract=contract,
        digest=digest,
        contract_entry=contract_entry,
        eval_entry=eval_entry,
        gate_entry=gate_entry,
        decision=decision,
    )

    selected_entries = _related_entries(chain, digest, [contract_entry, eval_entry, gate_entry])
    proofs = {entry["entry_id"]: chain.proof_for(entry) for entry in selected_entries}
    environment = eval_entry["payload"]["results"].get("environment", {})
    pack_body = {
        "@context": PROOF_PACK_CONTEXT,
        "type": "TrustAIProofPack",
        "spec_version": PROOF_PACK_SPEC_VERSION,
        "issued_at": utc_now(),
        "subject": {
            "agent": contract["agent"],
            "environment": environment,
        },
        "contract": {
            "hash": digest,
            "body": contract,
            "chain_entry_id": contract_entry["entry_id"],
        },
        "eval": {
            "results_hash": eval_entry["payload"]["results_hash"],
            "chain_entry_id": eval_entry["entry_id"],
        },
        "gate_decision": decision,
        "chain": {
            "tenant_id": chain.tenant_id,
            "tree": chain.tree(),
            "entries": selected_entries,
            "inclusion_proofs": proofs,
        },
        "framework_mappings": default_framework_mappings(decision),
    }
    pack_id = content_hash(pack_body)
    proof_pack = {
        **pack_body,
        "pack_id": pack_id,
        "signatures": [sign_value({"pack_id": pack_id, "pack": pack_body}, key)],
    }

    if out_path:
        target = Path(out_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(proof_pack, indent=2, sort_keys=True), encoding="utf-8")

    if pdf_path:
        write_proof_pack_pdf(pdf_path, proof_pack)

    return proof_pack


def write_proof_pack_pdf(path: str | Path, proof_pack: dict[str, Any]) -> None:
    decision = proof_pack["gate_decision"]
    lines = [
        f"Pack ID: {proof_pack['pack_id']}",
        f"Issued at: {proof_pack['issued_at']}",
        f"Agent: {decision['agent']['name']} @ {decision['agent']['version']}",
        f"Contract: {decision['contract_id']}",
        f"Outcome: {decision['outcome'].upper()}",
        f"Chain root: {proof_pack['chain']['tree']['root']}",
        f"Tree size: {proof_pack['chain']['tree']['size']}",
        f"Evidence entries in pack: {len(proof_pack['chain']['entries'])}",
        "",
        "Metric checks:",
    ]
    for check in decision["checks"]:
        status = "PASS" if check["passed"] else "FAIL"
        lines.append(
            f"- {status} {check['name']}: actual={check['actual']} "
            f"{check['operator']} threshold={check['threshold']}"
        )
    lines.extend(
        [
            "",
            f"Holdout: {'PASS' if decision['holdout']['passed'] else 'FAIL'}",
            f"Records checked: {decision['holdout']['records_checked']}",
            f"Freeze boundary: {decision['holdout']['freeze_at']}",
            f"Holdout minimum: {decision['holdout']['min_timestamp']}",
            "",
            f"Approvals: {'PASS' if decision['approvals']['passed'] else 'FAIL'}",
        ]
    )
    for approval in decision["approvals"].get("actual", []):
        lines.append(f"- {approval.get('role')}: {approval.get('approver')} at {approval.get('approved_at')}")
    lines.extend(["", "Related evidence:"])
    for entry in proof_pack["chain"].get("entries", []):
        lines.append(f"- #{entry.get('index')} {entry.get('entry_type')} {entry.get('entry_id')}")
    lines.extend(["", "Framework mappings:"])
    for mapping in proof_pack.get("framework_mappings", []):
        lines.append(f"- {mapping['framework']}: {', '.join(mapping['controls'])}")

    write_text_pdf(path, "TrustAI Proof Pack", lines)
