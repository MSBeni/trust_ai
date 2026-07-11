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
from .frameworks import default_framework_mappings
from .gate import EVAL_ENTRY_TYPE, GATE_ENTRY_TYPE, evaluate_contract
from .keyring import verify_entry_with_keyring, verify_value_with_keyring
from .merkle import verify_inclusion
from .tree_header import verify_packed_tree_header
from .mcp_gateway import MCP_TOOL_CALL_ENTRY_TYPE, verify_mcp_transcript_entries
from .proofpack import PROOF_PACK_SPEC_VERSION
from .registry import (
    AGENT_INVENTORY_ENTRY_TYPE,
    DELEGATION_ENTRY_TYPE,
    DELEGATION_GRAPH_ENTRY_TYPE,
    DELEGATION_GRAPH_SCHEMA,
    verify_delegation_graph,
)
from .shadow import (
    SOAK_REPORT_ENTRY_TYPE,
    SHADOW_REPLAY_ENTRY_TYPE,
    verify_soak_report_payload,
    verify_temporal_holdout_manifest,
)


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
    if not isinstance(chain, dict):
        errors.append("proof pack chain must be an object")
        chain = {}
    tree = chain.get("tree", {})
    root = tree.get("root") if isinstance(tree, dict) else None
    entries = chain.get("entries", [])
    proofs = chain.get("inclusion_proofs", {})
    errors.extend(verify_packed_tree_header(tree, entries, label="chain"))
    if not isinstance(proofs, dict):
        errors.append("chain inclusion_proofs must be an object")
        proofs = {}
    entry_by_type: dict[str, dict[str, Any]] = {}
    approval_entries: list[dict[str, Any]] = []
    shadow_entries: list[dict[str, Any]] = []
    mcp_entries: list[dict[str, Any]] = []
    soak_entries: list[dict[str, Any]] = []
    delegation_graph_entries: list[dict[str, Any]] = []

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
            if entry_type == SOAK_REPORT_ENTRY_TYPE:
                soak_entries.append(entry)
            if entry_type == DELEGATION_GRAPH_ENTRY_TYPE:
                delegation_graph_entries.append(entry)

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
            subject = proof_pack.get("subject", {})
            if not isinstance(subject, dict):
                errors.append("subject must be an object")
                subject = {}
            if subject.get("agent") != contract_body.get("agent"):
                errors.append("packed subject agent mismatch")
            if stored.get("agent") != contract_body.get("agent"):
                errors.append("gate decision agent mismatch")
            if eval_entry.get("payload", {}).get("agent") != contract_body.get("agent"):
                errors.append("eval entry agent mismatch")
            expected_environment = results.get("environment", {})
            if subject.get("environment") != expected_environment:
                errors.append("packed subject environment mismatch")
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
    if contract_digest and isinstance(contract_body, dict):
        for soak_entry in soak_entries:
            payload = soak_entry.get("payload", {})
            if not isinstance(payload, dict):
                errors.append(f"soak report entry {soak_entry.get('index')} payload missing")
                continue
            if payload.get("contract_hash") != contract_digest:
                errors.append(f"soak report entry {soak_entry.get('index')} references a different contract hash")
            if soak_entry.get("timestamp") != payload.get("evaluated_at"):
                errors.append(f"soak report entry {soak_entry.get('index')} timestamp mismatch")
            soak_result = verify_soak_report_payload(payload, contract_body)
            errors.extend(f"soak report entry {soak_entry.get('index')}: {error}" for error in soak_result.errors)
            warnings.extend(f"soak report entry {soak_entry.get('index')}: {warning}" for warning in soak_result.warnings)
    if contract_digest and mcp_entries:
        mcp_result = verify_mcp_transcript_entries(mcp_entries, contract_hash=contract_digest)
        errors.extend(mcp_result.errors)
        warnings.extend(mcp_result.warnings)
    if contract_digest and delegation_graph_entries:
        _verify_delegation_graph_pack_entries(
            delegation_graph_entries,
            entries,
            contract_hash=contract_digest,
            key=key,
            errors=errors,
            warnings=warnings,
        )
    framework_mappings = proof_pack.get("framework_mappings")
    if not isinstance(framework_mappings, list):
        errors.append("framework_mappings must be a list")
    elif framework_mappings != default_framework_mappings(proof_pack.get("gate_decision", {})):
        errors.append("framework mappings do not match gate decision")
    decision = proof_pack.get("gate_decision", {}).get("outcome")
    if decision and decision != "passed":
        warnings.append(f"proof pack is valid but gate outcome is {decision}")

    return VerificationResult(ok=not errors, errors=errors, warnings=warnings, decision=decision)


def _verify_delegation_graph_pack_entries(
    graph_entries: list[dict[str, Any]],
    pack_entries: list[dict[str, Any]],
    *,
    contract_hash: str,
    key: str | None,
    errors: list[str],
    warnings: list[str],
) -> None:
    entry_by_id = {entry.get("entry_id"): entry for entry in pack_entries if isinstance(entry, dict)}
    for graph_entry in graph_entries:
        label = f"delegation graph entry {graph_entry.get('index')}"
        payload = graph_entry.get("payload", {})
        if not isinstance(payload, dict):
            errors.append(f"{label} payload missing")
            continue
        if payload.get("schema") != DELEGATION_GRAPH_SCHEMA:
            errors.append(f"{label} schema mismatch")
        filters = payload.get("filters", {})
        if isinstance(filters, dict) and filters.get("contract_hash") not in (None, contract_hash):
            errors.append(f"{label} references a different contract hash")
        graph = payload.get("delegation_graph")
        if not isinstance(graph, dict):
            errors.append(f"{label} missing embedded delegation graph")
            continue
        if payload.get("delegation_graph_id") != graph.get("delegation_graph_id"):
            errors.append(f"{label} delegation_graph_id mismatch")
        if payload.get("delegation_graph_hash") != content_hash(graph):
            errors.append(f"{label} delegation_graph_hash mismatch")
        if payload.get("summary") != graph.get("summary"):
            errors.append(f"{label} summary mismatch")
        if payload.get("filters") != graph.get("filters"):
            errors.append(f"{label} filters mismatch")
        if payload.get("source_chain") != graph.get("source_chain"):
            errors.append(f"{label} source_chain mismatch")

        graph_filters = graph.get("filters", {})
        if isinstance(graph_filters, dict) and graph_filters.get("contract_hash") not in (None, contract_hash):
            errors.append(f"{label} embedded graph references a different contract hash")
        contract_hashes = graph.get("summary", {}).get("contract_hashes", [])
        if isinstance(contract_hashes, list) and contract_hash not in contract_hashes:
            errors.append(f"{label} embedded graph summary does not include packed contract hash")

        result = verify_delegation_graph(graph, key=key)
        errors.extend(f"{label}: {error}" for error in result.errors)
        warnings.extend(
            f"{label}: {warning}"
            for warning in result.warnings
            if "source chain not supplied" not in warning
        )

        for edge in graph.get("edges", []):
            if not isinstance(edge, dict):
                continue
            source = edge.get("source_entry", {})
            source_id = source.get("entry_id") if isinstance(source, dict) else None
            source_entry = entry_by_id.get(source_id)
            if source_entry is None:
                errors.append(f"{label} edge {edge.get('edge_id')} source delegation entry not embedded in proof pack")
                continue
            if source_entry.get("entry_type") != DELEGATION_ENTRY_TYPE:
                errors.append(f"{label} edge {edge.get('edge_id')} source entry is not delegation evidence")
            if source_entry.get("payload", {}).get("delegation_hash") != edge.get("delegation_hash"):
                errors.append(f"{label} edge {edge.get('edge_id')} source delegation hash mismatch")
            if source_entry.get("payload", {}).get("contract_hash") != contract_hash:
                errors.append(f"{label} edge {edge.get('edge_id')} source delegation contract mismatch")

        for node in graph.get("nodes", []):
            if not isinstance(node, dict) or not node.get("inventory_observed"):
                continue
            source = node.get("source_entry", {})
            source_id = source.get("entry_id") if isinstance(source, dict) else None
            source_entry = entry_by_id.get(source_id)
            if source_entry is None:
                errors.append(f"{label} node {node.get('agent_ref')} source inventory entry not embedded in proof pack")
                continue
            if source_entry.get("entry_type") != AGENT_INVENTORY_ENTRY_TYPE:
                errors.append(f"{label} node {node.get('agent_ref')} source entry is not inventory evidence")
            if source_entry.get("payload", {}).get("agent_hash") != node.get("agent_hash"):
                errors.append(f"{label} node {node.get('agent_ref')} source inventory hash mismatch")
