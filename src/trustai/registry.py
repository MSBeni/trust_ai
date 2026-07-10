from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .merkle import merkle_root, verify_inclusion

AGENT_INVENTORY_ENTRY_TYPE = "agent.inventory.discovered"
DELEGATION_ENTRY_TYPE = "agent.delegation.evidenced"
DELEGATION_GRAPH_SCHEMA = "trustai.agent-delegation-graph/0.1"
DELEGATION_GRAPH_ENTRY_TYPE = "agent.delegation_graph.exported"


@dataclass
class DelegationGraphVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_inventory(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("inventory file must contain an object")
    agents = value.get("agents")
    if not isinstance(agents, list) or not agents:
        raise ValueError("inventory requires a non-empty agents list")
    return value


def load_delegation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("delegation file must contain an object")
    return normalize_delegation(value)


def load_delegation_graph(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("delegation graph file must contain an object")
    return value


def write_delegation_graph(path: str | Path, graph: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(graph, indent=2, sort_keys=True), encoding="utf-8")


def normalize_agent(agent: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(agent, dict):
        raise ValueError("agent inventory item must be an object")
    required = ("name", "version", "owner", "risk_class")
    missing = [field for field in required if not agent.get(field)]
    if missing:
        raise ValueError(f"agent missing required fields: {', '.join(missing)}")
    normalized = json.loads(json.dumps(agent, sort_keys=True))
    normalized.setdefault("governed", False)
    normalized.setdefault("source", "manual")
    return normalized


def normalize_delegation(delegation: dict[str, Any]) -> dict[str, Any]:
    required = ("timestamp", "parent_agent", "child_agent", "contract_hash", "reason")
    missing = [field for field in required if not delegation.get(field)]
    if missing:
        raise ValueError(f"delegation missing required fields: {', '.join(missing)}")
    parse_rfc3339(delegation["timestamp"])
    for field in ("parent_agent", "child_agent"):
        agent = delegation[field]
        if not isinstance(agent, dict) or not agent.get("name") or not agent.get("version"):
            raise ValueError(f"{field} must include name and version")
    return json.loads(json.dumps(delegation, sort_keys=True))


def append_inventory(
    chain: EvidenceChain,
    inventory: dict[str, Any],
    key: str | None = None,
) -> list[dict[str, Any]]:
    observed_at = inventory.get("observed_at") or utc_now()
    parse_rfc3339(observed_at)
    entries: list[dict[str, Any]] = []
    for agent in inventory["agents"]:
        normalized = normalize_agent(agent)
        payload = {
            "observed_at": observed_at,
            "source": inventory.get("source", normalized.get("source", "manual")),
            "agent_hash": content_hash(normalized),
            "agent": normalized,
        }
        entries.append(chain.append(AGENT_INVENTORY_ENTRY_TYPE, payload, key=key, timestamp=observed_at))
    return entries


def append_delegation(
    chain: EvidenceChain,
    delegation: dict[str, Any],
    key: str | None = None,
) -> dict[str, Any]:
    normalized = normalize_delegation(delegation)
    payload = {
        "contract_hash": normalized["contract_hash"],
        "delegation_hash": content_hash(normalized),
        "delegation": normalized,
    }
    return chain.append(DELEGATION_ENTRY_TYPE, payload, key=key, timestamp=normalized["timestamp"])


def build_delegation_graph(
    chain: EvidenceChain,
    *,
    contract_hash: str | None = None,
    root_agent: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    verification = chain.verify_all(key)
    if not verification.ok:
        raise ValueError(f"source chain verification failed: {'; '.join(verification.errors[:3])}")

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    inventory_nodes = _inventory_nodes(chain)
    edges = _delegation_edges(chain, contract_hash=contract_hash)
    if not edges:
        raise ValueError("no delegation entries matched the graph filters")

    if root_agent:
        edges = _filter_edges_by_root(edges, inventory_nodes, root_agent)
        if not edges:
            raise ValueError(f"no delegation path found for root agent: {root_agent}")

    graph_refs = sorted({edge["parent_ref"] for edge in edges} | {edge["child_ref"] for edge in edges})
    nodes = [_graph_node_for_ref(ref, inventory_nodes, edges) for ref in graph_refs]
    summary = _summarize_graph(nodes, edges)
    body = {
        "schema": DELEGATION_GRAPH_SCHEMA,
        "generated_at": timestamp,
        "source_chain": _source_chain_record(chain),
        "filters": {
            "contract_hash": contract_hash,
            "root_agent": root_agent,
        },
        "nodes": nodes,
        "edges": edges,
        "summary": summary,
        "controls": _delegation_graph_controls(summary),
        "limitations": [
            "Graph edges bind delegation evidence already present in the source chain; runtime call transcripts remain separate evidence entries.",
            "Missing inventory bindings are surfaced as warnings because delegation entries can identify agents before discovery connectors observe them.",
        ],
    }
    graph_id = content_hash(body)
    return {
        **body,
        "delegation_graph_id": graph_id,
        "signatures": [sign_value({"delegation_graph_id": graph_id, "delegation_graph": body}, key)],
    }


def verify_delegation_graph(
    graph: dict[str, Any],
    *,
    source_chain: EvidenceChain | None = None,
    key: str | None = None,
) -> DelegationGraphVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if graph.get("schema") != DELEGATION_GRAPH_SCHEMA:
        errors.append(f"unsupported delegation graph schema: {graph.get('schema')}")

    body = without_keys(graph, "delegation_graph_id", "signatures")
    expected_id = content_hash(body)
    if graph.get("delegation_graph_id") != expected_id:
        errors.append("delegation_graph_id does not match canonical graph body")

    signatures = graph.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("delegation graph must include at least one signature")
    else:
        signed_value = {"delegation_graph_id": graph.get("delegation_graph_id"), "delegation_graph": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("delegation graph signature verification failed")

    try:
        parse_rfc3339(str(graph.get("generated_at", "")))
    except ValueError as exc:
        errors.append(f"delegation graph generated_at invalid: {exc}")

    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list):
        errors.append("delegation graph nodes must be a list")
        nodes = []
    if not isinstance(edges, list):
        errors.append("delegation graph edges must be a list")
        edges = []
    if not edges:
        errors.append("delegation graph must include at least one edge")

    node_refs = _verify_graph_nodes(nodes, errors, warnings)
    _verify_graph_edges(edges, node_refs, errors)

    expected_summary = _summarize_graph(nodes, edges)
    for field in ("node_count", "edge_count", "root_agents", "leaf_agents", "max_depth", "cycle_detected", "contract_hashes", "node_root", "edge_root"):
        if graph.get("summary", {}).get(field) != expected_summary.get(field):
            errors.append(f"delegation graph summary field mismatch: {field}")
    if expected_summary.get("cycle_detected"):
        errors.append("delegation graph contains a cycle")

    _verify_embedded_sources(graph, nodes, edges, errors)
    _verify_filters(graph, nodes, edges, errors)

    if source_chain is None:
        warnings.append("source chain not supplied; verifier checked graph signatures, hashes, summary, and embedded inclusion proofs only")
    else:
        _verify_source_chain_binding(graph, nodes, edges, source_chain, key, errors)

    if expected_summary.get("missing_inventory"):
        warnings.append("delegation graph contains agents without inventory source entries")

    return DelegationGraphVerification(ok=not errors, errors=errors, warnings=warnings)


def append_delegation_graph(
    chain: EvidenceChain,
    graph: dict[str, Any],
    *,
    source_chain: EvidenceChain | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    verification = verify_delegation_graph(graph, source_chain=source_chain or chain, key=key)
    if not verification.ok:
        raise ValueError(f"delegation graph verification failed: {'; '.join(verification.errors[:3])}")
    payload = {
        "schema": DELEGATION_GRAPH_SCHEMA,
        "delegation_graph_id": graph["delegation_graph_id"],
        "delegation_graph_hash": content_hash(graph),
        "generated_at": graph.get("generated_at"),
        "source_chain": graph.get("source_chain"),
        "filters": graph.get("filters", {}),
        "summary": graph.get("summary", {}),
    }
    return chain.append(DELEGATION_GRAPH_ENTRY_TYPE, payload, key=key, timestamp=graph.get("generated_at"))


def _agent_ref(agent: dict[str, Any]) -> str:
    return f"{agent.get('name')}@{agent.get('version')}"


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _source_ref(chain: EvidenceChain, entry: dict[str, Any]) -> dict[str, Any]:
    proof = chain.proof_for(entry)
    return {
        "entry_id": entry.get("entry_id"),
        "index": entry.get("index"),
        "entry_type": entry.get("entry_type"),
        "timestamp": entry.get("timestamp"),
        "payload_hash": entry.get("payload_hash"),
        "inclusion_proof": proof,
    }


def _source_chain_record(chain: EvidenceChain) -> dict[str, Any]:
    return {
        "tenant_id": chain.tenant_id,
        "entry_count": len(chain.entries),
        "tree": chain.tree(),
        "first_entry_id": chain.entries[0]["entry_id"] if chain.entries else None,
        "last_entry_id": chain.entries[-1]["entry_id"] if chain.entries else None,
    }


def _inventory_nodes(chain: EvidenceChain) -> dict[str, dict[str, Any]]:
    nodes: dict[str, dict[str, Any]] = {}
    for entry in chain.entries:
        if entry.get("entry_type") != AGENT_INVENTORY_ENTRY_TYPE:
            continue
        payload = entry.get("payload", {})
        agent = payload.get("agent", {})
        if not isinstance(agent, dict) or not agent.get("name") or not agent.get("version"):
            continue
        ref = _agent_ref(agent)
        nodes[ref] = {
            "agent_ref": ref,
            "name": agent["name"],
            "version": agent["version"],
            "owner": agent.get("owner"),
            "risk_class": agent.get("risk_class"),
            "environment": agent.get("environment"),
            "governed": agent.get("governed", False),
            "source": payload.get("source"),
            "agent_hash": payload.get("agent_hash") or content_hash(agent),
            "inventory_observed": True,
            "source_entry": _source_ref(chain, entry),
        }
    return nodes


def _delegation_edges(chain: EvidenceChain, *, contract_hash: str | None = None) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for entry in chain.entries:
        if entry.get("entry_type") != DELEGATION_ENTRY_TYPE:
            continue
        payload = entry.get("payload", {})
        delegation = normalize_delegation(payload.get("delegation", {}))
        if contract_hash and delegation["contract_hash"] != contract_hash:
            continue
        parent_ref = _agent_ref(delegation["parent_agent"])
        child_ref = _agent_ref(delegation["child_agent"])
        delegation_hash = payload.get("delegation_hash") or content_hash(delegation)
        edge = {
            "edge_id": content_hash({"source_entry_id": entry.get("entry_id"), "delegation_hash": delegation_hash}),
            "parent_ref": parent_ref,
            "child_ref": child_ref,
            "contract_hash": delegation["contract_hash"],
            "timestamp": delegation["timestamp"],
            "reason": delegation["reason"],
            "scope": delegation.get("scope", {}),
            "delegation_hash": delegation_hash,
            "delegation": delegation,
            "source_entry": _source_ref(chain, entry),
        }
        edges.append(edge)
    return sorted(edges, key=lambda edge: (edge["timestamp"], edge["source_entry"]["index"]))


def _filter_edges_by_root(
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    root_agent: str,
) -> list[dict[str, Any]]:
    refs = {edge["parent_ref"] for edge in edges} | {edge["child_ref"] for edge in edges}
    root_refs = {
        ref
        for ref in refs
        if ref == root_agent or nodes.get(ref, {}).get("name") == root_agent or ref.split("@", 1)[0] == root_agent
    }
    if not root_refs:
        return []
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        adjacency.setdefault(edge["parent_ref"], []).append(edge)
    selected_edges: list[dict[str, Any]] = []
    seen_edges: set[str] = set()
    frontier = list(sorted(root_refs))
    seen_refs = set(frontier)
    while frontier:
        parent = frontier.pop(0)
        for edge in adjacency.get(parent, []):
            if edge["edge_id"] not in seen_edges:
                selected_edges.append(edge)
                seen_edges.add(edge["edge_id"])
            if edge["child_ref"] not in seen_refs:
                seen_refs.add(edge["child_ref"])
                frontier.append(edge["child_ref"])
    return selected_edges


def _graph_node_for_ref(
    ref: str,
    inventory_nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    if ref in inventory_nodes:
        return inventory_nodes[ref]
    for edge in edges:
        for field in ("parent_agent", "child_agent"):
            agent = edge["delegation"].get(field, {})
            if _agent_ref(agent) == ref:
                return {
                    "agent_ref": ref,
                    "name": agent.get("name"),
                    "version": agent.get("version"),
                    "owner": agent.get("owner"),
                    "risk_class": agent.get("risk_class"),
                    "environment": agent.get("environment"),
                    "governed": agent.get("governed", False),
                    "source": None,
                    "agent_hash": content_hash(agent),
                    "inventory_observed": False,
                    "source_entry": None,
                }
    name, _, version = ref.partition("@")
    return {
        "agent_ref": ref,
        "name": name,
        "version": version,
        "owner": None,
        "risk_class": None,
        "environment": None,
        "governed": False,
        "source": None,
        "agent_hash": content_hash({"name": name, "version": version}),
        "inventory_observed": False,
        "source_entry": None,
    }


def _summarize_graph(nodes: list[Any], edges: list[Any]) -> dict[str, Any]:
    node_values = [node for node in nodes if isinstance(node, dict)]
    edge_values = [edge for edge in edges if isinstance(edge, dict)]
    refs = sorted({node.get("agent_ref") for node in node_values if node.get("agent_ref")})
    incoming = {ref: 0 for ref in refs}
    outgoing = {ref: 0 for ref in refs}
    adjacency = {ref: [] for ref in refs}
    for edge in edge_values:
        parent = edge.get("parent_ref")
        child = edge.get("child_ref")
        if parent in outgoing:
            outgoing[parent] += 1
        if child in incoming:
            incoming[child] += 1
        if parent in adjacency and child:
            adjacency[parent].append(child)

    cycle_paths = _cycle_paths(adjacency)
    if cycle_paths:
        max_depth = None
    else:
        max_depth = 0
        memo: dict[str, int] = {}

        def depth(ref: str) -> int:
            if ref in memo:
                return memo[ref]
            children = adjacency.get(ref, [])
            memo[ref] = 0 if not children else 1 + max(depth(child) for child in children)
            return memo[ref]

        for ref in refs:
            max_depth = max(max_depth, depth(ref))

    return {
        "node_count": len(refs),
        "edge_count": len(edge_values),
        "root_agents": sorted(ref for ref in refs if outgoing.get(ref, 0) > 0 and incoming.get(ref, 0) == 0),
        "leaf_agents": sorted(ref for ref in refs if incoming.get(ref, 0) > 0 and outgoing.get(ref, 0) == 0),
        "max_depth": max_depth,
        "cycle_detected": bool(cycle_paths),
        "cycles": cycle_paths,
        "contract_hashes": sorted({edge.get("contract_hash") for edge in edge_values if edge.get("contract_hash")}),
        "missing_inventory": sorted(node.get("agent_ref") for node in node_values if not node.get("inventory_observed")),
        "node_root": content_hash(sorted(node.get("agent_hash") for node in node_values if node.get("agent_hash"))),
        "edge_root": content_hash(sorted(edge.get("delegation_hash") for edge in edge_values if edge.get("delegation_hash"))),
    }


def _cycle_paths(adjacency: dict[str, list[str]]) -> list[list[str]]:
    cycles: list[list[str]] = []
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def visit(ref: str) -> None:
        if ref in visiting:
            if ref in stack:
                cycles.append(stack[stack.index(ref) :] + [ref])
            return
        if ref in visited:
            return
        visiting.add(ref)
        stack.append(ref)
        for child in adjacency.get(ref, []):
            visit(child)
        stack.pop()
        visiting.remove(ref)
        visited.add(ref)

    for ref in sorted(adjacency):
        visit(ref)
    return cycles


def _delegation_graph_controls(summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "control_id": "delegation.graph.edge-binding",
            "status": "pass" if summary["edge_count"] else "fail",
            "description": "Each delegation edge binds back to a source chain delegation entry and canonical delegation hash.",
        },
        {
            "control_id": "delegation.graph.inventory-binding",
            "status": "pass" if not summary["missing_inventory"] else "warn",
            "description": "Graph nodes bind back to agent inventory entries when discovery evidence exists.",
        },
        {
            "control_id": "delegation.graph.acyclic",
            "status": "pass" if not summary["cycle_detected"] else "fail",
            "description": "Delegation paths should be acyclic so authority flow can be audited from root to leaf agents.",
        },
        {
            "control_id": "delegation.graph.contract-scope",
            "status": "pass" if len(summary["contract_hashes"]) <= 1 else "warn",
            "description": "A contract-filtered graph should contain a single contract hash.",
        },
    ]


def _verify_graph_nodes(
    nodes: list[Any],
    errors: list[str],
    warnings: list[str],
) -> set[str]:
    refs: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"delegation graph node {index} must be an object")
            continue
        ref = node.get("agent_ref")
        if not ref or not node.get("name") or not node.get("version"):
            errors.append(f"delegation graph node {index} requires agent_ref, name, and version")
            continue
        if ref != _agent_ref(node):
            errors.append(f"delegation graph node {ref} agent_ref does not match name/version")
        if ref in refs:
            errors.append(f"delegation graph duplicate node ref: {ref}")
        refs.add(ref)
        if not node.get("agent_hash"):
            errors.append(f"delegation graph node {ref} missing agent_hash")
        if node.get("inventory_observed") and not node.get("source_entry"):
            errors.append(f"delegation graph node {ref} is marked inventory_observed but lacks source_entry")
        if not node.get("inventory_observed"):
            warnings.append(f"delegation graph node {ref} lacks inventory source evidence")
    return refs


def _verify_graph_edges(edges: list[Any], node_refs: set[str], errors: list[str]) -> None:
    edge_ids: set[str] = set()
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"delegation graph edge {index} must be an object")
            continue
        for field in ("edge_id", "parent_ref", "child_ref", "contract_hash", "timestamp", "reason", "delegation_hash", "delegation", "source_entry"):
            if not edge.get(field):
                errors.append(f"delegation graph edge {index} missing {field}")
        if edge.get("edge_id") in edge_ids:
            errors.append(f"delegation graph duplicate edge id: {edge.get('edge_id')}")
        edge_ids.add(edge.get("edge_id"))
        if edge.get("parent_ref") not in node_refs:
            errors.append(f"delegation graph edge {index} parent_ref has no node")
        if edge.get("child_ref") not in node_refs:
            errors.append(f"delegation graph edge {index} child_ref has no node")
        try:
            delegation = normalize_delegation(edge.get("delegation", {}))
        except ValueError as exc:
            errors.append(f"delegation graph edge {index} invalid delegation: {exc}")
            continue
        if edge.get("parent_ref") != _agent_ref(delegation["parent_agent"]):
            errors.append(f"delegation graph edge {index} parent_ref does not match delegation parent")
        if edge.get("child_ref") != _agent_ref(delegation["child_agent"]):
            errors.append(f"delegation graph edge {index} child_ref does not match delegation child")
        if edge.get("contract_hash") != delegation["contract_hash"]:
            errors.append(f"delegation graph edge {index} contract_hash does not match delegation")
        if edge.get("timestamp") != delegation["timestamp"]:
            errors.append(f"delegation graph edge {index} timestamp does not match delegation")
        if edge.get("reason") != delegation["reason"]:
            errors.append(f"delegation graph edge {index} reason does not match delegation")
        expected_hash = content_hash(delegation)
        if edge.get("delegation_hash") != expected_hash:
            errors.append(f"delegation graph edge {index} delegation_hash mismatch")


def _verify_embedded_sources(
    graph: dict[str, Any],
    nodes: list[Any],
    edges: list[Any],
    errors: list[str],
) -> None:
    source_chain = graph.get("source_chain", {})
    tree = source_chain.get("tree", {}) if isinstance(source_chain, dict) else {}
    expected_root = tree.get("root")
    expected_size = tree.get("size")
    for source, expected_type, label in _iter_sources(nodes, edges):
        if not isinstance(source, dict):
            errors.append(f"{label} missing source entry binding")
            continue
        if source.get("entry_type") != expected_type:
            errors.append(f"{label} source entry type mismatch")
        proof = source.get("inclusion_proof", {})
        if not isinstance(proof, dict):
            errors.append(f"{label} source inclusion proof missing")
            continue
        if proof.get("entry_id") != source.get("entry_id"):
            errors.append(f"{label} source inclusion proof entry_id mismatch")
        if proof.get("tree_root") != expected_root or proof.get("tree_size") != expected_size:
            errors.append(f"{label} source inclusion proof tree does not match graph source chain")
        audit_path = proof.get("audit_path")
        if expected_root and isinstance(audit_path, list) and not verify_inclusion(str(source.get("entry_id")), audit_path, expected_root):
            errors.append(f"{label} source inclusion proof failed")


def _iter_sources(
    nodes: list[Any],
    edges: list[Any],
) -> list[tuple[Any, str, str]]:
    sources: list[tuple[Any, str, str]] = []
    for node in nodes:
        if isinstance(node, dict) and node.get("inventory_observed"):
            sources.append((node.get("source_entry"), AGENT_INVENTORY_ENTRY_TYPE, f"node {node.get('agent_ref')}"))
    for edge in edges:
        if isinstance(edge, dict):
            sources.append((edge.get("source_entry"), DELEGATION_ENTRY_TYPE, f"edge {edge.get('edge_id')}"))
    return sources


def _verify_filters(
    graph: dict[str, Any],
    nodes: list[Any],
    edges: list[Any],
    errors: list[str],
) -> None:
    filters = graph.get("filters", {})
    contract_hash = filters.get("contract_hash") if isinstance(filters, dict) else None
    edge_values = [edge for edge in edges if isinstance(edge, dict)]
    if contract_hash and any(edge.get("contract_hash") != contract_hash for edge in edge_values):
        errors.append("delegation graph contract_hash filter does not match all edges")
    root_agent = filters.get("root_agent") if isinstance(filters, dict) else None
    if root_agent:
        root_refs = set(graph.get("summary", {}).get("root_agents", []))
        node_names = {node.get("name") for node in nodes if isinstance(node, dict)}
        if root_agent not in root_refs and root_agent not in node_names:
            errors.append("delegation graph root_agent filter does not match graph nodes")


def _verify_source_chain_binding(
    graph: dict[str, Any],
    nodes: list[Any],
    edges: list[Any],
    source_chain: EvidenceChain,
    key: str | None,
    errors: list[str],
) -> None:
    chain_verification = source_chain.verify_all(key)
    if not chain_verification.ok:
        errors.extend(f"source chain verification failed: {error}" for error in chain_verification.errors[:5])
    source_record = graph.get("source_chain", {})
    record_count = source_record.get("entry_count")
    if source_record.get("tenant_id") != source_chain.tenant_id:
        errors.append("delegation graph source_chain tenant_id mismatch")
    if not isinstance(record_count, int) or record_count < 0:
        errors.append("delegation graph source_chain entry_count invalid")
        record_count = 0
    if record_count > len(source_chain.entries):
        errors.append("delegation graph source_chain entry_count exceeds supplied chain")
        record_count = len(source_chain.entries)
    if source_record.get("tree") != _chain_tree_at(source_chain, record_count):
        errors.append("delegation graph source_chain tree mismatch")
    if record_count:
        if source_record.get("first_entry_id") != source_chain.entries[0].get("entry_id"):
            errors.append("delegation graph source_chain first_entry_id mismatch")
        if source_record.get("last_entry_id") != source_chain.entries[record_count - 1].get("entry_id"):
            errors.append("delegation graph source_chain last_entry_id mismatch")

    for node in nodes:
        if not isinstance(node, dict) or not node.get("inventory_observed"):
            continue
        source = node.get("source_entry", {})
        entry = source_chain.find_entry(str(source.get("entry_id")))
        if entry is None:
            errors.append(f"node {node.get('agent_ref')} source entry not found in chain")
            continue
        payload = entry.get("payload", {})
        agent = payload.get("agent", {})
        if entry.get("entry_type") != AGENT_INVENTORY_ENTRY_TYPE:
            errors.append(f"node {node.get('agent_ref')} source entry is not inventory")
        if _agent_ref(agent) != node.get("agent_ref"):
            errors.append(f"node {node.get('agent_ref')} source inventory agent mismatch")
        if (payload.get("agent_hash") or content_hash(agent)) != node.get("agent_hash"):
            errors.append(f"node {node.get('agent_ref')} source inventory hash mismatch")

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source = edge.get("source_entry", {})
        entry = source_chain.find_entry(str(source.get("entry_id")))
        if entry is None:
            errors.append(f"edge {edge.get('edge_id')} source entry not found in chain")
            continue
        payload = entry.get("payload", {})
        if entry.get("entry_type") != DELEGATION_ENTRY_TYPE:
            errors.append(f"edge {edge.get('edge_id')} source entry is not delegation")
        if payload.get("delegation_hash") != edge.get("delegation_hash"):
            errors.append(f"edge {edge.get('edge_id')} source delegation hash mismatch")
        if _json_clone(payload.get("delegation", {})) != _json_clone(edge.get("delegation", {})):
            errors.append(f"edge {edge.get('edge_id')} source delegation body mismatch")


def _chain_tree_at(chain: EvidenceChain, size: int) -> dict[str, Any]:
    ids = [entry["entry_id"] for entry in chain.entries[:size]]
    return {"size": len(ids), "root": merkle_root(ids)}
