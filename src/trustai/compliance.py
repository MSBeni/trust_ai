from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONTROL_CATALOG: dict[str, list[dict[str, str]]] = {
    "ISO 42001": [
        {"control": "AI system impact assessment", "evidence": "registered verification contract"},
        {"control": "Evaluation and monitoring", "evidence": "gate metrics and soak reports"},
        {"control": "Human oversight", "evidence": "approval events and required approvals"},
    ],
    "NIST AI RMF": [
        {"control": "Govern 6.1", "evidence": "chain-backed accountability records"},
        {"control": "Measure 2.5", "evidence": "temporal holdout metrics"},
        {"control": "Manage 1.3", "evidence": "promotion gate decision"},
    ],
    "EU AI Act Annex III": [
        {"control": "Technical documentation", "evidence": "proof pack body and environment fingerprint"},
        {"control": "Logging", "evidence": "Merkle evidence chain"},
        {"control": "Human oversight", "evidence": "approval evidence"},
    ],
    "SR 11-7": [
        {"control": "Model validation", "evidence": "pre-registered evaluation contract"},
        {"control": "Ongoing monitoring", "evidence": "runtime attestation and soak checks"},
        {"control": "Change control", "evidence": "promotion gate chain entry"},
    ],
    "SOC 2": [
        {"control": "Change management", "evidence": "signed promotion decision"},
        {"control": "Monitoring", "evidence": "runtime and ingest evidence"},
        {"control": "Logical access", "evidence": "approval roles and sign-offs"},
    ],
}


def build_compliance_export(proof_pack: dict[str, Any]) -> dict[str, Any]:
    decision = proof_pack.get("gate_decision", {})
    mappings = []
    for framework, controls in CONTROL_CATALOG.items():
        mappings.append(
            {
                "framework": framework,
                "agent": decision.get("agent", {}),
                "contract_id": decision.get("contract_id"),
                "pack_id": proof_pack.get("pack_id"),
                "gate_outcome": decision.get("outcome"),
                "controls": controls,
                "chain_root": proof_pack.get("chain", {}).get("tree", {}).get("root"),
                "evidence_entry_ids": [
                    entry.get("entry_id")
                    for entry in proof_pack.get("chain", {}).get("entries", [])
                ],
            }
        )
    return {
        "schema": "trustai.compliance-export/0.1",
        "pack_id": proof_pack.get("pack_id"),
        "issued_at": proof_pack.get("issued_at"),
        "mappings": mappings,
    }


def write_compliance_export(path: str | Path, export: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(export, indent=2, sort_keys=True), encoding="utf-8")
