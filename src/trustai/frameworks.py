from __future__ import annotations

from typing import Any


def default_framework_mappings(decision: dict[str, Any]) -> list[dict[str, Any]]:
    contract_id = decision.get("contract_id")
    gate_entry_id = decision.get("gate_entry_id")
    return [
        {
            "framework": "ISO 42001",
            "controls": ["AI system impact assessment", "Evaluation and monitoring", "Human oversight"],
            "evidence": {"contract_id": contract_id, "gate_entry_id": gate_entry_id},
        },
        {
            "framework": "NIST AI RMF",
            "controls": ["Measure 2.5", "Manage 1.3", "Govern 6.1"],
            "evidence": {"contract_id": contract_id, "gate_entry_id": gate_entry_id},
        },
        {
            "framework": "EU AI Act Annex III",
            "controls": ["Technical documentation", "Logging", "Human oversight"],
            "evidence": {"contract_id": contract_id, "gate_entry_id": gate_entry_id},
        },
        {
            "framework": "SR 11-7",
            "controls": ["Model validation", "Ongoing monitoring", "Change control"],
            "evidence": {"contract_id": contract_id, "gate_entry_id": gate_entry_id},
        },
        {
            "framework": "SOC 2",
            "controls": ["Change management", "Logical access", "Monitoring"],
            "evidence": {"contract_id": contract_id, "gate_entry_id": gate_entry_id},
        },
    ]
