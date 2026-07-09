from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .crypto import sign_value, verify_value

EU_AI_ACT_DOCUMENT_SCHEMA = "trustai.eu-ai-act-technical-documentation/0.1"

REQUIRED_SECTION_IDS = (
    "system_description",
    "intended_purpose",
    "risk_classification",
    "data_and_holdout",
    "performance_and_robustness",
    "human_oversight",
    "logging_and_traceability",
    "post_market_monitoring",
    "conformity_assessment_support",
)


@dataclass
class EUAIActVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def _entries_from(proof_pack: dict[str, Any], regulator_disclosure: dict[str, Any] | None) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for entry in proof_pack.get("chain", {}).get("entries", []):
        if entry.get("entry_id"):
            selected[entry["entry_id"]] = entry
    if regulator_disclosure:
        for entry in regulator_disclosure.get("chain", {}).get("entries", []):
            if entry.get("entry_id"):
                selected[entry["entry_id"]] = entry
    return sorted(selected.values(), key=lambda item: item.get("index", 0))


def _evidence_refs(entries: list[dict[str, Any]], entry_types: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    wanted = set(entry_types)
    refs = []
    for entry in entries:
        if entry.get("entry_type") not in wanted:
            continue
        refs.append(
            {
                "entry_id": entry.get("entry_id"),
                "entry_type": entry.get("entry_type"),
                "index": entry.get("index"),
                "timestamp": entry.get("timestamp"),
                "payload_hash": entry.get("payload_hash"),
            }
        )
    return refs


def _payloads(entries: list[dict[str, Any]], entry_type: str) -> list[dict[str, Any]]:
    return [entry.get("payload", {}) for entry in entries if entry.get("entry_type") == entry_type]


def _metric_summary(decision: dict[str, Any]) -> list[dict[str, Any]]:
    summary = []
    for check in decision.get("checks", []):
        summary.append(
            {
                "name": check.get("name"),
                "actual": check.get("actual"),
                "operator": check.get("operator"),
                "threshold": check.get("threshold"),
                "passed": check.get("passed"),
            }
        )
    return summary


def _section(section_id: str, title: str, summary: str, evidence: list[dict[str, Any]], content: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": section_id,
        "title": title,
        "summary": summary,
        "evidence": evidence,
        "content": content,
    }


def build_eu_ai_act_document(
    proof_pack: dict[str, Any],
    regulator_disclosure: dict[str, Any] | None = None,
    operator: str = "local-operator",
    high_risk_category: str = "Annex III high-risk AI system under operator assessment",
    key: str | None = None,
) -> dict[str, Any]:
    contract = proof_pack.get("contract", {}).get("body", {})
    decision = proof_pack.get("gate_decision", {})
    entries = _entries_from(proof_pack, regulator_disclosure)
    policy_decisions = _payloads(entries, "policy.decision")
    incidents = _payloads(entries, "incident.recorded")
    demotions = _payloads(entries, "promotion_gate.demoted")
    rollbacks = _payloads(entries, "promotion_gate.rolled_back")
    runtime_attestations = _payloads(entries, "runtime.attested")
    soak_reports = _payloads(entries, "soak_report.completed")

    source_artifacts = {
        "proof_pack": {
            "pack_id": proof_pack.get("pack_id"),
            "spec_version": proof_pack.get("spec_version"),
            "issued_at": proof_pack.get("issued_at"),
            "chain_tree": proof_pack.get("chain", {}).get("tree", {}),
        },
        "regulator_disclosure": None,
    }
    if regulator_disclosure:
        source_artifacts["regulator_disclosure"] = {
            "disclosure_id": regulator_disclosure.get("disclosure_id"),
            "schema": regulator_disclosure.get("schema"),
            "issued_at": regulator_disclosure.get("issued_at"),
            "chain_tree": regulator_disclosure.get("chain", {}).get("tree", {}),
            "disclosed_entry_count": regulator_disclosure.get("selection", {}).get("disclosed_entry_count"),
        }

    sections = [
        _section(
            "system_description",
            "System Description",
            "Identifies the governed agent version, operating environment, and technical fingerprint.",
            _evidence_refs(entries, ("verification_contract.registered",)),
            {
                "operator": operator,
                "agent": contract.get("agent") or decision.get("agent", {}),
                "environment": contract.get("environment"),
                "contract_id": contract.get("id") or decision.get("contract_id"),
                "contract_hash": proof_pack.get("contract", {}).get("hash"),
                "freeze": contract.get("freeze", {}),
            },
        ),
        _section(
            "intended_purpose",
            "Intended Purpose and Use Limits",
            "Documents the intended operating scope and blast-radius constraints registered before evaluation.",
            _evidence_refs(entries, ("verification_contract.registered", "runtime.attested")),
            {
                "risk_class": (contract.get("agent") or {}).get("risk_class"),
                "blast_radius": contract.get("blast_radius", {}),
                "required_approvals": contract.get("required_approvals", []),
            },
        ),
        _section(
            "risk_classification",
            "Risk Classification",
            "Records the operator-assessed high-risk category and evidence basis.",
            _evidence_refs(entries, ("verification_contract.registered", "policy.decision", "incident.recorded")),
            {
                "category": high_risk_category,
                "rationale": "The governed agent can affect money or production systems and is controlled through pre-registered gates, runtime policy, and incident evidence.",
                "framework_controls": contract.get("framework_controls", []),
            },
        ),
        _section(
            "data_and_holdout",
            "Evaluation Data and Temporal Holdout",
            "Shows that evaluation evidence was generated after the frozen agent version boundary.",
            _evidence_refs(entries, ("verification_contract.registered", "eval.completed", "shadow_replay.completed")),
            {
                "freeze": contract.get("freeze", {}),
                "holdout": contract.get("holdout", {}),
                "gate_holdout_result": decision.get("holdout", {}),
            },
        ),
        _section(
            "performance_and_robustness",
            "Performance, Accuracy, and Robustness",
            "Summarizes pre-registered metric checks, soak windows, and gate outcome.",
            _evidence_refs(entries, ("eval.completed", "promotion_gate.decided", "soak_report.completed")),
            {
                "gate_outcome": decision.get("outcome"),
                "metric_checks": _metric_summary(decision),
                "soak_reports": soak_reports,
            },
        ),
        _section(
            "human_oversight",
            "Human Oversight",
            "Documents required sign-offs and runtime approval or policy decisions.",
            _evidence_refs(entries, ("promotion_gate.decided", "policy.decision", "runtime.attested")),
            {
                "required_approvals": contract.get("required_approvals", []),
                "gate_approvals": decision.get("approvals", {}),
                "policy_decisions": policy_decisions,
            },
        ),
        _section(
            "logging_and_traceability",
            "Logging and Traceability",
            "Provides portable evidence identifiers, tree roots, signatures, timestamps, and inclusion-proof references.",
            _evidence_refs(
                entries,
                (
                    "verification_contract.registered",
                    "eval.completed",
                    "promotion_gate.decided",
                    "runtime.attested",
                    "policy.decision",
                    "chain.anchor.published",
                ),
            ),
            {
                "source_artifacts": source_artifacts,
                "evidence_entry_count": len(entries),
                "evidence_entry_types": sorted({entry.get("entry_type") for entry in entries}),
            },
        ),
        _section(
            "post_market_monitoring",
            "Post-Market Monitoring",
            "Captures runtime attestations, incidents, demotions, and rollbacks after promotion evidence is issued.",
            _evidence_refs(
                entries,
                (
                    "runtime.attested",
                    "soak_report.completed",
                    "policy.decision",
                    "incident.recorded",
                    "promotion_gate.demoted",
                    "promotion_gate.rolled_back",
                ),
            ),
            {
                "runtime_attestations": runtime_attestations,
                "policy_decisions": policy_decisions,
                "incidents": incidents,
                "demotions": demotions,
                "rollbacks": rollbacks,
            },
        ),
        _section(
            "conformity_assessment_support",
            "Conformity Assessment Support",
            "Gives a reviewer the commands and artifacts needed to verify the supporting evidence offline.",
            _evidence_refs(entries, ("chain.anchor.published", "promotion_gate.decided", "policy.decision")),
            {
                "offline_verification_commands": [
                    "python -m trustai verify <proof-pack.json>",
                    "python -m trustai regulator-verify <regulator-disclosure.json>",
                    "python -m trustai eu-ai-act-verify <eu-ai-act-document.json>",
                ],
                "limitations": [
                    "This reference implementation uses local development signing unless configured otherwise.",
                    "External conformity assessment remains a human and regulatory process.",
                ],
            },
        ),
    ]

    body = {
        "schema": EU_AI_ACT_DOCUMENT_SCHEMA,
        "issued_at": utc_now(),
        "title": "EU AI Act Technical Documentation",
        "regulatory_basis": "EU AI Act high-risk technical documentation package",
        "source_artifacts": source_artifacts,
        "sections": sections,
    }
    document_id = content_hash(body)
    return {
        **body,
        "document_id": document_id,
        "signatures": [sign_value({"document_id": document_id, "document": body}, key)],
    }


def verify_eu_ai_act_document(
    document: dict[str, Any],
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    key: str | None = None,
) -> EUAIActVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if document.get("schema") != EU_AI_ACT_DOCUMENT_SCHEMA:
        errors.append(f"unsupported EU AI Act document schema: {document.get('schema')}")

    body = without_keys(document, "document_id", "signatures")
    expected_document_id = content_hash(body)
    if document.get("document_id") != expected_document_id:
        errors.append("document_id does not match canonical document body")

    signatures = document.get("signatures", [])
    if not signatures:
        errors.append("EU AI Act document missing signature")
    elif not verify_value({"document_id": document.get("document_id"), "document": body}, signatures[0], key):
        errors.append("EU AI Act document signature invalid")

    sections = document.get("sections", [])
    section_ids = {section.get("id") for section in sections if isinstance(section, dict)}
    for section_id in REQUIRED_SECTION_IDS:
        if section_id not in section_ids:
            errors.append(f"missing required section: {section_id}")

    if not sections:
        errors.append("EU AI Act document must include sections")
    for section in sections:
        if not section.get("evidence"):
            warnings.append(f"section {section.get('id')} has no evidence references")

    source = document.get("source_artifacts", {})
    if proof_pack is not None:
        expected_pack_id = proof_pack.get("pack_id")
        actual_pack_id = source.get("proof_pack", {}).get("pack_id")
        if expected_pack_id != actual_pack_id:
            errors.append("source proof pack id mismatch")
    if regulator_disclosure is not None:
        expected_disclosure_id = regulator_disclosure.get("disclosure_id")
        actual_disclosure_id = source.get("regulator_disclosure", {}).get("disclosure_id")
        if expected_disclosure_id != actual_disclosure_id:
            errors.append("source regulator disclosure id mismatch")
    elif not source.get("regulator_disclosure"):
        warnings.append("EU AI Act document has no regulator disclosure source")

    return EUAIActVerification(ok=not errors, errors=errors, warnings=warnings)


def load_eu_ai_act_document(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_eu_ai_act_document(path: str | Path, document: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")


def write_eu_ai_act_markdown(path: str | Path, document: dict[str, Any]) -> None:
    lines = [
        f"# {document.get('title', 'EU AI Act Technical Documentation')}",
        "",
        f"Document ID: `{document.get('document_id')}`",
        f"Issued at: `{document.get('issued_at')}`",
        f"Schema: `{document.get('schema')}`",
        "",
    ]
    source = document.get("source_artifacts", {})
    pack = source.get("proof_pack", {})
    disclosure = source.get("regulator_disclosure") or {}
    lines.extend(
        [
            "## Source Artifacts",
            "",
            f"- Proof pack: `{pack.get('pack_id')}`",
            f"- Regulator disclosure: `{disclosure.get('disclosure_id')}`",
            "",
        ]
    )
    for section in document.get("sections", []):
        lines.extend([f"## {section.get('title')}", "", section.get("summary", ""), ""])
        evidence = section.get("evidence", [])
        if evidence:
            lines.append("Evidence:")
            for item in evidence:
                lines.append(
                    f"- #{item.get('index')} `{item.get('entry_type')}` `{item.get('entry_id')}`"
                )
            lines.append("")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines), encoding="utf-8")
