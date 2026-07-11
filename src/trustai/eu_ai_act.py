from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .crypto import sign_value, verify_value
from .regulator import verify_regulator_disclosure
from .verifier import verify_proof_pack

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


def _section_by_id(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sections: dict[str, dict[str, Any]] = {}
    for section in document.get("sections", []):
        if isinstance(section, dict) and section.get("id"):
            sections[str(section["id"])] = section
    return sections


def _source_artifacts_from(
    proof_pack: dict[str, Any],
    regulator_disclosure: dict[str, Any] | None,
) -> dict[str, Any]:
    source_artifacts = {
        "proof_pack": {
            "pack_id": proof_pack.get("pack_id"),
            "spec_version": proof_pack.get("spec_version"),
            "issued_at": proof_pack.get("issued_at"),
            "chain_tree": deepcopy(proof_pack.get("chain", {}).get("tree", {})),
        },
        "regulator_disclosure": None,
    }
    if regulator_disclosure:
        source_artifacts["regulator_disclosure"] = {
            "disclosure_id": regulator_disclosure.get("disclosure_id"),
            "schema": regulator_disclosure.get("schema"),
            "issued_at": regulator_disclosure.get("issued_at"),
            "chain_tree": deepcopy(regulator_disclosure.get("chain", {}).get("tree", {})),
            "disclosed_entry_count": regulator_disclosure.get("selection", {}).get("disclosed_entry_count"),
        }
    return source_artifacts


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

    source_artifacts = _source_artifacts_from(proof_pack, regulator_disclosure)

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
                "source_artifacts": deepcopy(source_artifacts),
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
        "source_artifacts": deepcopy(source_artifacts),
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
    if not isinstance(sections, list):
        errors.append("EU AI Act document sections must be a list")
        sections = []
    section_ids = {section.get("id") for section in sections if isinstance(section, dict)}
    for section_id in REQUIRED_SECTION_IDS:
        if section_id not in section_ids:
            errors.append(f"missing required section: {section_id}")

    if not sections:
        errors.append("EU AI Act document must include sections")
    for section in sections:
        if not isinstance(section, dict):
            errors.append("EU AI Act document section must be an object")
            continue
        if not section.get("evidence"):
            warnings.append(f"section {section.get('id')} has no evidence references")

    source = document.get("source_artifacts", {})
    if not isinstance(source, dict):
        errors.append("source_artifacts must be an object")
        source = {}
    if proof_pack is not None:
        pack_result = verify_proof_pack(proof_pack, key=key)
        errors.extend(f"source proof pack invalid: {error}" for error in pack_result.errors)
        warnings.extend(f"source proof pack warning: {warning}" for warning in pack_result.warnings)
        _verify_bound_sources(document, proof_pack, regulator_disclosure, errors)
    if regulator_disclosure is not None:
        disclosure_result = verify_regulator_disclosure(regulator_disclosure, key=key)
        errors.extend(f"source regulator disclosure invalid: {error}" for error in disclosure_result.errors)
        warnings.extend(f"source regulator disclosure warning: {warning}" for warning in disclosure_result.warnings)
    elif not source.get("regulator_disclosure"):
        warnings.append("EU AI Act document has no regulator disclosure source")

    return EUAIActVerification(ok=not errors, errors=errors, warnings=warnings)


def _verify_bound_sources(
    document: dict[str, Any],
    proof_pack: dict[str, Any],
    regulator_disclosure: dict[str, Any] | None,
    errors: list[str],
) -> None:
    expected_sources = _source_artifacts_from(proof_pack, regulator_disclosure)
    source = document.get("source_artifacts", {})
    if not isinstance(source, dict):
        source = {}
    if source.get("proof_pack") != expected_sources["proof_pack"]:
        errors.append("source proof pack summary mismatch")
    if source.get("regulator_disclosure") != expected_sources["regulator_disclosure"]:
        errors.append("source regulator disclosure summary mismatch")

    if regulator_disclosure is not None:
        disclosure_source = regulator_disclosure.get("source_proof_pack", {})
        if isinstance(disclosure_source, dict) and disclosure_source.get("pack_id") != proof_pack.get("pack_id"):
            errors.append("regulator disclosure source proof pack id does not match supplied proof pack")
        if isinstance(disclosure_source, dict) and disclosure_source.get("contract_hash") != proof_pack.get("contract", {}).get("hash"):
            errors.append("regulator disclosure source contract hash does not match supplied proof pack")

    contract = proof_pack.get("contract", {}).get("body", {})
    if not isinstance(contract, dict):
        contract = {}
    decision = proof_pack.get("gate_decision", {})
    if not isinstance(decision, dict):
        decision = {}
    entries = _entries_from(proof_pack, regulator_disclosure)
    sections = _section_by_id(document)

    system = _section_content(sections, "system_description", errors)
    _expect_equal(system, "agent", contract.get("agent") or decision.get("agent", {}), "system_description agent", errors)
    _expect_equal(system, "environment", contract.get("environment"), "system_description environment", errors, required=False)
    _expect_equal(system, "contract_id", contract.get("id") or decision.get("contract_id"), "system_description contract_id", errors)
    _expect_equal(system, "contract_hash", proof_pack.get("contract", {}).get("hash"), "system_description contract_hash", errors)
    _expect_equal(system, "freeze", contract.get("freeze", {}), "system_description freeze", errors)

    intended = _section_content(sections, "intended_purpose", errors)
    _expect_equal(intended, "risk_class", (contract.get("agent") or {}).get("risk_class"), "intended_purpose risk_class", errors, required=False)
    _expect_equal(intended, "blast_radius", contract.get("blast_radius", {}), "intended_purpose blast_radius", errors)
    _expect_equal(intended, "required_approvals", contract.get("required_approvals", []), "intended_purpose required_approvals", errors)

    risk = _section_content(sections, "risk_classification", errors)
    _expect_equal(risk, "framework_controls", contract.get("framework_controls", []), "risk_classification framework_controls", errors)

    data = _section_content(sections, "data_and_holdout", errors)
    _expect_equal(data, "freeze", contract.get("freeze", {}), "data_and_holdout freeze", errors)
    _expect_equal(data, "holdout", contract.get("holdout", {}), "data_and_holdout holdout", errors)
    _expect_equal(data, "gate_holdout_result", decision.get("holdout", {}), "data_and_holdout gate_holdout_result", errors)

    performance = _section_content(sections, "performance_and_robustness", errors)
    _expect_equal(performance, "gate_outcome", decision.get("outcome"), "performance_and_robustness gate_outcome", errors)
    _expect_equal(performance, "metric_checks", _metric_summary(decision), "performance_and_robustness metric_checks", errors)
    _expect_equal(performance, "soak_reports", _payloads(entries, "soak_report.completed"), "performance_and_robustness soak_reports", errors)

    human = _section_content(sections, "human_oversight", errors)
    _expect_equal(human, "required_approvals", contract.get("required_approvals", []), "human_oversight required_approvals", errors)
    _expect_equal(human, "gate_approvals", decision.get("approvals", {}), "human_oversight gate_approvals", errors)
    _expect_equal(human, "policy_decisions", _payloads(entries, "policy.decision"), "human_oversight policy_decisions", errors)

    logging = _section_content(sections, "logging_and_traceability", errors)
    _expect_equal(logging, "source_artifacts", expected_sources, "logging_and_traceability source_artifacts", errors)
    _expect_equal(logging, "evidence_entry_count", len(entries), "logging_and_traceability evidence_entry_count", errors)
    _expect_equal(logging, "evidence_entry_types", sorted({entry.get("entry_type") for entry in entries}), "logging_and_traceability evidence_entry_types", errors)

    post_market = _section_content(sections, "post_market_monitoring", errors)
    _expect_equal(post_market, "runtime_attestations", _payloads(entries, "runtime.attested"), "post_market_monitoring runtime_attestations", errors)
    _expect_equal(post_market, "policy_decisions", _payloads(entries, "policy.decision"), "post_market_monitoring policy_decisions", errors)
    _expect_equal(post_market, "incidents", _payloads(entries, "incident.recorded"), "post_market_monitoring incidents", errors)
    _expect_equal(post_market, "demotions", _payloads(entries, "promotion_gate.demoted"), "post_market_monitoring demotions", errors)
    _expect_equal(post_market, "rollbacks", _payloads(entries, "promotion_gate.rolled_back"), "post_market_monitoring rollbacks", errors)

    _verify_evidence_refs(sections, entries, errors)


def _section_content(
    sections: dict[str, dict[str, Any]],
    section_id: str,
    errors: list[str],
) -> dict[str, Any]:
    section = sections.get(section_id)
    if not isinstance(section, dict):
        return {}
    content = section.get("content")
    if not isinstance(content, dict):
        errors.append(f"section {section_id} content must be an object")
        return {}
    return content


def _expect_equal(
    content: dict[str, Any],
    field: str,
    expected: Any,
    label: str,
    errors: list[str],
    *,
    required: bool = True,
) -> None:
    if field not in content:
        if required:
            errors.append(f"{label} missing")
        return
    if content.get(field) != expected:
        errors.append(f"{label} mismatch")


def _verify_evidence_refs(
    sections: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
    errors: list[str],
) -> None:
    entries_by_id = {entry.get("entry_id"): entry for entry in entries if isinstance(entry, dict)}
    for section_id, section in sections.items():
        evidence = section.get("evidence", [])
        if not isinstance(evidence, list):
            errors.append(f"section {section_id} evidence must be a list")
            continue
        for ref in evidence:
            if not isinstance(ref, dict):
                errors.append(f"section {section_id} evidence reference must be an object")
                continue
            entry = entries_by_id.get(ref.get("entry_id"))
            if entry is None:
                errors.append(f"section {section_id} evidence entry is not in supplied sources: {ref.get('entry_id')}")
                continue
            for field in ("entry_type", "index", "timestamp", "payload_hash"):
                if ref.get(field) != entry.get(field):
                    errors.append(f"section {section_id} evidence {ref.get('entry_id')} {field} mismatch")


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
