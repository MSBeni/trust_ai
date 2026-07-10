from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

DESIGN_PARTNER_SCHEMA = "trustai.design-partner-pilot/0.1"
DESIGN_PARTNER_ENTRY_TYPE = "design_partner.pilot_dossier.attested"

DOSSIER_MODES = {"readiness", "external-evidence"}
CONTRACT_STATUSES = {"planned", "negotiating", "signed", "active"}
SCRUTINY_OUTCOMES = {"planned", "submitted", "survived", "accepted", "rejected"}
SCRUTINY_PARTY_TYPES = {"auditor", "regulator", "insurer", "procurement", "internal-audit", "model-risk"}

P1_PARTNER_TARGET = 3
P1_SIGNED_VALUE_TARGET_USD = 250_000

REQUIRED_SOURCE_PATHS = (
    "docs/specs/design-partner-pilot-v0.1.md",
    "docs/specs/proof-pack-v0.1.md",
    "docs/specs/verification-contract-v0.1.md",
    "docs/specs/mcp-gateway-v0.1.md",
    "docs/specs/shadow-replay-v0.1.md",
    "docs/specs/control-plane-v0.1.md",
    "docs/specs/review-portal-service-attestation-v0.1.md",
    "docs/specs/byoc-production-authority-v0.1.md",
    "docs/architecture/roadmap-coverage.md",
    "src/trustai/gate.py",
    "src/trustai/proofpack.py",
    "src/trustai/mcp_gateway.py",
    "src/trustai/shadow.py",
    "src/trustai/cicd.py",
    "src/trustai/review_portal_service.py",
    "src/trustai/byoc_authority.py",
    "examples/aitrade/verification-contract.yaml",
)


@dataclass
class DesignPartnerVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_design_partner_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("design-partner pilot dossier must contain an object")
    return value


def write_design_partner_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def build_design_partner_dossier(
    root: str | Path,
    *,
    dossier_ref: str,
    producer_ref: str,
    partners: list[dict[str, Any]],
    scrutiny_events: list[dict[str, Any]] | None = None,
    mode: str = "readiness",
    environment: str = "local",
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in DOSSIER_MODES:
        raise ValueError(f"mode must be one of {sorted(DOSSIER_MODES)}")
    _require_text(dossier_ref, "dossier_ref")
    _require_text(producer_ref, "producer_ref")
    _require_text(environment, "environment")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)

    normalized_partners = [_normalize_partner(partner) for partner in partners]
    normalized_scrutiny = [_normalize_scrutiny(event) for event in (scrutiny_events or [])]
    source_artifacts = [_file_binding(Path(root), relative_path) for relative_path in REQUIRED_SOURCE_PATHS]
    metrics = _metrics(normalized_partners, normalized_scrutiny)
    body: dict[str, Any] = {
        "schema": DESIGN_PARTNER_SCHEMA,
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "producer_ref": producer_ref,
        "mode": mode,
        "environment": environment,
        "targets": {
            "paying_design_partners": P1_PARTNER_TARGET,
            "signed_pilot_value_usd": P1_SIGNED_VALUE_TARGET_USD,
            "external_scrutiny_survival_events": 1,
        },
        "partners": normalized_partners,
        "external_scrutiny_events": normalized_scrutiny,
        "metrics": metrics,
        "source_artifacts": source_artifacts,
        "controls": _controls(mode, source_artifacts, metrics, normalized_partners, normalized_scrutiny),
        "limitations": [
            "Readiness mode is a local/reference dossier and does not claim real paying customers, ARR, or external acceptance.",
            "External-evidence mode requires redacted external contract and review evidence references, but still stores references and hashes rather than raw customer contracts or private proof packs.",
            "Business milestones remain unproven until customer-owned contracts, payment records, and third-party review artifacts are supplied as external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    return {
        **body,
        "dossier_id": dossier_id,
        "signatures": [sign_value({"dossier_id": dossier_id, "design_partner_pilot": body}, key)],
    }


def verify_design_partner_dossier(
    dossier: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> DesignPartnerVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if dossier.get("schema") != DESIGN_PARTNER_SCHEMA:
        errors.append(f"unsupported design-partner pilot schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical design-partner pilot body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("design-partner pilot dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "design_partner_pilot": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("design-partner pilot signature verification failed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"design-partner pilot generated_at invalid: {exc}")
    for field in ("dossier_ref", "producer_ref", "environment"):
        if not dossier.get(field):
            errors.append(f"design-partner pilot {field} is required")
    mode = dossier.get("mode")
    if mode not in DOSSIER_MODES:
        errors.append("design-partner pilot mode is unsupported")

    partners = dossier.get("partners", [])
    if not isinstance(partners, list):
        errors.append("design-partner pilot partners must be a list")
        partners = []
    normalized_partners: list[dict[str, Any]] = []
    seen_partner_refs: set[str] = set()
    for partner in partners:
        if not isinstance(partner, dict):
            errors.append("design-partner pilot partner must be an object")
            continue
        try:
            normalized = _normalize_partner(partner)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if normalized["partner_ref"] in seen_partner_refs:
            errors.append(f"duplicate design partner ref: {normalized['partner_ref']}")
        seen_partner_refs.add(normalized["partner_ref"])
        if normalized != partner:
            errors.append(f"design partner {normalized['partner_ref']} is not canonical")
        normalized_partners.append(normalized)

    scrutiny_events = dossier.get("external_scrutiny_events", [])
    if not isinstance(scrutiny_events, list):
        errors.append("design-partner pilot external_scrutiny_events must be a list")
        scrutiny_events = []
    normalized_scrutiny: list[dict[str, Any]] = []
    seen_scrutiny_refs: set[str] = set()
    for event in scrutiny_events:
        if not isinstance(event, dict):
            errors.append("design-partner pilot scrutiny event must be an object")
            continue
        try:
            normalized = _normalize_scrutiny(event)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if normalized["scrutiny_ref"] in seen_scrutiny_refs:
            errors.append(f"duplicate external scrutiny ref: {normalized['scrutiny_ref']}")
        seen_scrutiny_refs.add(normalized["scrutiny_ref"])
        if normalized != event:
            errors.append(f"external scrutiny {normalized['scrutiny_ref']} is not canonical")
        if normalized["partner_ref"] not in seen_partner_refs:
            errors.append(f"external scrutiny {normalized['scrutiny_ref']} references unknown partner_ref: {normalized['partner_ref']}")
        normalized_scrutiny.append(normalized)

    expected_metrics = _metrics(normalized_partners, normalized_scrutiny)
    if dossier.get("metrics") != expected_metrics:
        errors.append("design-partner pilot metrics do not match partners and scrutiny events")

    artifacts = dossier.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("design-partner pilot source_artifacts must be a list")
        artifacts = []
    expected_paths = set(REQUIRED_SOURCE_PATHS)
    seen_paths: set[str] = set()
    root_path = Path(root)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("design-partner pilot source artifact must be an object")
            continue
        path = str(artifact.get("path") or "")
        if path in seen_paths:
            errors.append(f"duplicate design-partner pilot source artifact: {path}")
        seen_paths.add(path)
        if path not in expected_paths:
            errors.append(f"unexpected design-partner pilot source artifact: {path}")
            continue
        try:
            expected = _file_binding(root_path, path)
        except FileNotFoundError:
            errors.append(f"design-partner pilot source artifact is missing: {path}")
            continue
        if artifact != expected:
            errors.append(f"design-partner pilot source artifact hash mismatch: {path}")
    missing = sorted(expected_paths - seen_paths)
    if missing:
        errors.append("design-partner pilot source artifacts missing: " + ", ".join(missing))

    if mode in DOSSIER_MODES:
        expected_controls = _controls(str(mode), artifacts, expected_metrics, normalized_partners, normalized_scrutiny)
        if dossier.get("controls") != expected_controls:
            errors.append("design-partner pilot controls do not match dossier body")
        if mode == "readiness":
            warnings.append("readiness mode does not prove paying partners, signed value, or external scrutiny survival")
        elif any(control["status"] == "external-required" for control in expected_controls):
            errors.append("external-evidence mode requires partner contract and scrutiny evidence references for exit-criteria claims")
    return DesignPartnerVerification(ok=not errors, errors=errors, warnings=warnings)


def append_design_partner_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_design_partner_dossier(dossier, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid design-partner pilot dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "dossier_ref": dossier.get("dossier_ref"),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "partner_count": dossier.get("metrics", {}).get("partner_count", 0),
        "signed_partner_count": dossier.get("metrics", {}).get("signed_partner_count", 0),
        "signed_pilot_value_usd": dossier.get("metrics", {}).get("signed_pilot_value_usd", 0),
        "external_scrutiny_survival_count": dossier.get("metrics", {}).get("external_scrutiny_survival_count", 0),
        "source_artifact_count": len(dossier.get("source_artifacts", [])),
        "control_summary": _status_summary(dossier.get("controls", [])),
    }
    return chain.append(DESIGN_PARTNER_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def parse_partner(value: str) -> dict[str, Any]:
    parts = [part.strip() for part in value.split(",")]
    if len(parts) not in {5, 6}:
        raise ValueError("partner must be partner_ref,industry,agent_ref,pilot_value_usd,contract_status[,contract_evidence_ref]")
    partner: dict[str, Any] = {
        "partner_ref": parts[0],
        "industry": parts[1],
        "agent_ref": parts[2],
        "pilot_value_usd": int(parts[3]),
        "contract_status": parts[4],
    }
    if len(parts) == 6 and parts[5]:
        partner["contract_evidence_ref"] = parts[5]
    return partner


def parse_scrutiny(value: str) -> dict[str, Any]:
    parts = [part.strip() for part in value.split(",")]
    if len(parts) not in {5, 6}:
        raise ValueError("scrutiny must be scrutiny_ref,party_type,party_ref,partner_ref,outcome[,evidence_ref]")
    event: dict[str, Any] = {
        "scrutiny_ref": parts[0],
        "party_type": parts[1],
        "party_ref": parts[2],
        "partner_ref": parts[3],
        "outcome": parts[4],
    }
    if len(parts) == 6 and parts[5]:
        event["evidence_ref"] = parts[5]
    return event


def _normalize_partner(partner: dict[str, Any]) -> dict[str, Any]:
    partner_ref = _require_text(str(partner.get("partner_ref") or ""), "partner_ref")
    industry = _require_text(str(partner.get("industry") or ""), "industry")
    agent_ref = _require_text(str(partner.get("agent_ref") or ""), "agent_ref")
    status = str(partner.get("contract_status") or "")
    if status not in CONTRACT_STATUSES:
        raise ValueError(f"design partner {partner_ref} contract_status must be one of {sorted(CONTRACT_STATUSES)}")
    try:
        value = int(partner.get("pilot_value_usd"))
    except (TypeError, ValueError):
        raise ValueError(f"design partner {partner_ref} pilot_value_usd must be an integer")
    if value < 0:
        raise ValueError(f"design partner {partner_ref} pilot_value_usd must be non-negative")
    normalized: dict[str, Any] = {
        "partner_ref": partner_ref,
        "industry": industry,
        "agent_ref": agent_ref,
        "pilot_value_usd": value,
        "contract_status": status,
    }
    evidence_ref = partner.get("contract_evidence_ref")
    if evidence_ref:
        normalized["contract_evidence_ref"] = _require_text(str(evidence_ref), "contract_evidence_ref")
    return normalized


def _normalize_scrutiny(event: dict[str, Any]) -> dict[str, Any]:
    scrutiny_ref = _require_text(str(event.get("scrutiny_ref") or ""), "scrutiny_ref")
    party_type = str(event.get("party_type") or "")
    if party_type not in SCRUTINY_PARTY_TYPES:
        raise ValueError(f"external scrutiny {scrutiny_ref} party_type must be one of {sorted(SCRUTINY_PARTY_TYPES)}")
    outcome = str(event.get("outcome") or "")
    if outcome not in SCRUTINY_OUTCOMES:
        raise ValueError(f"external scrutiny {scrutiny_ref} outcome must be one of {sorted(SCRUTINY_OUTCOMES)}")
    normalized: dict[str, Any] = {
        "scrutiny_ref": scrutiny_ref,
        "party_type": party_type,
        "party_ref": _require_text(str(event.get("party_ref") or ""), "party_ref"),
        "partner_ref": _require_text(str(event.get("partner_ref") or ""), "partner_ref"),
        "outcome": outcome,
    }
    evidence_ref = event.get("evidence_ref")
    if evidence_ref:
        normalized["evidence_ref"] = _require_text(str(evidence_ref), "evidence_ref")
    return normalized


def _metrics(partners: list[dict[str, Any]], scrutiny_events: list[dict[str, Any]]) -> dict[str, int]:
    signed_partners = [partner for partner in partners if partner.get("contract_status") in {"signed", "active"}]
    return {
        "partner_count": len(partners),
        "signed_partner_count": len(signed_partners),
        "signed_pilot_value_usd": sum(int(partner.get("pilot_value_usd", 0)) for partner in signed_partners),
        "external_scrutiny_event_count": len(scrutiny_events),
        "external_scrutiny_survival_count": sum(1 for event in scrutiny_events if event.get("outcome") in {"survived", "accepted"}),
    }


def _controls(
    mode: str,
    source_artifacts: list[dict[str, Any]],
    metrics: dict[str, int],
    partners: list[dict[str, Any]],
    scrutiny_events: list[dict[str, Any]],
) -> list[dict[str, str]]:
    paths = {artifact.get("path") for artifact in source_artifacts if isinstance(artifact, dict)}
    contract_evidence_complete = all(
        partner.get("contract_status") in {"signed", "active"} and partner.get("contract_evidence_ref")
        for partner in partners
    )
    scrutiny_evidence_complete = any(
        event.get("outcome") in {"survived", "accepted"} and event.get("evidence_ref")
        for event in scrutiny_events
    )
    external_claim_ready = mode == "external-evidence"
    return [
        {
            "id": "pilot-partner-count-target",
            "status": "passed" if metrics["partner_count"] >= P1_PARTNER_TARGET else "external-required",
            "detail": "Phase 1 requires at least three design partners with governed agents.",
        },
        {
            "id": "signed-value-target",
            "status": "passed" if external_claim_ready and metrics["signed_pilot_value_usd"] >= P1_SIGNED_VALUE_TARGET_USD and contract_evidence_complete else "external-required",
            "detail": "Phase 1 signed-value claims require customer-owned contract evidence and at least $250k signed.",
        },
        {
            "id": "external-scrutiny-survival-target",
            "status": "passed" if external_claim_ready and scrutiny_evidence_complete else "external-required",
            "detail": "At least one proof pack must survive auditor, regulator, insurer, procurement, or model-risk scrutiny with external evidence.",
        },
        {
            "id": "promotion-gate-source-bound",
            "status": _status(paths, ["src/trustai/gate.py", "docs/specs/verification-contract-v0.1.md"]),
            "detail": "Promotion gate and contract preregistration sources are hash-bound.",
        },
        {
            "id": "proof-pack-source-bound",
            "status": _status(paths, ["src/trustai/proofpack.py", "docs/specs/proof-pack-v0.1.md"]),
            "detail": "Portable proof-pack compiler source and spec are hash-bound.",
        },
        {
            "id": "mcp-shadow-cicd-source-bound",
            "status": _status(paths, ["src/trustai/mcp_gateway.py", "src/trustai/shadow.py", "src/trustai/cicd.py"]),
            "detail": "MCP gateway, shadow replay, and CI/CD gate sources are hash-bound.",
        },
        {
            "id": "auditor-byoc-source-bound",
            "status": _status(paths, ["src/trustai/review_portal_service.py", "src/trustai/byoc_authority.py"]),
            "detail": "Auditor review portal service and BYOC production authority sources are hash-bound.",
        },
        {
            "id": "raw-customer-data-excluded",
            "status": "passed",
            "detail": "Dossier stores references, hashes, values, and statuses, not raw contracts, customer data, or private proof-pack payloads.",
        },
    ]


def _status(paths: set[str], required_paths: list[str]) -> str:
    return "passed" if all(path in paths for path in required_paths) else "failed"


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if not isinstance(controls, list):
        return summary
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _file_binding(root: Path, relative_path: str) -> dict[str, Any]:
    data = (root / relative_path).read_bytes()
    return {
        "path": relative_path,
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"design-partner pilot {field} is required")
    return value.strip()
