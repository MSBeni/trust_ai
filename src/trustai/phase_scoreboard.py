from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

PHASE_SCOREBOARD_SCHEMA = "trustai.roadmap-phase-scoreboard/0.1"
PHASE_SCOREBOARD_ENTRY_TYPE = "trustai.roadmap_phase_scoreboard.attested"

PHASE_SCOREBOARD_MODES = {"readiness", "external-evidence"}
PHASES = {"P1", "P2", "P3", "P4"}
MILESTONE_KINDS = {
    "paying-design-partner",
    "signed-pilot-value",
    "external-scrutiny-survival",
    "customer-count",
    "arr",
    "vertical-beyond-finserv",
    "insurer-integration-live",
    "own-soc2-type-ii",
    "own-iso-42001",
    "series-a",
    "regulator-acceptance",
    "insurer-pricing",
    "standards-track",
    "procurement-contract",
    "data-product-revenue",
    "generic-market-usage",
}

PHASE_TARGETS = {
    "P1": {"paying_design_partners": 3, "signed_pilot_value_usd": 250_000, "external_scrutiny_survival_events": 1},
    "P2": {"customers_min": 15, "arr_min_usd": 1_000_000, "verticals_beyond_finserv": 2, "insurer_integrations_live": 1, "series_a_closed": 1, "own_soc2_type_ii": 1, "own_iso_42001": 1},
    "P3": {"arr_min_usd": 8_000_000, "regulator_acceptances": 1, "insurers_pricing_on_packs": 2, "standards_track": 1},
    "P4": {"procurement_contracts": 1, "data_product_revenue_usd_min": 1, "generic_market_usage_evidence": 1},
}

REQUIRED_SOURCE_PATHS = (
    "docs/specs/roadmap-phase-scoreboard-v0.1.md",
    "docs/specs/design-partner-pilot-v0.1.md",
    "docs/specs/own-compliance-dossier-v0.1.md",
    "docs/specs/underwriting-quote-v0.1.md",
    "docs/specs/regulator-acceptance-v0.1.md",
    "docs/specs/standards-body-submission-v0.1.md",
    "docs/specs/procurement-clause-v0.1.md",
    "docs/specs/actuarial-product-v0.1.md",
    "docs/specs/state-of-agent-reliability-report-v0.1.md",
    "docs/specs/roadmap-audit-v0.1.md",
    "docs/architecture/roadmap-coverage.md",
    "src/trustai/phase_scoreboard.py",
    "src/trustai/design_partner.py",
    "src/trustai/own_compliance.py",
    "src/trustai/underwriting_quote.py",
    "src/trustai/regulator_acceptance.py",
    "src/trustai/standards_body_submission.py",
    "src/trustai/procurement_clause.py",
    "src/trustai/actuarial.py",
    "src/trustai/reliability_report.py",
    "src/trustai/roadmap_audit.py",
    "tests/test_phase_scoreboard.py",
)


@dataclass
class PhaseScoreboardVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_phase_scoreboard(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("roadmap phase scoreboard must contain an object")
    return value


def write_phase_scoreboard(path: str | Path, scoreboard: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(scoreboard, indent=2, sort_keys=True), encoding="utf-8")


def build_phase_scoreboard(
    root: str | Path,
    *,
    scoreboard_ref: str,
    producer_ref: str,
    milestones: list[dict[str, Any]] | None = None,
    mode: str = "readiness",
    environment: str = "local",
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in PHASE_SCOREBOARD_MODES:
        raise ValueError(f"mode must be one of {sorted(PHASE_SCOREBOARD_MODES)}")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    normalized_milestones = [_normalize_milestone(item) for item in (milestones or [])]
    root_path = Path(root)
    source_artifacts = [_file_binding(root_path, relative_path) for relative_path in REQUIRED_SOURCE_PATHS]
    metrics = _metrics(normalized_milestones, source_artifacts)
    body: dict[str, Any] = {
        "schema": PHASE_SCOREBOARD_SCHEMA,
        "generated_at": timestamp,
        "scoreboard_ref": _require_text(scoreboard_ref, "scoreboard_ref"),
        "producer_ref": _require_text(producer_ref, "producer_ref"),
        "mode": mode,
        "environment": _require_text(environment, "environment"),
        "targets": PHASE_TARGETS,
        "milestones": normalized_milestones,
        "metrics": metrics,
        "source_artifacts": source_artifacts,
        "controls": _controls(mode, source_artifacts, normalized_milestones),
        "limitations": [
            "Readiness mode proves local/reference evidence plumbing for the roadmap scoreboard only; it does not claim ARR, customers, regulator acceptance, insurer pricing, procurement adoption, or market usage.",
            "External-evidence mode requires redacted external evidence references and hashes for every claimed phase exit criterion.",
            "The scoreboard stores counters, references, hashes, issuers, and timestamps, not raw contracts, revenue ledgers, customer proof packs, regulator correspondence, insurer pricing files, or private market research.",
        ],
    }
    scoreboard_id = content_hash(body)
    return {
        **body,
        "scoreboard_id": scoreboard_id,
        "signatures": [sign_value({"scoreboard_id": scoreboard_id, "roadmap_phase_scoreboard": body}, key)],
    }
def verify_phase_scoreboard(
    scoreboard: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> PhaseScoreboardVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if scoreboard.get("schema") != PHASE_SCOREBOARD_SCHEMA:
        errors.append(f"unsupported roadmap phase scoreboard schema: {scoreboard.get('schema')}")
    body = without_keys(scoreboard, "scoreboard_id", "signatures")
    if scoreboard.get("scoreboard_id") != content_hash(body):
        errors.append("scoreboard_id does not match canonical roadmap phase scoreboard body")
    signatures = scoreboard.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("roadmap phase scoreboard must include at least one signature")
    else:
        signed_value = {"scoreboard_id": scoreboard.get("scoreboard_id"), "roadmap_phase_scoreboard": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("roadmap phase scoreboard signature verification failed")
    try:
        parse_rfc3339(str(scoreboard.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"roadmap phase scoreboard generated_at invalid: {exc}")
    for field in ("scoreboard_ref", "producer_ref", "environment"):
        if not scoreboard.get(field):
            errors.append(f"roadmap phase scoreboard {field} is required")
    mode = scoreboard.get("mode")
    if mode not in PHASE_SCOREBOARD_MODES:
        errors.append("roadmap phase scoreboard mode is unsupported")

    milestones = scoreboard.get("milestones", [])
    if not isinstance(milestones, list):
        errors.append("roadmap phase scoreboard milestones must be a list")
        milestones = []
    normalized_milestones: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_refs: set[str] = set()
    for milestone in milestones:
        if not isinstance(milestone, dict):
            errors.append("roadmap phase scoreboard milestone must be an object")
            continue
        try:
            normalized = _normalize_milestone(milestone)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if normalized["milestone_id"] in seen_ids:
            errors.append(f"duplicate roadmap phase scoreboard milestone id: {normalized['milestone_id']}")
        if normalized["evidence_ref"] in seen_refs:
            errors.append(f"duplicate roadmap phase scoreboard evidence ref: {normalized['evidence_ref']}")
        seen_ids.add(normalized["milestone_id"])
        seen_refs.add(normalized["evidence_ref"])
        if normalized != milestone:
            errors.append(f"roadmap phase scoreboard milestone {normalized['evidence_ref']} is not canonical")
        normalized_milestones.append(normalized)

    artifacts = scoreboard.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("roadmap phase scoreboard source_artifacts must be a list")
        artifacts = []
    expected_paths = set(REQUIRED_SOURCE_PATHS)
    seen_paths: set[str] = set()
    root_path = Path(root)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("roadmap phase scoreboard source artifact must be an object")
            continue
        path = str(artifact.get("path") or "")
        if path in seen_paths:
            errors.append(f"duplicate roadmap phase scoreboard source artifact: {path}")
        seen_paths.add(path)
        if path not in expected_paths:
            errors.append(f"unexpected roadmap phase scoreboard source artifact: {path}")
            continue
        try:
            expected = _file_binding(root_path, path)
        except FileNotFoundError:
            errors.append(f"roadmap phase scoreboard source artifact is missing: {path}")
            continue
        if artifact != expected:
            errors.append(f"roadmap phase scoreboard source artifact hash mismatch: {path}")
    missing = sorted(expected_paths - seen_paths)
    if missing:
        errors.append("roadmap phase scoreboard source artifacts missing: " + ", ".join(missing))

    expected_metrics = _metrics(normalized_milestones, artifacts)
    if scoreboard.get("metrics") != expected_metrics:
        errors.append("roadmap phase scoreboard metrics do not match milestones and source artifacts")
    if mode in PHASE_SCOREBOARD_MODES:
        expected_controls = _controls(str(mode), artifacts, normalized_milestones)
        if scoreboard.get("controls") != expected_controls:
            errors.append("roadmap phase scoreboard controls do not match scoreboard body")
        if mode == "readiness":
            warnings.append("readiness mode does not prove roadmap business milestones or market adoption")
        elif any(control["status"] == "external-required" for control in expected_controls):
            errors.append("external-evidence mode requires evidence references for all phase scoreboard exit criteria")
    return PhaseScoreboardVerification(ok=not errors, errors=errors, warnings=warnings)


def append_phase_scoreboard(
    chain: EvidenceChain,
    scoreboard: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_phase_scoreboard(scoreboard, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid roadmap phase scoreboard: " + "; ".join(result.errors))
    payload = {
        "scoreboard_id": scoreboard["scoreboard_id"],
        "scoreboard_hash": content_hash(scoreboard),
        "scoreboard_ref": scoreboard.get("scoreboard_ref"),
        "mode": scoreboard.get("mode"),
        "environment": scoreboard.get("environment"),
        "milestone_count": scoreboard.get("metrics", {}).get("milestone_count", 0),
        "phase_counts": scoreboard.get("metrics", {}).get("phase_counts", {}),
        "control_summary": _status_summary(scoreboard.get("controls", [])),
    }
    return chain.append(PHASE_SCOREBOARD_ENTRY_TYPE, payload, key=key, timestamp=scoreboard.get("generated_at"))
def parse_phase_milestone(value: str) -> dict[str, Any]:
    parts = [part.strip() for part in value.split(",")]
    if len(parts) not in {7, 8}:
        raise ValueError("milestone must be phase,kind,metric_value,evidence_ref,evidence_hash,issuer,issued_at[,expires_at]")
    milestone: dict[str, Any] = {
        "phase": parts[0],
        "kind": parts[1],
        "metric_value": int(parts[2]),
        "evidence_ref": parts[3],
        "evidence_hash": parts[4],
        "issuer": parts[5],
        "issued_at": parts[6],
    }
    if len(parts) == 8 and parts[7]:
        milestone["expires_at"] = parts[7]
    return milestone


def _normalize_milestone(milestone: dict[str, Any]) -> dict[str, Any]:
    phase = str(milestone.get("phase") or "")
    if phase not in PHASES:
        raise ValueError(f"roadmap phase scoreboard phase must be one of {sorted(PHASES)}")
    kind = str(milestone.get("kind") or "")
    if kind not in MILESTONE_KINDS:
        raise ValueError(f"roadmap phase scoreboard kind must be one of {sorted(MILESTONE_KINDS)}")
    try:
        metric_value = int(milestone.get("metric_value"))
    except (TypeError, ValueError):
        raise ValueError("roadmap phase scoreboard metric_value must be an integer")
    if metric_value < 0:
        raise ValueError("roadmap phase scoreboard metric_value must be non-negative")
    issued_at = _require_text(milestone.get("issued_at"), "issued_at")
    parse_rfc3339(issued_at)
    normalized: dict[str, Any] = {
        "phase": phase,
        "kind": kind,
        "metric_value": metric_value,
        "evidence_ref": _require_text(milestone.get("evidence_ref"), "evidence_ref"),
        "evidence_hash": _require_hash(milestone.get("evidence_hash"), "evidence_hash"),
        "issuer": _require_text(milestone.get("issuer"), "issuer"),
        "issued_at": issued_at,
    }
    expires_at = milestone.get("expires_at")
    if expires_at:
        expires_at_text = _require_text(expires_at, "expires_at")
        parse_rfc3339(expires_at_text)
        normalized["expires_at"] = expires_at_text
    normalized["milestone_id"] = content_hash(normalized)
    return normalized


def _metrics(milestones: list[dict[str, Any]], source_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    phase_counts = {phase: 0 for phase in sorted(PHASES)}
    kind_totals: dict[str, int] = {}
    for milestone in milestones:
        phase = str(milestone.get("phase"))
        kind = str(milestone.get("kind"))
        metric_value = int(milestone.get("metric_value", 0))
        if phase in phase_counts:
            phase_counts[phase] += 1
        key = f"{phase}:{kind}"
        kind_totals[key] = kind_totals.get(key, 0) + metric_value
    return {
        "milestone_count": len(milestones),
        "phase_counts": phase_counts,
        "kind_totals": dict(sorted(kind_totals.items())),
        "source_artifact_count": len(source_artifacts),
    }


def _controls(mode: str, source_artifacts: list[dict[str, Any]], milestones: list[dict[str, Any]]) -> list[dict[str, str]]:
    paths = {artifact.get("path") for artifact in source_artifacts if isinstance(artifact, dict)}
    external_claim_ready = mode == "external-evidence"

    def total(phase: str, kind: str) -> int:
        return sum(int(item.get("metric_value", 0)) for item in milestones if item.get("phase") == phase and item.get("kind") == kind)

    return [
        {
            "id": "p1-paying-design-partner-target",
            "status": "passed" if external_claim_ready and total("P1", "paying-design-partner") >= PHASE_TARGETS["P1"]["paying_design_partners"] else "external-required",
            "detail": "Phase 1 requires at least three paying design partners.",
        },
        {
            "id": "p1-signed-pilot-value-target",
            "status": "passed" if external_claim_ready and total("P1", "signed-pilot-value") >= PHASE_TARGETS["P1"]["signed_pilot_value_usd"] else "external-required",
            "detail": "Phase 1 requires at least $250k signed pilot value.",
        },
        {
            "id": "p1-external-scrutiny-survival-target",
            "status": "passed" if external_claim_ready and total("P1", "external-scrutiny-survival") >= PHASE_TARGETS["P1"]["external_scrutiny_survival_events"] else "external-required",
            "detail": "Phase 1 requires at least one proof pack to survive external scrutiny.",
        },
        {
            "id": "p2-customer-count-target",
            "status": "passed" if external_claim_ready and total("P2", "customer-count") >= PHASE_TARGETS["P2"]["customers_min"] else "external-required",
            "detail": "Phase 2 requires at least fifteen customers.",
        },
        {
            "id": "p2-arr-and-series-a-target",
            "status": "passed" if external_claim_ready and total("P2", "arr") >= PHASE_TARGETS["P2"]["arr_min_usd"] and total("P2", "series-a") >= PHASE_TARGETS["P2"]["series_a_closed"] else "external-required",
            "detail": "Phase 2 requires $1M+ ARR and a Series A financing milestone.",
        },
        {
            "id": "p2-vertical-expansion-target",
            "status": "passed" if external_claim_ready and total("P2", "vertical-beyond-finserv") >= PHASE_TARGETS["P2"]["verticals_beyond_finserv"] else "external-required",
            "detail": "Phase 2 requires at least two verticals beyond financial services.",
        },
        {
            "id": "p2-insurer-and-own-compliance-target",
            "status": "passed" if external_claim_ready and total("P2", "insurer-integration-live") >= 1 and total("P2", "own-soc2-type-ii") >= 1 and total("P2", "own-iso-42001") >= 1 else "external-required",
            "detail": "Phase 2 requires a live insurer integration plus TrustAI SOC 2 Type II and ISO/IEC 42001 evidence.",
        },
        {
            "id": "p3-arr-scale-target",
            "status": "passed" if external_claim_ready and total("P3", "arr") >= PHASE_TARGETS["P3"]["arr_min_usd"] else "external-required",
            "detail": "Phase 3 requires at least $8M ARR.",
        },
        {
            "id": "p3-regulator-insurer-standards-target",
            "status": "passed" if external_claim_ready and total("P3", "regulator-acceptance") >= 1 and total("P3", "insurer-pricing") >= 2 and total("P3", "standards-track") >= 1 else "external-required",
            "detail": "Phase 3 requires regulator acceptance, two insurers pricing on packs, and standards-track status.",
        },
        {
            "id": "p4-network-data-market-target",
            "status": "passed" if external_claim_ready and total("P4", "procurement-contract") >= 1 and total("P4", "data-product-revenue") >= 1 and total("P4", "generic-market-usage") >= 1 else "external-required",
            "detail": "Phase 4 requires third-party procurement clauses, data-product revenue, and generic market usage evidence.",
        },
        {
            "id": "roadmap-business-source-artifacts-bound",
            "status": _status(paths, ["src/trustai/design_partner.py", "src/trustai/own_compliance.py", "src/trustai/underwriting_quote.py", "src/trustai/regulator_acceptance.py", "src/trustai/standards_body_submission.py", "src/trustai/procurement_clause.py", "src/trustai/actuarial.py", "src/trustai/reliability_report.py", "src/trustai/roadmap_audit.py"]),
            "detail": "Existing local/reference evidence surfaces for scoreboard milestones are hash-bound.",
        },
        {
            "id": "raw-business-sensitive-data-excluded",
            "status": "passed",
            "detail": "Scoreboard stores counters, references, hashes, issuers, and timestamps only.",
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
        raise ValueError(f"roadmap phase scoreboard {field} is required")
    return value.strip()


def _require_hash(value: Any, field: str) -> str:
    text = _require_text(value, field)
    if not text.startswith("sha256:") or len(text) <= len("sha256:"):
        raise ValueError(f"roadmap phase scoreboard {field} must be a sha256: hash reference")
    return text