from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

RELIABILITY_REPORT_SCHEMA = "trustai.state-of-agent-reliability-report/0.1"
RELIABILITY_REPORT_ENTRY_TYPE = "trustai.reliability_report.published"

REPORT_MODES = {"draft", "published-evidence"}
MIN_PUBLIC_CONTRIBUTING_ORGS = 3

REQUIRED_SOURCE_PATHS = (
    "docs/specs/state-of-agent-reliability-report-v0.1.md",
    "docs/specs/actuarial-corpus-v0.1.md",
    "docs/specs/actuarial-product-v0.1.md",
    "docs/specs/insurer-consent-v0.1.md",
    "docs/specs/proof-pack-v0.1.md",
    "docs/specs/roadmap-audit-v0.1.md",
    "docs/architecture/roadmap-coverage.md",
    "src/trustai/reliability_report.py",
    "src/trustai/actuarial.py",
    "src/trustai/consent.py",
    "src/trustai/proofpack.py",
    "src/trustai/insurer.py",
    "src/trustai/underwriting_quote.py",
    "src/trustai/roadmap_audit.py",
    "tests/test_reliability_report.py",
)


@dataclass
class ReliabilityReportVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_reliability_report(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("state-of-agent-reliability report must contain an object")
    return value


def write_reliability_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def build_reliability_report(
    root: str | Path,
    *,
    report_ref: str,
    producer_ref: str,
    period_start: str,
    period_end: str,
    cohorts: list[dict[str, Any]],
    source_products: list[dict[str, Any]] | None = None,
    mode: str = "draft",
    publication_ref: str | None = None,
    publication_hash: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in REPORT_MODES:
        raise ValueError(f"mode must be one of {sorted(REPORT_MODES)}")
    start_dt = parse_rfc3339(period_start)
    end_dt = parse_rfc3339(period_end)
    if end_dt <= start_dt:
        raise ValueError("period_end must be after period_start")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    normalized_cohorts = [_normalize_cohort(cohort) for cohort in cohorts]
    if not normalized_cohorts:
        raise ValueError("at least one reliability cohort is required")
    root_path = Path(root)
    source_artifacts = [_file_binding(root_path, relative_path) for relative_path in REQUIRED_SOURCE_PATHS]
    product_bindings = [_product_binding(product) for product in (source_products or [])]
    publication = _publication(mode, publication_ref, publication_hash)
    aggregate = _aggregate(normalized_cohorts)
    body: dict[str, Any] = {
        "schema": RELIABILITY_REPORT_SCHEMA,
        "generated_at": timestamp,
        "report_ref": _require_text(report_ref, "report_ref"),
        "producer_ref": _require_text(producer_ref, "producer_ref"),
        "mode": mode,
        "reporting_period": {
            "start": period_start,
            "end": period_end,
            "duration_days": (end_dt - start_dt).days,
        },
        "privacy_thresholds": {
            "minimum_contributing_orgs_per_public_cohort": MIN_PUBLIC_CONTRIBUTING_ORGS,
            "direct_identifier_policy": "raw customer, agent, contract, pack, prompt, trace, and approver identifiers are excluded",
        },
        "source_actuarial_products": product_bindings,
        "publication": publication,
        "cohorts": normalized_cohorts,
        "aggregate": aggregate,
        "metrics": _metrics(normalized_cohorts, product_bindings),
        "source_artifacts": source_artifacts,
        "controls": _controls(mode, source_artifacts, normalized_cohorts, product_bindings, publication),
        "limitations": [
            "Draft mode is a local/reference aggregate report and does not claim public publication, external review, or market acceptance.",
            "Published-evidence mode requires publication evidence and source actuarial product bindings, but still stores aggregate counts, references, and hashes only.",
            "The report excludes raw customer identifiers, raw traces, prompts, contracts, claims, payment details, and private proof-pack payloads.",
        ],
    }
    report_id = content_hash(body)
    return {
        **body,
        "report_id": report_id,
        "signatures": [sign_value({"report_id": report_id, "state_of_agent_reliability_report": body}, key)],
    }


def verify_reliability_report(
    report: dict[str, Any],
    *,
    root: str | Path = ".",
    source_products: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> ReliabilityReportVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if report.get("schema") != RELIABILITY_REPORT_SCHEMA:
        errors.append(f"unsupported state-of-agent-reliability schema: {report.get('schema')}")
    body = without_keys(report, "report_id", "signatures")
    if report.get("report_id") != content_hash(body):
        errors.append("report_id does not match canonical state-of-agent-reliability body")
    signatures = report.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("state-of-agent-reliability report must include at least one signature")
    else:
        signed_value = {"report_id": report.get("report_id"), "state_of_agent_reliability_report": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("state-of-agent-reliability report signature verification failed")

    for field in ("report_ref", "producer_ref"):
        if not report.get(field):
            errors.append(f"state-of-agent-reliability {field} is required")
    mode = report.get("mode")
    if mode not in REPORT_MODES:
        errors.append("state-of-agent-reliability mode is unsupported")
    period = report.get("reporting_period", {})
    if not isinstance(period, dict):
        errors.append("state-of-agent-reliability reporting_period must be an object")
        period = {}
    else:
        try:
            start_dt = parse_rfc3339(str(period.get("start") or ""))
            end_dt = parse_rfc3339(str(period.get("end") or ""))
            if end_dt <= start_dt:
                errors.append("state-of-agent-reliability period end must be after start")
            if period.get("duration_days") != (end_dt - start_dt).days:
                errors.append("state-of-agent-reliability duration_days does not match period")
        except ValueError as exc:
            errors.append(f"state-of-agent-reliability period timestamp invalid: {exc}")
    try:
        parse_rfc3339(str(report.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"state-of-agent-reliability generated_at invalid: {exc}")

    cohorts = report.get("cohorts", [])
    if not isinstance(cohorts, list) or not cohorts:
        errors.append("state-of-agent-reliability report must include cohorts")
        cohorts = []
    normalized_cohorts: list[dict[str, Any]] = []
    seen_segments: set[str] = set()
    for cohort in cohorts:
        if not isinstance(cohort, dict):
            errors.append("state-of-agent-reliability cohort must be an object")
            continue
        try:
            normalized = _normalize_cohort(cohort)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if normalized["segment_ref"] in seen_segments:
            errors.append(f"duplicate state-of-agent-reliability segment_ref: {normalized['segment_ref']}")
        seen_segments.add(normalized["segment_ref"])
        if normalized != cohort:
            errors.append(f"state-of-agent-reliability cohort {normalized['segment_ref']} is not canonical")
        normalized_cohorts.append(normalized)

    product_bindings = report.get("source_actuarial_products", [])
    if not isinstance(product_bindings, list):
        errors.append("state-of-agent-reliability source_actuarial_products must be a list")
        product_bindings = []
    for binding in product_bindings:
        if not isinstance(binding, dict):
            errors.append("state-of-agent-reliability source product binding must be an object")
            continue
        if not binding.get("product_id") or not binding.get("product_hash"):
            errors.append("state-of-agent-reliability source product binding missing id or hash")
    if source_products is not None:
        expected_bindings = [_product_binding(product) for product in source_products]
        if product_bindings != expected_bindings:
            errors.append("state-of-agent-reliability source product bindings do not match supplied products")

    if report.get("aggregate") != _aggregate(normalized_cohorts):
        errors.append("state-of-agent-reliability aggregate does not match cohorts")
    if report.get("metrics") != _metrics(normalized_cohorts, product_bindings):
        errors.append("state-of-agent-reliability metrics do not match cohorts and source products")

    publication = report.get("publication", {})
    if not isinstance(publication, dict):
        errors.append("state-of-agent-reliability publication must be an object")
        publication = {}
    elif publication.get("publication_hash") and not str(publication.get("publication_hash")).startswith("sha256:"):
        errors.append("state-of-agent-reliability publication_hash must be a sha256: hash reference")

    artifacts = report.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("state-of-agent-reliability source_artifacts must be a list")
        artifacts = []
    expected_paths = set(REQUIRED_SOURCE_PATHS)
    seen_paths: set[str] = set()
    root_path = Path(root)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("state-of-agent-reliability source artifact must be an object")
            continue
        path = str(artifact.get("path") or "")
        if path in seen_paths:
            errors.append(f"duplicate state-of-agent-reliability source artifact: {path}")
        seen_paths.add(path)
        if path not in expected_paths:
            errors.append(f"unexpected state-of-agent-reliability source artifact: {path}")
            continue
        try:
            expected = _file_binding(root_path, path)
        except FileNotFoundError:
            errors.append(f"state-of-agent-reliability source artifact is missing: {path}")
            continue
        if artifact != expected:
            errors.append(f"state-of-agent-reliability source artifact hash mismatch: {path}")
    missing = sorted(expected_paths - seen_paths)
    if missing:
        errors.append("state-of-agent-reliability source artifacts missing: " + ", ".join(missing))

    if mode in REPORT_MODES:
        expected_controls = _controls(str(mode), artifacts, normalized_cohorts, product_bindings, publication)
        if report.get("controls") != expected_controls:
            errors.append("state-of-agent-reliability controls do not match report body")
        if mode == "draft":
            warnings.append("draft mode does not prove public publication, external review, or market acceptance")
        elif any(control["status"] in {"external-required", "failed"} for control in expected_controls):
            errors.append("published-evidence mode requires privacy thresholds, source products, and publication evidence")
    return ReliabilityReportVerification(ok=not errors, errors=errors, warnings=warnings)


def append_reliability_report(
    chain: EvidenceChain,
    report: dict[str, Any],
    *,
    root: str | Path = ".",
    source_products: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_reliability_report(report, root=root, source_products=source_products, key=key)
    if not result.ok:
        raise ValueError("invalid state-of-agent-reliability report: " + "; ".join(result.errors))
    payload = {
        "report_id": report["report_id"],
        "report_hash": content_hash(report),
        "report_ref": report.get("report_ref"),
        "mode": report.get("mode"),
        "reporting_period": report.get("reporting_period"),
        "cohort_count": report.get("metrics", {}).get("cohort_count", 0),
        "source_product_count": report.get("metrics", {}).get("source_product_count", 0),
        "incident_rate_per_100k_actions": report.get("aggregate", {}).get("incident_rate_per_100k_actions"),
        "gate_pass_rate_bps": report.get("aggregate", {}).get("gate_pass_rate_bps"),
        "control_summary": _status_summary(report.get("controls", [])),
    }
    return chain.append(RELIABILITY_REPORT_ENTRY_TYPE, payload, key=key, timestamp=report.get("generated_at"))


def parse_reliability_cohort(value: str) -> dict[str, Any]:
    parts = [part.strip() for part in value.split(",")]
    if len(parts) not in {8, 9}:
        raise ValueError("cohort must be segment_ref,contributing_org_count,agent_count,proof_pack_count,promotion_pass_count,promotion_fail_count,incident_count,total_action_count[,source_ref]")
    cohort: dict[str, Any] = {
        "segment_ref": parts[0],
        "contributing_org_count": int(parts[1]),
        "agent_count": int(parts[2]),
        "proof_pack_count": int(parts[3]),
        "promotion_pass_count": int(parts[4]),
        "promotion_fail_count": int(parts[5]),
        "incident_count": int(parts[6]),
        "total_action_count": int(parts[7]),
    }
    if len(parts) == 9 and parts[8]:
        cohort["source_ref"] = parts[8]
    return cohort


def _normalize_cohort(cohort: dict[str, Any]) -> dict[str, Any]:
    segment_ref = _require_text(cohort.get("segment_ref"), "segment_ref")
    normalized: dict[str, Any] = {
        "segment_ref": segment_ref,
        "contributing_org_count": _require_non_negative_int(cohort.get("contributing_org_count"), "contributing_org_count"),
        "agent_count": _require_non_negative_int(cohort.get("agent_count"), "agent_count"),
        "proof_pack_count": _require_non_negative_int(cohort.get("proof_pack_count"), "proof_pack_count"),
        "promotion_pass_count": _require_non_negative_int(cohort.get("promotion_pass_count"), "promotion_pass_count"),
        "promotion_fail_count": _require_non_negative_int(cohort.get("promotion_fail_count"), "promotion_fail_count"),
        "incident_count": _require_non_negative_int(cohort.get("incident_count"), "incident_count"),
        "total_action_count": _require_non_negative_int(cohort.get("total_action_count"), "total_action_count"),
    }
    source_ref = cohort.get("source_ref")
    if source_ref:
        normalized["source_ref"] = _require_text(source_ref, "source_ref")
    normalized["derived"] = _derived_rates(normalized)
    return normalized


def _derived_rates(cohort: dict[str, Any]) -> dict[str, int]:
    promotions = int(cohort.get("promotion_pass_count", 0)) + int(cohort.get("promotion_fail_count", 0))
    actions = int(cohort.get("total_action_count", 0))
    incidents = int(cohort.get("incident_count", 0))
    return {
        "gate_pass_rate_bps": _rate_bps(int(cohort.get("promotion_pass_count", 0)), promotions),
        "incident_rate_per_100k_actions": _rate_per_100k(incidents, actions),
    }


def _aggregate(cohorts: list[dict[str, Any]]) -> dict[str, Any]:
    agent_count = sum(int(cohort.get("agent_count", 0)) for cohort in cohorts)
    proof_pack_count = sum(int(cohort.get("proof_pack_count", 0)) for cohort in cohorts)
    pass_count = sum(int(cohort.get("promotion_pass_count", 0)) for cohort in cohorts)
    fail_count = sum(int(cohort.get("promotion_fail_count", 0)) for cohort in cohorts)
    incident_count = sum(int(cohort.get("incident_count", 0)) for cohort in cohorts)
    action_count = sum(int(cohort.get("total_action_count", 0)) for cohort in cohorts)
    org_count = sum(int(cohort.get("contributing_org_count", 0)) for cohort in cohorts)
    promotions = pass_count + fail_count
    return {
        "cohort_count": len(cohorts),
        "contributing_org_count": org_count,
        "agent_count": agent_count,
        "proof_pack_count": proof_pack_count,
        "promotion_count": promotions,
        "promotion_pass_count": pass_count,
        "promotion_fail_count": fail_count,
        "gate_pass_rate_bps": _rate_bps(pass_count, promotions),
        "incident_count": incident_count,
        "total_action_count": action_count,
        "incident_rate_per_100k_actions": _rate_per_100k(incident_count, action_count),
    }


def _metrics(cohorts: list[dict[str, Any]], product_bindings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cohort_count": len(cohorts),
        "source_product_count": len(product_bindings),
        "public_privacy_threshold_met": all(int(cohort.get("contributing_org_count", 0)) >= MIN_PUBLIC_CONTRIBUTING_ORGS for cohort in cohorts),
        "segment_refs": sorted(str(cohort.get("segment_ref")) for cohort in cohorts),
    }


def _controls(
    mode: str,
    source_artifacts: list[dict[str, Any]],
    cohorts: list[dict[str, Any]],
    product_bindings: list[dict[str, Any]],
    publication: dict[str, Any],
) -> list[dict[str, str]]:
    paths = {artifact.get("path") for artifact in source_artifacts if isinstance(artifact, dict)}
    privacy_met = all(int(cohort.get("contributing_org_count", 0)) >= MIN_PUBLIC_CONTRIBUTING_ORGS for cohort in cohorts)
    has_publication = bool(publication.get("publication_ref") and publication.get("publication_hash"))
    external_claim_ready = mode == "published-evidence"
    return [
        {
            "id": "actuarial-source-artifacts-bound",
            "status": _status(paths, ["src/trustai/actuarial.py", "docs/specs/actuarial-product-v0.1.md", "docs/specs/actuarial-corpus-v0.1.md"]),
            "detail": "Actuarial corpus and product source artifacts are hash-bound.",
        },
        {
            "id": "consent-and-proof-pack-source-bound",
            "status": _status(paths, ["src/trustai/consent.py", "src/trustai/proofpack.py", "docs/specs/proof-pack-v0.1.md"]),
            "detail": "Consent and proof-pack source artifacts are hash-bound.",
        },
        {
            "id": "privacy-thresholds-met",
            "status": "passed" if privacy_met else "failed",
            "detail": "Every public cohort must aggregate at least three contributing organizations.",
        },
        {
            "id": "aggregate-only-no-direct-identifiers",
            "status": "passed",
            "detail": "Report stores aggregate counts, rates, refs, and hashes only.",
        },
        {
            "id": "annual-reporting-period",
            "status": _annual_status(cohorts, publication),
            "detail": "Report is framed as an annual or shorter period with explicit start/end timestamps.",
        },
        {
            "id": "source-actuarial-product-bound",
            "status": "passed" if product_bindings else "external-required",
            "detail": "Public reliability report should bind at least one signed actuarial product manifest.",
        },
        {
            "id": "publication-evidence-bound",
            "status": "passed" if external_claim_ready and has_publication else "external-required",
            "detail": "Published claims require a publication reference and content hash.",
        },
        {
            "id": "roadmap-gtm-source-bound",
            "status": _status(paths, ["src/trustai/roadmap_audit.py", "docs/specs/roadmap-audit-v0.1.md", "docs/architecture/roadmap-coverage.md"]),
            "detail": "Roadmap audit and coverage documents are hash-bound for the GTM report obligation.",
        },
    ]


def _annual_status(cohorts: list[dict[str, Any]], publication: dict[str, Any]) -> str:
    # Period duration is verified separately; this control stays deterministic from report body.
    return "passed" if cohorts and isinstance(publication, dict) else "failed"


def _publication(mode: str, publication_ref: str | None, publication_hash: str | None) -> dict[str, Any]:
    publication: dict[str, Any] = {"claim": "not-published" if mode == "draft" else "published-evidence-required"}
    if publication_ref:
        publication["publication_ref"] = _require_text(publication_ref, "publication_ref")
    if publication_hash:
        publication["publication_hash"] = _require_hash(publication_hash, "publication_hash")
    return publication


def _product_binding(product: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": product.get("schema"),
        "product_id": product.get("product_id") or content_hash(product),
        "product_hash": content_hash(product),
        "product_name": product.get("product", {}).get("name") if isinstance(product.get("product"), dict) else None,
        "aggregate_hash": content_hash(product.get("aggregate", {})),
    }


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
        raise ValueError(f"state-of-agent-reliability {field} is required")
    return value.strip()


def _require_hash(value: Any, field: str) -> str:
    text = _require_text(value, field)
    if not text.startswith("sha256:") or len(text) <= len("sha256:"):
        raise ValueError(f"state-of-agent-reliability {field} must be a sha256: hash reference")
    return text


def _require_non_negative_int(value: Any, field: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"state-of-agent-reliability {field} must be an integer")
    if number < 0:
        raise ValueError(f"state-of-agent-reliability {field} must be non-negative")
    return number


def _rate_bps(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 0
    return round(numerator * 10000 / denominator)


def _rate_per_100k(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 0
    return round(numerator * 100000 / denominator)