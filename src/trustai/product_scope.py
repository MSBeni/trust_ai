from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

PRODUCT_SCOPE_SCHEMA = "trustai.product-scope-decision/0.1"
PRODUCT_SCOPE_ENTRY_TYPE = "trustai.product_scope.decision.attested"

DECISIONS = {"accept", "defer", "decline"}
PROOF_IMPACTS = {"proof-strength", "cheaper-production", "wider-acceptance"}
ANTI_FOCUS_FLAGS = {
    "observability-dashboard",
    "trace-viewer-ux",
    "agent-framework-orchestrator",
    "guardrails-content-safety",
    "eval-library",
    "general-mlops-model-registry",
    "insurer-risk-bearing",
    "consumer-product",
    "non-evidence-analytics",
}

REQUIRED_SOURCE_PATHS = (
    "docs/specs/product-scope-decision-v0.1.md",
    "docs/specs/proof-pack-v0.1.md",
    "docs/specs/verification-contract-v0.1.md",
    "docs/specs/roadmap-audit-v0.1.md",
    "docs/architecture/roadmap-coverage.md",
    "src/trustai/product_scope.py",
    "src/trustai/proofpack.py",
    "src/trustai/verifier.py",
    "src/trustai/gate.py",
    "src/trustai/roadmap_audit.py",
    "tests/test_product_scope.py",
)


@dataclass
class ProductScopeVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_product_scope_decision(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("product scope decision must contain an object")
    return value


def write_product_scope_decision(path: str | Path, decision: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(decision, indent=2, sort_keys=True), encoding="utf-8")


def build_product_scope_decision(
    root: str | Path,
    *,
    decision_ref: str,
    requester_ref: str,
    reviewer_ref: str,
    feature_title: str,
    feature_summary: str,
    decision: str,
    proof_impacts: list[str] | None = None,
    anti_focus_flags: list[str] | None = None,
    rationale: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    normalized_impacts = _normalize_string_set(proof_impacts or [], PROOF_IMPACTS, "proof_impacts")
    normalized_flags = _normalize_string_set(anti_focus_flags or [], ANTI_FOCUS_FLAGS, "anti_focus_flags")
    root_path = Path(root)
    source_artifacts = [_file_binding(root_path, relative_path) for relative_path in REQUIRED_SOURCE_PATHS]
    body: dict[str, Any] = {
        "schema": PRODUCT_SCOPE_SCHEMA,
        "generated_at": timestamp,
        "decision_ref": _require_text(decision_ref, "decision_ref"),
        "requester_ref": _require_text(requester_ref, "requester_ref"),
        "reviewer_ref": _require_text(reviewer_ref, "reviewer_ref"),
        "feature": {
            "title": _require_text(feature_title, "feature_title"),
            "summary": _require_text(feature_summary, "feature_summary"),
        },
        "decision": decision,
        "proof_impacts": normalized_impacts,
        "anti_focus_flags": normalized_flags,
        "rationale": _require_text(rationale or _default_rationale(decision, normalized_impacts, normalized_flags), "rationale"),
        "discipline_test": {
            "question": "Does this make the proof stronger, cheaper to produce, or more widely accepted?",
            "accept_requires_positive_impact": True,
            "anti_focus_requires_decline": True,
        },
        "source_artifacts": source_artifacts,
        "controls": _controls(decision, normalized_impacts, normalized_flags, source_artifacts),
        "limitations": [
            "This receipt records product-scope discipline; it does not replace customer discovery, legal review, security review, or roadmap prioritization.",
            "Accepted decisions still require normal implementation evidence before a production claim can be made.",
            "The receipt stores request summaries, flags, rationale, and source hashes, not private customer requests, contracts, or confidential strategy documents.",
        ],
    }
    decision_id = content_hash(body)
    return {
        **body,
        "decision_id": decision_id,
        "signatures": [sign_value({"decision_id": decision_id, "product_scope_decision": body}, key)],
    }
def verify_product_scope_decision(
    decision_receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> ProductScopeVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if decision_receipt.get("schema") != PRODUCT_SCOPE_SCHEMA:
        errors.append(f"unsupported product scope schema: {decision_receipt.get('schema')}")
    body = without_keys(decision_receipt, "decision_id", "signatures")
    if decision_receipt.get("decision_id") != content_hash(body):
        errors.append("decision_id does not match canonical product scope decision body")
    signatures = decision_receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("product scope decision must include at least one signature")
    else:
        signed_value = {"decision_id": decision_receipt.get("decision_id"), "product_scope_decision": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("product scope decision signature verification failed")
    try:
        parse_rfc3339(str(decision_receipt.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"product scope generated_at invalid: {exc}")
    for field in ("decision_ref", "requester_ref", "reviewer_ref", "rationale"):
        if not decision_receipt.get(field):
            errors.append(f"product scope {field} is required")
    feature = decision_receipt.get("feature", {})
    if not isinstance(feature, dict):
        errors.append("product scope feature must be an object")
        feature = {}
    if not feature.get("title") or not feature.get("summary"):
        errors.append("product scope feature title and summary are required")
    decision = decision_receipt.get("decision")
    if decision not in DECISIONS:
        errors.append("product scope decision is unsupported")

    try:
        impacts = _normalize_string_set(decision_receipt.get("proof_impacts", []), PROOF_IMPACTS, "proof_impacts")
    except ValueError as exc:
        errors.append(str(exc))
        impacts = []
    if decision_receipt.get("proof_impacts") != impacts:
        errors.append("product scope proof_impacts must be sorted unique canonical values")
    try:
        flags = _normalize_string_set(decision_receipt.get("anti_focus_flags", []), ANTI_FOCUS_FLAGS, "anti_focus_flags")
    except ValueError as exc:
        errors.append(str(exc))
        flags = []
    if decision_receipt.get("anti_focus_flags") != flags:
        errors.append("product scope anti_focus_flags must be sorted unique canonical values")

    discipline = decision_receipt.get("discipline_test", {})
    if not isinstance(discipline, dict):
        errors.append("product scope discipline_test must be an object")
    elif not discipline.get("accept_requires_positive_impact") or not discipline.get("anti_focus_requires_decline"):
        errors.append("product scope discipline_test must preserve proof-impact and anti-focus rules")

    artifacts = decision_receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("product scope source_artifacts must be a list")
        artifacts = []
    expected_paths = set(REQUIRED_SOURCE_PATHS)
    seen_paths: set[str] = set()
    root_path = Path(root)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("product scope source artifact must be an object")
            continue
        path = str(artifact.get("path") or "")
        if path in seen_paths:
            errors.append(f"duplicate product scope source artifact: {path}")
        seen_paths.add(path)
        if path not in expected_paths:
            errors.append(f"unexpected product scope source artifact: {path}")
            continue
        try:
            expected = _file_binding(root_path, path)
        except FileNotFoundError:
            errors.append(f"product scope source artifact is missing: {path}")
            continue
        if artifact != expected:
            errors.append(f"product scope source artifact hash mismatch: {path}")
    missing = sorted(expected_paths - seen_paths)
    if missing:
        errors.append("product scope source artifacts missing: " + ", ".join(missing))

    if decision in DECISIONS:
        expected_controls = _controls(str(decision), impacts, flags, artifacts)
        if decision_receipt.get("controls") != expected_controls:
            errors.append("product scope controls do not match decision body")
        if any(control["status"] == "failed" for control in expected_controls):
            errors.append("product scope decision violates roadmap discipline test")
        if decision == "decline":
            warnings.append("declined decision records scope discipline but does not produce implementation work")
    return ProductScopeVerification(ok=not errors, errors=errors, warnings=warnings)


def append_product_scope_decision(
    chain: EvidenceChain,
    decision_receipt: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_product_scope_decision(decision_receipt, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid product scope decision: " + "; ".join(result.errors))
    payload = {
        "decision_id": decision_receipt["decision_id"],
        "decision_hash": content_hash(decision_receipt),
        "decision_ref": decision_receipt.get("decision_ref"),
        "decision": decision_receipt.get("decision"),
        "feature_title": decision_receipt.get("feature", {}).get("title"),
        "proof_impacts": decision_receipt.get("proof_impacts", []),
        "anti_focus_flags": decision_receipt.get("anti_focus_flags", []),
        "control_summary": _status_summary(decision_receipt.get("controls", [])),
    }
    return chain.append(PRODUCT_SCOPE_ENTRY_TYPE, payload, key=key, timestamp=decision_receipt.get("generated_at"))
def _controls(
    decision: str,
    proof_impacts: list[str],
    anti_focus_flags: list[str],
    source_artifacts: list[dict[str, Any]],
) -> list[dict[str, str]]:
    paths = {artifact.get("path") for artifact in source_artifacts if isinstance(artifact, dict)}
    has_impact = bool(proof_impacts)
    has_anti_focus = bool(anti_focus_flags)
    decision_is_decline = decision == "decline"
    return [
        {
            "id": "discipline-test-recorded",
            "status": "passed" if has_impact or decision_is_decline else "failed",
            "detail": "A request with no proof-strength, cheaper-production, or wider-acceptance impact must be declined.",
        },
        {
            "id": "accept-requires-proof-impact",
            "status": "passed" if decision != "accept" or has_impact else "failed",
            "detail": "Accepted scope decisions require at least one positive proof impact.",
        },
        {
            "id": "anti-focus-requires-decline",
            "status": "passed" if not has_anti_focus or decision_is_decline else "failed",
            "detail": "Requests matching anti-focus categories must be declined rather than accepted or deferred.",
        },
        {
            "id": "neutrality-preserved",
            "status": "passed" if decision_is_decline or "agent-framework-orchestrator" not in anti_focus_flags else "failed",
            "detail": "TrustAI must not become an agent framework or orchestrator.",
        },
        {
            "id": "observability-dashboard-competition-avoided",
            "status": "passed" if decision_is_decline or not {"observability-dashboard", "trace-viewer-ux", "non-evidence-analytics"}.intersection(anti_focus_flags) else "failed",
            "detail": "TrustAI ingests traces but does not compete on dashboard or trace-viewer UX.",
        },
        {
            "id": "insurer-risk-bearing-avoided",
            "status": "passed" if decision_is_decline or "insurer-risk-bearing" not in anti_focus_flags else "failed",
            "detail": "TrustAI sells underwriting data and must not hold insurance risk.",
        },
        {
            "id": "consumer-scope-avoided",
            "status": "passed" if decision_is_decline or "consumer-product" not in anti_focus_flags else "failed",
            "detail": "The roadmap explicitly excludes consumer products.",
        },
        {
            "id": "roadmap-scope-source-bound",
            "status": _status(paths, ["docs/architecture/roadmap-coverage.md", "src/trustai/roadmap_audit.py", "docs/specs/roadmap-audit-v0.1.md"]),
            "detail": "Roadmap coverage and audit sources are hash-bound.",
        },
        {
            "id": "proof-surface-source-bound",
            "status": _status(paths, ["src/trustai/proofpack.py", "src/trustai/verifier.py", "src/trustai/gate.py", "docs/specs/proof-pack-v0.1.md", "docs/specs/verification-contract-v0.1.md"]),
            "detail": "Proof-pack, verifier, gate, and verification-contract sources are hash-bound for the scope discipline test.",
        },
        {
            "id": "raw-private-request-data-excluded",
            "status": "passed",
            "detail": "Decision receipts store request summaries, flags, and rationale, not private customer requests or confidential strategy documents.",
        },
    ]


def _default_rationale(decision: str, proof_impacts: list[str], anti_focus_flags: list[str]) -> str:
    if decision == "decline" and anti_focus_flags:
        return "Declined because the request maps to explicit roadmap anti-focus categories."
    if decision == "decline":
        return "Declined because the request does not satisfy the roadmap proof discipline test."
    return "Decision is based on the recorded proof impacts and anti-focus screen."


def _normalize_string_set(values: Any, allowed: set[str], field: str) -> list[str]:
    if not isinstance(values, list):
        raise ValueError(f"product scope {field} must be a list")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"product scope {field} values must be non-empty strings")
        text = value.strip()
        if text not in allowed:
            raise ValueError(f"product scope {field} value must be one of {sorted(allowed)}")
        normalized.append(text)
    return sorted(set(normalized))


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
        raise ValueError(f"product scope {field} is required")
    return value.strip()