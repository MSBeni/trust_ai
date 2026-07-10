from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .standards_body_submission import (
    SUBMISSION_STATUSES,
    verify_standards_body_submission_receipt,
)

STANDARDS_BODY_STATUS_SCHEMA = "trustai.standards-body-status/0.1"
STANDARDS_BODY_STATUS_ENTRY_TYPE = "standards.body.status.updated"

STANDARDS_BODY_STATUSES = {
    "acknowledged",
    "under_review",
    "ballot_open",
    "changes_requested",
    "accepted",
    "rejected",
    "withdrawn",
}
FINAL_STATUSES = {"accepted", "rejected", "withdrawn"}


@dataclass
class StandardsBodyStatusVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    previous_status: str | None = None
    new_status: str | None = None


def build_standards_body_status_receipt(
    submission_receipt: dict[str, Any],
    *,
    new_status: str,
    actor_ref: str,
    root: str | Path = ".",
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    docket_ref: str | None = None,
    status_ref: str | None = None,
    decision_ref: str | None = None,
    ballot_ref: str | None = None,
    ballot_opened_at: str | None = None,
    ballot_closed_at: str | None = None,
    votes_for: int | None = None,
    votes_against: int | None = None,
    abstentions: int | None = None,
    quorum: int | None = None,
    comments_ref: str | None = None,
    reason: str | None = None,
    evidence_refs: list[str] | None = None,
    actor_role: str = "standards-body-operator",
    decided_at: str | None = None,
    effective_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if new_status not in STANDARDS_BODY_STATUSES:
        raise ValueError(
            "new_status must be acknowledged, under_review, ballot_open, changes_requested, accepted, rejected, or withdrawn"
        )
    _require_text(actor_ref, "actor_ref")
    _require_text(actor_role, "actor_role")
    if new_status == "ballot_open" and not ballot_ref:
        raise ValueError("ballot_open status requires ballot_ref")
    if new_status in {"accepted", "rejected"} and not (decision_ref or ballot_ref):
        raise ValueError("accepted or rejected status requires decision_ref or ballot_ref")

    decided = decided_at or utc_now()
    effective = effective_at or decided
    parse_rfc3339(decided)
    parse_rfc3339(effective)
    if parse_rfc3339(effective) < parse_rfc3339(decided):
        raise ValueError("standards-body status effective_at must be at or after decided_at")
    _validate_ballot_window(ballot_opened_at, ballot_closed_at)

    submission_result = verify_standards_body_submission_receipt(
        submission_receipt,
        standards_package=standards_package,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not submission_result.ok:
        raise ValueError("invalid standards-body submission receipt: " + "; ".join(submission_result.errors))
    previous_status = submission_receipt.get("submission", {}).get("status")
    if previous_status == new_status:
        raise ValueError("new_status must differ from standards-body submission status")

    target = _target_record(submission_receipt)
    ballot = {
        "ballot_ref": ballot_ref,
        "opened_at": ballot_opened_at,
        "closed_at": ballot_closed_at,
        "votes_for": votes_for,
        "votes_against": votes_against,
        "abstentions": abstentions,
        "quorum": quorum,
        "comments_ref": comments_ref,
    }
    status_update = {
        "previous_status": previous_status,
        "new_status": new_status,
        "docket_ref": docket_ref or submission_receipt.get("submission", {}).get("submission_ref"),
        "status_ref": status_ref
        or content_hash(
            {
                "submission_id": submission_receipt.get("submission_id"),
                "new_status": new_status,
                "effective_at": effective,
            }
        )[:32],
        "decision_ref": decision_ref,
        "reason": reason,
        "decided_at": decided,
        "effective_at": effective,
        "actor": {
            "ref": actor_ref,
            "role": actor_role,
            "attestation_mode": "local-reference",
            "production_replacement": "authenticated standards-body docket, working-group, or ballot-system event",
        },
        "ballot": ballot,
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    status_update["status_payload_hash"] = _status_payload_hash(target, status_update)
    body = {
        "schema": STANDARDS_BODY_STATUS_SCHEMA,
        "decided_at": decided,
        "effective_at": effective,
        "target_submission": target,
        "status_update": status_update,
        "source_artifacts": [_submission_artifact(submission_receipt)],
        "controls": _controls_for(new_status, bool(docket_ref), bool(decision_ref), bool(ballot_ref)),
        "limitations": [
            "This receipt records a local-reference standards-body docket status update.",
            "It binds the status update to a signed standards-body submission receipt by canonical hash.",
            "It can model acknowledgement, review, ballot, final acceptance, rejection, or withdrawal status without claiming external standards-body authority.",
            "Production deployments should replace this local receipt with an authenticated standards-body docket event, ballot record, and propagation audit.",
        ],
    }
    status_id = content_hash(body)
    return {
        **body,
        "status_id": status_id,
        "signatures": [sign_value({"status_id": status_id, "status": body}, key)],
    }


def verify_standards_body_status_receipt(
    receipt: dict[str, Any],
    *,
    submission_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> StandardsBodyStatusVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != STANDARDS_BODY_STATUS_SCHEMA:
        errors.append(f"unsupported standards-body status schema: {receipt.get('schema')}")
    body = without_keys(receipt, "status_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("status_id") != expected_id:
        errors.append("status_id does not match canonical standards-body status body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("standards-body status receipt missing signature")
    else:
        signed_value = {"status_id": receipt.get("status_id"), "status": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("standards-body status receipt signature invalid")

    _verify_times(receipt, now, errors)
    target = receipt.get("target_submission", {})
    if not isinstance(target, dict) or not target.get("submission_id") or not target.get("submission_ref"):
        errors.append("standards-body status target submission_id and submission_ref are required")

    update = receipt.get("status_update", {})
    if not isinstance(update, dict):
        errors.append("standards-body status_update must be an object")
        update = {}
    previous_status = update.get("previous_status")
    new_status = update.get("new_status")
    if previous_status not in SUBMISSION_STATUSES:
        errors.append("standards-body previous_status is unsupported")
    if new_status not in STANDARDS_BODY_STATUSES:
        errors.append("standards-body new_status is unsupported")
    if previous_status == new_status:
        errors.append("standards-body status update must change status")
    if not update.get("docket_ref") or not update.get("status_ref"):
        errors.append("standards-body docket_ref and status_ref are required")
    if new_status == "ballot_open" and not (update.get("ballot") or {}).get("ballot_ref"):
        errors.append("standards-body ballot_open status requires ballot_ref")
    if new_status in {"accepted", "rejected"} and not (update.get("decision_ref") or (update.get("ballot") or {}).get("ballot_ref")):
        errors.append("standards-body accepted or rejected status requires decision_ref or ballot_ref")
    actor = update.get("actor", {})
    if not isinstance(actor, dict) or not actor.get("ref") or not actor.get("role"):
        errors.append("standards-body status actor ref and role are required")
    ballot = update.get("ballot", {})
    if not isinstance(ballot, dict):
        errors.append("standards-body status ballot must be an object")
        ballot = {}
    try:
        _validate_ballot_window(ballot.get("opened_at"), ballot.get("closed_at"))
    except ValueError as exc:
        errors.append(str(exc))

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("standards-body status receipt must include exactly one submission source artifact")
        artifacts = []
    artifact = artifacts[0] if artifacts and isinstance(artifacts[0], dict) else None
    if artifact and artifact.get("name") != "standards_body_submission_receipt":
        errors.append("standards-body status source artifact must be standards_body_submission_receipt")

    if submission_receipt is None:
        warnings.append("standards-body submission source not supplied; verified status binding only")
    else:
        submission_result = verify_standards_body_submission_receipt(
            submission_receipt,
            standards_package=standards_package,
            verifier_release=verifier_release,
            conformance_report=conformance_report,
            root=root,
            key=key,
        )
        if not submission_result.ok:
            errors.extend(f"source standards-body submission receipt invalid: {error}" for error in submission_result.errors)
        warnings.extend(f"source standards-body submission warning: {warning}" for warning in submission_result.warnings)
        _compare_artifact(artifact, _submission_artifact(submission_receipt), errors)
        expected_target = _target_record(submission_receipt)
        if target != expected_target:
            errors.append("standards-body status target does not match source submission receipt")
        source_status = submission_receipt.get("submission", {}).get("status")
        if previous_status != source_status:
            errors.append("standards-body status previous_status does not match source submission receipt")

    expected_payload_hash = _status_payload_hash(target, update)
    if update.get("status_payload_hash") != expected_payload_hash:
        errors.append("standards-body status payload hash does not match status update")

    return StandardsBodyStatusVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        previous_status=previous_status,
        new_status=new_status,
    )


def append_standards_body_status_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    submission_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_standards_body_status_receipt(
        receipt,
        submission_receipt=submission_receipt,
        standards_package=standards_package,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid standards-body status receipt: " + "; ".join(result.errors))
    payload = {
        "status_id": receipt["status_id"],
        "status_hash": content_hash(receipt),
        "target_submission": receipt.get("target_submission"),
        "status_update": {
            "previous_status": receipt.get("status_update", {}).get("previous_status"),
            "new_status": receipt.get("status_update", {}).get("new_status"),
            "docket_ref": receipt.get("status_update", {}).get("docket_ref"),
            "status_ref": receipt.get("status_update", {}).get("status_ref"),
            "decision_ref": receipt.get("status_update", {}).get("decision_ref"),
            "effective_at": receipt.get("effective_at"),
            "actor": receipt.get("status_update", {}).get("actor"),
            "ballot": receipt.get("status_update", {}).get("ballot"),
            "status_payload_hash": receipt.get("status_update", {}).get("status_payload_hash"),
        },
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(STANDARDS_BODY_STATUS_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("decided_at"))


def load_standards_body_status_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("standards-body status receipt must contain an object")
    return value


def write_standards_body_status_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _target_record(submission_receipt: dict[str, Any]) -> dict[str, Any]:
    submission = submission_receipt.get("submission", {})
    body = submission_receipt.get("standards_body", {})
    return {
        "submission_id": submission_receipt.get("submission_id"),
        "content_hash": content_hash(submission_receipt),
        "submission_ref": submission.get("submission_ref"),
        "current_status": submission.get("status"),
        "standards_body": {
            "name": body.get("name"),
            "program_ref": body.get("program_ref"),
            "target_track": body.get("target_track"),
            "endpoint": body.get("endpoint"),
        },
        "package": {
            "package_id": submission_receipt.get("package", {}).get("package_id"),
            "content_hash": submission_receipt.get("package", {}).get("content_hash"),
        },
        "verifier_release": {
            "release_id": submission_receipt.get("verifier_release", {}).get("release_id"),
            "content_hash": submission_receipt.get("verifier_release", {}).get("content_hash"),
            "conformance_targets": submission_receipt.get("verifier_release", {}).get("conformance_targets", []),
            "conformance_source_provider_bundle": submission_receipt.get("verifier_release", {}).get("conformance_source_provider_bundle"),
        },
        "conformance_report": {
            "report_id": submission_receipt.get("conformance_report", {}).get("report_id"),
            "content_hash": submission_receipt.get("conformance_report", {}).get("content_hash"),
            "targets": submission_receipt.get("conformance_report", {}).get("targets", []),
            "case_count_by_target": submission_receipt.get("conformance_report", {}).get("case_count_by_target", {}),
            "source_provider_bundle": submission_receipt.get("conformance_report", {}).get("source_provider_bundle"),
        },
    }


def _submission_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    submission = receipt.get("submission", {})
    return {
        "name": "standards_body_submission_receipt",
        "artifact_type": "trustai.standards-body-submission",
        "content_hash": content_hash(receipt),
        "submission_id": receipt.get("submission_id"),
        "submission_ref": submission.get("submission_ref"),
        "status": submission.get("status"),
    }


def _status_payload_hash(target: dict[str, Any], update: dict[str, Any]) -> str:
    ballot = update.get("ballot") if isinstance(update.get("ballot"), dict) else {}
    return content_hash(
        {
            "submission_id": target.get("submission_id"),
            "previous_status": update.get("previous_status"),
            "new_status": update.get("new_status"),
            "docket_ref": update.get("docket_ref"),
            "status_ref": update.get("status_ref"),
            "decision_ref": update.get("decision_ref"),
            "reason": update.get("reason"),
            "effective_at": update.get("effective_at"),
            "ballot": {
                "ballot_ref": ballot.get("ballot_ref"),
                "opened_at": ballot.get("opened_at"),
                "closed_at": ballot.get("closed_at"),
                "votes_for": ballot.get("votes_for"),
                "votes_against": ballot.get("votes_against"),
                "abstentions": ballot.get("abstentions"),
                "quorum": ballot.get("quorum"),
                "comments_ref": ballot.get("comments_ref"),
            },
            "evidence_refs": sorted(set(update.get("evidence_refs") or [])),
        }
    )


def _controls_for(new_status: str, has_docket: bool, has_decision: bool, has_ballot: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "submission-status-binding",
            "status": "implemented-reference",
            "description": "Receipt binds a standards-body status update to a signed submission receipt by canonical hash.",
        },
        {
            "id": "docket-status-reference",
            "status": "local-reference" if has_docket else "planned-production",
            "description": "Production status updates should bind a standards-body docket, ticket, or working-group reference.",
        },
        {
            "id": "ballot-record-binding",
            "status": "local-reference" if has_ballot else ("planned-production" if new_status in FINAL_STATUSES else "not-applicable"),
            "description": "Final standards outcomes should bind ballot or formal decision records.",
        },
        {
            "id": "decision-record-binding",
            "status": "local-reference" if has_decision else ("planned-production" if new_status in FINAL_STATUSES else "not-applicable"),
            "description": "Accepted or rejected status should bind a formal decision reference.",
        },
        {
            "id": "status-feed-propagation",
            "status": "planned-production",
            "description": "Production deployments should prove propagation through an authenticated standards-body status feed.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        decided = parse_rfc3339(str(receipt.get("decided_at")))
        effective = parse_rfc3339(str(receipt.get("effective_at")))
        if effective < decided:
            errors.append("standards-body status effective_at must be at or after decided_at")
        if now and parse_rfc3339(now) < decided:
            errors.append("standards-body status decision is in the future")
    except ValueError as exc:
        errors.append(f"invalid standards-body status time field: {exc}")


def _validate_ballot_window(opened_at: Any, closed_at: Any) -> None:
    if opened_at:
        parse_rfc3339(str(opened_at))
    if closed_at:
        parse_rfc3339(str(closed_at))
    if opened_at and closed_at and parse_rfc3339(str(closed_at)) < parse_rfc3339(str(opened_at)):
        raise ValueError("standards-body ballot closed_at must be at or after opened_at")


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"standards-body status missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "submission_id": artifact.get("submission_id"),
    }


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
