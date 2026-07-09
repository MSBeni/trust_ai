from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .standards_body_status import verify_standards_body_status_receipt
from .standards_body_submission import verify_standards_body_submission_receipt

STANDARDS_BODY_BALLOT_SCHEMA = "trustai.standards-body-ballot/0.1"
STANDARDS_BODY_BALLOT_ENTRY_TYPE = "standards.body.ballot.certified"

BALLOT_OUTCOMES = {"accepted", "rejected", "changes_requested", "deferred"}
BALLOT_MODES = {"working-group", "committee", "member-ballot", "public-review"}


@dataclass
class StandardsBodyBallotVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    ballot_ref: str | None = None
    outcome: str | None = None


def build_standards_body_ballot_receipt(
    submission_receipt: dict[str, Any],
    *,
    ballot_ref: str,
    decision_ref: str,
    actor_ref: str,
    root: str | Path = ".",
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    motion: str = "Advance TrustAI proof-pack and verifier specification package on the standards track.",
    ballot_mode: str = "working-group",
    outcome: str = "accepted",
    eligible_voters: int = 1,
    votes_for: int = 1,
    votes_against: int = 0,
    abstentions: int = 0,
    quorum_required: int = 1,
    approval_threshold_percent: int = 50,
    opened_at: str | None = None,
    closed_at: str | None = None,
    decided_at: str | None = None,
    effective_at: str | None = None,
    comments_ref: str | None = None,
    minutes_ref: str | None = None,
    actor_role: str = "standards-body-chair",
    evidence_refs: list[str] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(ballot_ref, "ballot_ref")
    _require_text(decision_ref, "decision_ref")
    _require_text(actor_ref, "actor_ref")
    _require_text(actor_role, "actor_role")
    _require_text(motion, "motion")
    if ballot_mode not in BALLOT_MODES:
        raise ValueError("ballot_mode must be working-group, committee, member-ballot, or public-review")
    if outcome not in BALLOT_OUTCOMES:
        raise ValueError("outcome must be accepted, rejected, changes_requested, or deferred")

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
    if status_receipt is not None:
        status_result = verify_standards_body_status_receipt(
            status_receipt,
            submission_receipt=submission_receipt,
            standards_package=standards_package,
            verifier_release=verifier_release,
            conformance_report=conformance_report,
            root=root,
            key=key,
        )
        if not status_result.ok:
            raise ValueError("invalid standards-body status receipt: " + "; ".join(status_result.errors))
        if status_result.new_status not in {"acknowledged", "under_review", "ballot_open"}:
            raise ValueError("standards-body ballot requires acknowledged, under_review, or ballot_open status context")

    opened = opened_at or utc_now()
    closed = closed_at or opened
    decided = decided_at or closed
    effective = effective_at or decided
    _validate_times(opened, closed, decided, effective)

    _validate_counts(eligible_voters, votes_for, votes_against, abstentions, quorum_required, approval_threshold_percent)
    vote_count = votes_for + votes_against + abstentions
    decisive_votes = votes_for + votes_against
    quorum_met = vote_count >= quorum_required
    approval_met = decisive_votes > 0 and votes_for * 100 >= approval_threshold_percent * decisive_votes
    if outcome == "accepted" and not (quorum_met and approval_met):
        raise ValueError("accepted ballot outcome requires quorum and approval threshold")
    if outcome == "rejected" and not quorum_met:
        raise ValueError("rejected ballot outcome requires quorum")

    target = _target_record(submission_receipt)
    status_context = _status_context(status_receipt) if status_receipt is not None else None
    ballot = {
        "ballot_ref": ballot_ref,
        "mode": ballot_mode,
        "motion": motion,
        "opened_at": opened,
        "closed_at": closed,
        "eligible_voters": eligible_voters,
        "votes_for": votes_for,
        "votes_against": votes_against,
        "abstentions": abstentions,
        "vote_count": vote_count,
        "quorum_required": quorum_required,
        "quorum_met": quorum_met,
        "approval_threshold_percent": approval_threshold_percent,
        "approval_basis": "votes_for_over_votes_for_plus_votes_against",
        "approval_met": approval_met,
        "comments_ref": comments_ref,
    }
    decision = {
        "outcome": outcome,
        "decision_ref": decision_ref,
        "minutes_ref": minutes_ref,
        "decided_at": decided,
        "effective_at": effective,
        "actor": {
            "ref": actor_ref,
            "role": actor_role,
            "attestation_mode": "local-reference",
            "production_replacement": "authenticated standards-body ballot authority, decision record, and vote certification",
        },
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    ballot_payload_hash = _ballot_payload_hash(target, status_context, ballot, decision)
    body = {
        "schema": STANDARDS_BODY_BALLOT_SCHEMA,
        "opened_at": opened,
        "closed_at": closed,
        "decided_at": decided,
        "effective_at": effective,
        "target_submission": target,
        "status_context": status_context,
        "ballot": ballot,
        "decision": decision,
        "ballot_payload_hash": ballot_payload_hash,
        "source_artifacts": _source_artifacts(submission_receipt, status_receipt),
        "controls": _controls_for(outcome, quorum_met, approval_met, status_receipt is not None, bool(minutes_ref)),
        "limitations": [
            "This receipt records a local-reference standards-body ballot and decision certification.",
            "It binds ballot tally, quorum math, decision references, and source standards-body submission evidence by canonical hash.",
            "It can model a standards-track accepted, rejected, changes-requested, or deferred outcome without claiming external standards-body authority.",
            "Production deployments should replace this local receipt with authenticated ballot-system exports, formal meeting minutes, and standards-body publication records.",
        ],
    }
    ballot_id = content_hash(body)
    return {
        **body,
        "ballot_id": ballot_id,
        "signatures": [sign_value({"ballot_id": ballot_id, "ballot": body}, key)],
    }


def verify_standards_body_ballot_receipt(
    receipt: dict[str, Any],
    *,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> StandardsBodyBallotVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != STANDARDS_BODY_BALLOT_SCHEMA:
        errors.append(f"unsupported standards-body ballot schema: {receipt.get('schema')}")
    body = without_keys(receipt, "ballot_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("ballot_id") != expected_id:
        errors.append("ballot_id does not match canonical standards-body ballot body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("standards-body ballot receipt missing signature")
    else:
        signed_value = {"ballot_id": receipt.get("ballot_id"), "ballot": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("standards-body ballot receipt signature invalid")

    _verify_times(receipt, now, errors)

    target = receipt.get("target_submission", {})
    if not isinstance(target, dict) or not target.get("submission_id") or not target.get("submission_ref"):
        errors.append("standards-body ballot target submission_id and submission_ref are required")

    status_context = receipt.get("status_context")
    if status_context is not None and not isinstance(status_context, dict):
        errors.append("standards-body ballot status_context must be an object when supplied")
        status_context = None

    ballot = receipt.get("ballot", {})
    if not isinstance(ballot, dict):
        errors.append("standards-body ballot must be an object")
        ballot = {}
    decision = receipt.get("decision", {})
    if not isinstance(decision, dict):
        errors.append("standards-body ballot decision must be an object")
        decision = {}

    ballot_ref = ballot.get("ballot_ref")
    outcome = decision.get("outcome")
    _verify_ballot(ballot, errors)
    _verify_decision(decision, errors)
    if outcome == "accepted" and not (ballot.get("quorum_met") and ballot.get("approval_met")):
        errors.append("standards-body accepted ballot outcome requires quorum and approval threshold")
    if outcome == "rejected" and not ballot.get("quorum_met"):
        errors.append("standards-body rejected ballot outcome requires quorum")
    try:
        expected_payload_hash = _ballot_payload_hash(target, status_context, ballot, decision)
        if receipt.get("ballot_payload_hash") != expected_payload_hash:
            errors.append("standards-body ballot payload hash does not match records")
    except Exception as exc:  # defensive: structural errors are reported above.
        errors.append(f"standards-body ballot payload hash could not be recomputed: {exc}")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) not in {1, 2}:
        errors.append("standards-body ballot receipt must include submission source and optional status source artifacts")
        artifacts = []

    if submission_receipt is None:
        warnings.append("standards-body submission source not supplied; verified ballot binding only")
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
        _compare_artifact(_artifact_by_name(artifacts, "standards_body_submission_receipt"), _submission_artifact(submission_receipt), errors)
        if target != _target_record(submission_receipt):
            errors.append("standards-body ballot target does not match source submission receipt")

    status_artifact = _artifact_by_name(artifacts, "standards_body_status_receipt")
    if status_receipt is None:
        if status_context is not None:
            warnings.append("standards-body status source not supplied; verified status context binding only")
    else:
        if status_context is None:
            errors.append("standards-body ballot status_context missing while status source was supplied")
        status_result = verify_standards_body_status_receipt(
            status_receipt,
            submission_receipt=submission_receipt,
            standards_package=standards_package,
            verifier_release=verifier_release,
            conformance_report=conformance_report,
            root=root,
            key=key,
        )
        if not status_result.ok:
            errors.extend(f"source standards-body status receipt invalid: {error}" for error in status_result.errors)
        warnings.extend(f"source standards-body status warning: {warning}" for warning in status_result.warnings)
        _compare_artifact(status_artifact, _status_artifact(status_receipt), errors)
        if status_context != _status_context(status_receipt):
            errors.append("standards-body ballot status_context does not match source status receipt")
        if status_result.new_status not in {"acknowledged", "under_review", "ballot_open"}:
            errors.append("standards-body ballot status context must be acknowledged, under_review, or ballot_open")

    return StandardsBodyBallotVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        ballot_ref=ballot_ref if isinstance(ballot_ref, str) else None,
        outcome=outcome if isinstance(outcome, str) else None,
    )


def append_standards_body_ballot_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_standards_body_ballot_receipt(
        receipt,
        submission_receipt=submission_receipt,
        status_receipt=status_receipt,
        standards_package=standards_package,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid standards-body ballot receipt: " + "; ".join(result.errors))
    payload = {
        "ballot_id": receipt["ballot_id"],
        "ballot_hash": content_hash(receipt),
        "target_submission": receipt.get("target_submission"),
        "status_context": receipt.get("status_context"),
        "ballot": receipt.get("ballot"),
        "decision": receipt.get("decision"),
        "ballot_payload_hash": receipt.get("ballot_payload_hash"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(STANDARDS_BODY_BALLOT_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("decided_at"))


def load_standards_body_ballot_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("standards-body ballot receipt must contain an object")
    return value


def write_standards_body_ballot_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
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
        },
        "conformance_report": {
            "report_id": submission_receipt.get("conformance_report", {}).get("report_id"),
            "content_hash": submission_receipt.get("conformance_report", {}).get("content_hash"),
        },
    }


def _status_context(status_receipt: dict[str, Any]) -> dict[str, Any]:
    update = status_receipt.get("status_update", {})
    return {
        "status_id": status_receipt.get("status_id"),
        "content_hash": content_hash(status_receipt),
        "docket_ref": update.get("docket_ref"),
        "status_ref": update.get("status_ref"),
        "new_status": update.get("new_status"),
        "effective_at": status_receipt.get("effective_at"),
    }


def _source_artifacts(submission_receipt: dict[str, Any], status_receipt: dict[str, Any] | None) -> list[dict[str, Any]]:
    artifacts = [_submission_artifact(submission_receipt)]
    if status_receipt is not None:
        artifacts.append(_status_artifact(status_receipt))
    return artifacts


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


def _status_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    update = receipt.get("status_update", {})
    return {
        "name": "standards_body_status_receipt",
        "artifact_type": "trustai.standards-body-status",
        "content_hash": content_hash(receipt),
        "status_id": receipt.get("status_id"),
        "status_ref": update.get("status_ref"),
        "new_status": update.get("new_status"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "submission_id": artifact.get("submission_id"),
        "status_id": artifact.get("status_id"),
    }


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"standards-body ballot missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _ballot_payload_hash(
    target: dict[str, Any],
    status_context: dict[str, Any] | None,
    ballot: dict[str, Any],
    decision: dict[str, Any],
) -> str:
    return content_hash(
        {
            "submission_id": target.get("submission_id"),
            "status_context": status_context,
            "ballot": {
                "ballot_ref": ballot.get("ballot_ref"),
                "mode": ballot.get("mode"),
                "motion": ballot.get("motion"),
                "opened_at": ballot.get("opened_at"),
                "closed_at": ballot.get("closed_at"),
                "eligible_voters": ballot.get("eligible_voters"),
                "votes_for": ballot.get("votes_for"),
                "votes_against": ballot.get("votes_against"),
                "abstentions": ballot.get("abstentions"),
                "vote_count": ballot.get("vote_count"),
                "quorum_required": ballot.get("quorum_required"),
                "quorum_met": ballot.get("quorum_met"),
                "approval_threshold_percent": ballot.get("approval_threshold_percent"),
                "approval_basis": ballot.get("approval_basis"),
                "approval_met": ballot.get("approval_met"),
                "comments_ref": ballot.get("comments_ref"),
            },
            "decision": {
                "outcome": decision.get("outcome"),
                "decision_ref": decision.get("decision_ref"),
                "minutes_ref": decision.get("minutes_ref"),
                "decided_at": decision.get("decided_at"),
                "effective_at": decision.get("effective_at"),
                "actor": decision.get("actor"),
                "evidence_refs": sorted(set(decision.get("evidence_refs") or [])),
            },
        }
    )


def _verify_ballot(ballot: dict[str, Any], errors: list[str]) -> None:
    if not ballot.get("ballot_ref") or ballot.get("mode") not in BALLOT_MODES or not ballot.get("motion"):
        errors.append("standards-body ballot_ref, mode, and motion are required")
    values = {
        "eligible_voters": ballot.get("eligible_voters"),
        "votes_for": ballot.get("votes_for"),
        "votes_against": ballot.get("votes_against"),
        "abstentions": ballot.get("abstentions"),
        "quorum_required": ballot.get("quorum_required"),
        "approval_threshold_percent": ballot.get("approval_threshold_percent"),
    }
    try:
        _validate_counts(
            int(values["eligible_voters"]),
            int(values["votes_for"]),
            int(values["votes_against"]),
            int(values["abstentions"]),
            int(values["quorum_required"]),
            int(values["approval_threshold_percent"]),
        )
        vote_count = int(values["votes_for"]) + int(values["votes_against"]) + int(values["abstentions"])
        decisive_votes = int(values["votes_for"]) + int(values["votes_against"])
        quorum_met = vote_count >= int(values["quorum_required"])
        approval_met = decisive_votes > 0 and int(values["votes_for"]) * 100 >= int(values["approval_threshold_percent"]) * decisive_votes
        if ballot.get("vote_count") != vote_count:
            errors.append("standards-body ballot vote_count does not match vote tally")
        if ballot.get("quorum_met") != quorum_met:
            errors.append("standards-body ballot quorum_met does not match vote tally")
        if ballot.get("approval_met") != approval_met:
            errors.append("standards-body ballot approval_met does not match vote tally")
    except (TypeError, ValueError) as exc:
        errors.append(f"invalid standards-body ballot vote field: {exc}")
    try:
        _validate_times(
            str(ballot.get("opened_at")),
            str(ballot.get("closed_at")),
            str(ballot.get("closed_at")),
            str(ballot.get("closed_at")),
        )
    except ValueError as exc:
        errors.append(str(exc))


def _verify_decision(decision: dict[str, Any], errors: list[str]) -> None:
    outcome = decision.get("outcome")
    if outcome not in BALLOT_OUTCOMES:
        errors.append("standards-body ballot outcome is unsupported")
    if not decision.get("decision_ref"):
        errors.append("standards-body ballot decision_ref is required")
    actor = decision.get("actor", {})
    if not isinstance(actor, dict) or not actor.get("ref") or not actor.get("role"):
        errors.append("standards-body ballot decision actor ref and role are required")


def _validate_counts(
    eligible_voters: int,
    votes_for: int,
    votes_against: int,
    abstentions: int,
    quorum_required: int,
    approval_threshold_percent: int,
) -> None:
    for name, value in {
        "eligible_voters": eligible_voters,
        "votes_for": votes_for,
        "votes_against": votes_against,
        "abstentions": abstentions,
        "quorum_required": quorum_required,
        "approval_threshold_percent": approval_threshold_percent,
    }.items():
        if not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if value < 0:
            raise ValueError(f"{name} must be non-negative")
    if eligible_voters <= 0:
        raise ValueError("eligible_voters must be positive")
    if quorum_required <= 0:
        raise ValueError("quorum_required must be positive")
    if quorum_required > eligible_voters:
        raise ValueError("quorum_required cannot exceed eligible_voters")
    if votes_for + votes_against + abstentions > eligible_voters:
        raise ValueError("vote tally cannot exceed eligible_voters")
    if approval_threshold_percent > 100:
        raise ValueError("approval_threshold_percent cannot exceed 100")


def _validate_times(opened: str, closed: str, decided: str, effective: str) -> None:
    opened_dt = parse_rfc3339(opened)
    closed_dt = parse_rfc3339(closed)
    decided_dt = parse_rfc3339(decided)
    effective_dt = parse_rfc3339(effective)
    if closed_dt < opened_dt:
        raise ValueError("standards-body ballot closed_at must be at or after opened_at")
    if decided_dt < closed_dt:
        raise ValueError("standards-body ballot decided_at must be at or after closed_at")
    if effective_dt < decided_dt:
        raise ValueError("standards-body ballot effective_at must be at or after decided_at")


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        _validate_times(
            str(receipt.get("opened_at")),
            str(receipt.get("closed_at")),
            str(receipt.get("decided_at")),
            str(receipt.get("effective_at")),
        )
        if now and parse_rfc3339(now) < parse_rfc3339(str(receipt.get("decided_at"))):
            errors.append("standards-body ballot decision is in the future")
    except ValueError as exc:
        errors.append(f"invalid standards-body ballot time field: {exc}")


def _controls_for(
    outcome: str,
    quorum_met: bool,
    approval_met: bool,
    has_status_context: bool,
    has_minutes: bool,
) -> list[dict[str, str]]:
    return [
        {
            "id": "submission-ballot-binding",
            "status": "implemented-reference",
            "description": "Receipt binds a standards-body ballot decision to a signed standards-body submission receipt by canonical hash.",
        },
        {
            "id": "docket-status-context",
            "status": "local-reference" if has_status_context else "planned-production",
            "description": "Production ballot decisions should bind the standards-body docket status that opened or authorized the ballot.",
        },
        {
            "id": "quorum-and-approval-math",
            "status": "implemented-reference" if quorum_met and (approval_met or outcome != "accepted") else "planned-production",
            "description": "Receipt records quorum, vote tally, and approval-threshold calculations.",
        },
        {
            "id": "formal-minutes-binding",
            "status": "local-reference" if has_minutes else "planned-production",
            "description": "Production ballot outcomes should bind formal working-group or committee minutes.",
        },
        {
            "id": "authenticated-ballot-system-export",
            "status": "planned-production",
            "description": "Production deployments should bind an authenticated export from the standards body's ballot system.",
        },
    ]


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
