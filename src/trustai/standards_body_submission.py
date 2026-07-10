from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .standards import verify_standards_submission
from .verifier_conformance import verify_verifier_conformance_report
from .verifier_release import verifier_conformance_release_reference, verify_verifier_release_manifest

STANDARDS_BODY_SUBMISSION_SCHEMA = "trustai.standards-body-submission/0.1"
STANDARDS_BODY_SUBMISSION_ENTRY_TYPE = "standards.body.submitted"

SUBMISSION_STATUSES = {"submitted", "acknowledged", "accepted", "rejected", "withdrawn"}
SUBMISSION_CHANNELS = {"repository", "email", "portal", "api", "working-group"}


@dataclass
class StandardsBodySubmissionVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    status: str | None = None


def build_standards_body_submission_receipt(
    standards_package: dict[str, Any],
    verifier_release: dict[str, Any],
    conformance_report: dict[str, Any],
    *,
    root: str | Path = ".",
    standards_body: str | None = None,
    program_ref: str = "trustai-proof-pack-standards-track",
    target_track: str = "draft-specification",
    endpoint: str | None = None,
    contact_ref: str | None = None,
    submission_ref: str | None = None,
    status: str = "submitted",
    channel: str = "repository",
    submitter_ref: str = "trustai-local",
    subject: str = "TrustAI proof-pack and verifier specification package",
    version_label: str = "v0.1",
    terms_ref: str | None = None,
    submitted_at: str | None = None,
    acknowledgement_due_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if status not in SUBMISSION_STATUSES:
        raise ValueError("status must be submitted, acknowledged, accepted, rejected, or withdrawn")
    if channel not in SUBMISSION_CHANNELS:
        raise ValueError("channel must be repository, email, portal, api, or working-group")
    _require_text(program_ref, "program_ref")
    _require_text(target_track, "target_track")
    _require_text(submitter_ref, "submitter_ref")
    _require_text(subject, "subject")
    _require_text(version_label, "version_label")

    standards_result = verify_standards_submission(standards_package, root=root)
    if not standards_result.ok:
        raise ValueError("invalid standards package: " + "; ".join(standards_result.errors))
    conformance_result = verify_verifier_conformance_report(conformance_report)
    if not conformance_result.ok:
        raise ValueError("invalid verifier conformance report: " + "; ".join(conformance_result.errors))
    release_result = verify_verifier_release_manifest(
        verifier_release,
        root=root,
        conformance_report=conformance_report,
        standards_package=standards_package,
        key=key,
    )
    if not release_result.ok:
        raise ValueError("invalid verifier release manifest: " + "; ".join(release_result.errors))

    submitted = submitted_at or utc_now()
    parse_rfc3339(submitted)
    if acknowledgement_due_at:
        _validate_after("acknowledgement_due_at", submitted, acknowledgement_due_at)

    body_name = standards_body or str(standards_package.get("target_body") or "ETSI/ISO/IEEE or Linux Foundation project")
    ref = submission_ref or content_hash(
        {
            "standards_body": body_name,
            "package_id": standards_package.get("package_id"),
            "release_id": verifier_release.get("release_id"),
            "program_ref": program_ref,
        }
    )[:32]
    submission = {
        "submission_ref": ref,
        "status": status,
        "channel": channel,
        "submitter_ref": submitter_ref,
        "subject": subject,
        "version_label": version_label,
        "terms_ref": terms_ref,
        "idempotency_key": content_hash(
            {
                "submission_ref": ref,
                "package_id": standards_package.get("package_id"),
                "release_id": verifier_release.get("release_id"),
                "channel": channel,
                "submitted_at": submitted,
            }
        )[:32],
    }
    package_record = _package_record(standards_package)
    release_record = _release_record(verifier_release)
    conformance_record = _conformance_record(conformance_report)
    body = {
        "schema": STANDARDS_BODY_SUBMISSION_SCHEMA,
        "submitted_at": submitted,
        "acknowledgement_due_at": acknowledgement_due_at,
        "standards_body": {
            "name": body_name,
            "program_ref": program_ref,
            "target_track": target_track,
            "endpoint": endpoint,
            "contact_ref": contact_ref,
            "attestation_mode": "local-reference",
            "production_replacement": "standards-body authenticated submission acknowledgement and docket status",
        },
        "submission": submission,
        "package": package_record,
        "verifier_release": release_record,
        "conformance_report": conformance_record,
        "submission_payload_hash": content_hash(
            {
                "standards_body": body_name,
                "submission": submission,
                "package": package_record,
                "verifier_release": release_record,
                "conformance_report": conformance_record,
            }
        ),
        "source_artifacts": _source_artifacts(standards_package, verifier_release, conformance_report),
        "controls": _controls_for(bool(endpoint), bool(contact_ref), status),
        "limitations": [
            "This receipt records a local-reference standards-body submission event.",
            "It binds the submitted specification package, verifier release, and conformance report by canonical hash.",
            "It does not claim authenticated standards-body docket acceptance, working-group ballot, or final standards approval.",
            "Production deployments should replace this local receipt with an authenticated standards-body acknowledgement and status feed.",
        ],
    }
    submission_id = content_hash(body)
    return {
        **body,
        "submission_id": submission_id,
        "signatures": [sign_value({"submission_id": submission_id, "submission": body}, key)],
    }


def verify_standards_body_submission_receipt(
    receipt: dict[str, Any],
    *,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> StandardsBodySubmissionVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != STANDARDS_BODY_SUBMISSION_SCHEMA:
        errors.append(f"unsupported standards-body submission schema: {receipt.get('schema')}")
    body = without_keys(receipt, "submission_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("submission_id") != expected_id:
        errors.append("submission_id does not match canonical standards-body submission body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("standards-body submission receipt missing signature")
    else:
        signed_value = {"submission_id": receipt.get("submission_id"), "submission": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("standards-body submission receipt signature invalid")

    _verify_times(receipt, now, errors)
    standards_body = receipt.get("standards_body", {})
    if not isinstance(standards_body, dict) or not standards_body.get("name") or not standards_body.get("program_ref"):
        errors.append("standards-body submission body name and program_ref are required")
    submission = receipt.get("submission", {})
    if not isinstance(submission, dict):
        errors.append("standards-body submission must include a submission object")
        submission = {}
    status = submission.get("status")
    if status not in SUBMISSION_STATUSES:
        errors.append("standards-body submission status is unsupported")
    if submission.get("channel") not in SUBMISSION_CHANNELS:
        errors.append("standards-body submission channel is unsupported")
    if not submission.get("submission_ref") or not submission.get("submitter_ref") or not submission.get("idempotency_key"):
        errors.append("standards-body submission_ref, submitter_ref, and idempotency_key are required")

    package = receipt.get("package", {})
    release = receipt.get("verifier_release", {})
    conformance = receipt.get("conformance_report", {})
    if not isinstance(package, dict) or not package.get("package_id"):
        errors.append("standards-body submission package record is required")
    if not isinstance(release, dict) or not release.get("release_id"):
        errors.append("standards-body submission verifier release record is required")
    if not isinstance(conformance, dict) or not conformance.get("report_id"):
        errors.append("standards-body submission conformance report record is required")
    expected_payload_hash = content_hash(
        {
            "standards_body": standards_body.get("name"),
            "submission": submission,
            "package": package,
            "verifier_release": release,
            "conformance_report": conformance,
        }
    )
    if receipt.get("submission_payload_hash") != expected_payload_hash:
        errors.append("standards-body submission payload hash does not match records")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 3:
        errors.append("standards-body submission must include standards package, verifier release, and conformance report artifacts")
        artifacts = []

    if standards_package is None:
        warnings.append("standards package source not supplied; verified submission binding only")
    else:
        standards_result = verify_standards_submission(standards_package, root=root)
        if not standards_result.ok:
            errors.extend(f"source standards package invalid: {error}" for error in standards_result.errors)
        warnings.extend(f"source standards package warning: {warning}" for warning in standards_result.warnings)
        _compare_artifact(_artifact_by_name(artifacts, "standards_package"), _standards_artifact(standards_package), errors)
        if package != _package_record(standards_package):
            errors.append("standards-body submission package record does not match source standards package")

    if conformance_report is None:
        warnings.append("verifier conformance report source not supplied; verified submission binding only")
    else:
        conformance_result = verify_verifier_conformance_report(conformance_report)
        if not conformance_result.ok:
            errors.extend(f"source verifier conformance report invalid: {error}" for error in conformance_result.errors)
        warnings.extend(f"source verifier conformance warning: {warning}" for warning in conformance_result.warnings)
        _compare_artifact(_artifact_by_name(artifacts, "verifier_conformance_report"), _conformance_artifact(conformance_report), errors)
        if conformance != _conformance_record(conformance_report):
            errors.append("standards-body submission conformance record does not match source report")

    if verifier_release is None:
        warnings.append("verifier release source not supplied; verified submission binding only")
    else:
        release_result = verify_verifier_release_manifest(
            verifier_release,
            root=root,
            conformance_report=conformance_report,
            standards_package=standards_package,
            key=key,
        )
        if not release_result.ok:
            errors.extend(f"source verifier release invalid: {error}" for error in release_result.errors)
        warnings.extend(f"source verifier release warning: {warning}" for warning in release_result.warnings)
        _compare_artifact(_artifact_by_name(artifacts, "verifier_release_manifest"), _release_artifact(verifier_release), errors)
        if release != _release_record(verifier_release):
            errors.append("standards-body submission verifier release record does not match source release")

    if verifier_release is not None and standards_package is not None:
        release_standards = verifier_release.get("standards_package", {})
        if release_standards.get("package_id") != standards_package.get("package_id"):
            errors.append("verifier release standards package does not match submitted standards package")
    if verifier_release is not None and conformance_report is not None:
        release_conformance = verifier_release.get("conformance_report", {})
        expected_conformance = verifier_conformance_release_reference(conformance_report)
        for field in ("report_id", "content_hash", "targets", "case_count_by_target", "source_provider_bundle"):
            if release_conformance.get(field) != expected_conformance.get(field):
                errors.append(f"verifier release conformance report {field} does not match submitted conformance report")

    return StandardsBodySubmissionVerification(ok=not errors, errors=errors, warnings=warnings, status=status)


def append_standards_body_submission_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_standards_body_submission_receipt(
        receipt,
        standards_package=standards_package,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid standards-body submission receipt: " + "; ".join(result.errors))
    payload = {
        "submission_id": receipt["submission_id"],
        "submission_hash": content_hash(receipt),
        "standards_body": receipt.get("standards_body"),
        "submission": receipt.get("submission"),
        "package": receipt.get("package"),
        "verifier_release": receipt.get("verifier_release"),
        "conformance_report": receipt.get("conformance_report"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(STANDARDS_BODY_SUBMISSION_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("submitted_at"))


def load_standards_body_submission_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("standards-body submission receipt must contain an object")
    return value


def write_standards_body_submission_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _package_record(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "package_id": package.get("package_id"),
        "status": package.get("status"),
        "target_body": package.get("target_body"),
        "spec_count": len(package.get("specs", [])),
        "required_spec_count": len(package.get("required_specs", [])),
        "conformance_target_count": len(package.get("conformance_targets", [])),
        "content_hash": content_hash(package),
    }


def _release_record(release: dict[str, Any]) -> dict[str, Any]:
    release_info = release.get("release", {})
    conformance = release.get("conformance_report", {}) if isinstance(release.get("conformance_report"), dict) else {}
    return {
        "release_id": release.get("release_id"),
        "version": release_info.get("version"),
        "implementation": release_info.get("implementation"),
        "verifier_command": release_info.get("verifier_command"),
        "mode": release_info.get("mode"),
        "content_hash": content_hash(release),
        "conformance_report_id": conformance.get("report_id"),
        "conformance_targets": conformance.get("targets", []),
        "conformance_case_count_by_target": conformance.get("case_count_by_target", {}),
        "conformance_source_provider_bundle": conformance.get("source_provider_bundle"),
        "standards_package_id": release.get("standards_package", {}).get("package_id"),
    }


def _conformance_record(report: dict[str, Any]) -> dict[str, Any]:
    reference = verifier_conformance_release_reference(report)
    return {
        "report_id": reference.get("report_id"),
        "verifier_command": reference.get("verifier_command"),
        "mode": report.get("verifier", {}).get("mode"),
        "case_count": reference.get("case_count"),
        "passed_count": reference.get("passed_count"),
        "failed_count": reference.get("failed_count"),
        "targets": reference.get("targets", []),
        "case_count_by_target": reference.get("case_count_by_target", {}),
        "passed_count_by_target": reference.get("passed_count_by_target", {}),
        "source_proof_pack": reference.get("source_proof_pack", {}),
        "source_provider_bundle": reference.get("source_provider_bundle"),
        "content_hash": reference.get("content_hash"),
    }


def _source_artifacts(package: dict[str, Any], release: dict[str, Any], report: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _standards_artifact(package),
        _release_artifact(release),
        _conformance_artifact(report),
    ]


def _standards_artifact(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "standards_package",
        "artifact_type": "trustai.standards-submission",
        "content_hash": content_hash(package),
        "package_id": package.get("package_id"),
        "spec_count": len(package.get("specs", [])),
        "target_body": package.get("target_body"),
    }


def _release_artifact(release: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "verifier_release_manifest",
        "artifact_type": "trustai.verifier-release",
        "content_hash": content_hash(release),
        "release_id": release.get("release_id"),
        "version": release.get("release", {}).get("version"),
    }


def _conformance_artifact(report: dict[str, Any]) -> dict[str, Any]:
    record = _conformance_record(report)
    return {
        "name": "verifier_conformance_report",
        "artifact_type": "trustai.verifier-conformance",
        "content_hash": record.get("content_hash"),
        "report_id": record.get("report_id"),
        "passed_count": record.get("passed_count"),
        "case_count": record.get("case_count"),
        "targets": record.get("targets", []),
        "case_count_by_target": record.get("case_count_by_target", {}),
        "source_provider_bundle": record.get("source_provider_bundle"),
    }


def _controls_for(has_endpoint: bool, has_contact: bool, status: str) -> list[dict[str, str]]:
    return [
        {
            "id": "standards-package-binding",
            "status": "implemented-reference",
            "description": "Receipt binds a standards submission package by canonical hash.",
        },
        {
            "id": "verifier-release-binding",
            "status": "implemented-reference",
            "description": "Receipt binds the submitted offline verifier release and conformance report by canonical hash.",
        },
        {
            "id": "standards-body-docket",
            "status": "local-reference" if status in {"acknowledged", "accepted"} else "planned-production",
            "description": "Production submission should bind a standards-body docket or working-group acknowledgement.",
        },
        {
            "id": "submission-endpoint",
            "status": "local-reference" if has_endpoint else "planned-production",
            "description": "Production submission should bind the standards-body endpoint or repository URL.",
        },
        {
            "id": "working-group-contact",
            "status": "local-reference" if has_contact else "planned-production",
            "description": "Production submission should bind a standards-body contact, working group, or ticket reference.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        submitted = parse_rfc3339(str(receipt.get("submitted_at")))
        due_at = receipt.get("acknowledgement_due_at")
        if due_at:
            due = parse_rfc3339(str(due_at))
            if due <= submitted:
                errors.append("standards-body acknowledgement_due_at must be after submitted_at")
            if now and parse_rfc3339(now) > due and receipt.get("submission", {}).get("status") == "submitted":
                errors.append("standards-body submission acknowledgement is overdue")
    except ValueError as exc:
        errors.append(f"invalid standards-body submission time field: {exc}")


def _validate_after(field_name: str, submitted_at: Any, value: Any) -> None:
    submitted = parse_rfc3339(str(submitted_at))
    parsed = parse_rfc3339(str(value))
    if parsed <= submitted:
        raise ValueError(f"standards-body submission {field_name} must be after submitted_at")


def _artifact_by_name(artifacts: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"standards-body submission missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "package_id": artifact.get("package_id"),
        "release_id": artifact.get("release_id"),
        "report_id": artifact.get("report_id"),
        "targets": artifact.get("targets"),
        "source_provider_bundle": artifact.get("source_provider_bundle"),
    }


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
