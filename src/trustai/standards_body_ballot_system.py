from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .standards_body_ballot import verify_standards_body_ballot_receipt

STANDARDS_BODY_BALLOT_SYSTEM_SCHEMA = "trustai.standards-body-ballot-system/0.1"
STANDARDS_BODY_BALLOT_SYSTEM_ENTRY_TYPE = "standards.body.ballot_system.exported"
BALLOT_SYSTEM_EXPORT_SCHEMA = "trustai.standards-body-ballot-system-export/0.1"

BALLOT_SYSTEM_MODES = {"dry-run", "recorded-response", "authenticated-export"}


@dataclass
class StandardsBodyBallotSystemVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    export_ref: str | None = None
    mode: str | None = None


def build_standards_body_ballot_system_receipt(
    ballot_receipt: dict[str, Any],
    *,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    ballot_system: str = "local-ballot-system",
    endpoint_base: str = "local-ballot-system",
    credential_ref: str = "local-reference",
    mode: str = "dry-run",
    request_method: str = "GET",
    request_path: str | None = None,
    export_ref: str | None = None,
    export_url: str | None = None,
    export_format: str = "json",
    export_payload: dict[str, Any] | None = None,
    export_generated_at: str | None = None,
    actor_ref: str | None = None,
    response_status: int | None = None,
    response_body: Any | None = None,
    evidence_refs: list[str] | None = None,
    exported_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(ballot_system, "ballot_system")
    _require_text(endpoint_base, "endpoint_base")
    _require_text(credential_ref, "credential_ref")
    _require_text(request_method, "request_method")
    _require_text(export_format, "export_format")
    if mode not in BALLOT_SYSTEM_MODES:
        raise ValueError("mode must be dry-run, recorded-response, or authenticated-export")
    if mode == "authenticated-export" and not actor_ref:
        raise ValueError("authenticated-export mode requires actor_ref")
    if mode in {"recorded-response", "authenticated-export"} and response_status is None:
        raise ValueError("response_status is required for recorded-response or authenticated-export mode")

    ballot_result = verify_standards_body_ballot_receipt(
        ballot_receipt,
        submission_receipt=submission_receipt,
        status_receipt=status_receipt,
        standards_package=standards_package,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not ballot_result.ok:
        raise ValueError("invalid standards-body ballot receipt: " + "; ".join(ballot_result.errors))
    if ballot_result.outcome != "accepted":
        raise ValueError("standards-body ballot-system export requires an accepted ballot receipt")

    exported = exported_at or utc_now()
    generated = export_generated_at or exported
    _validate_times(generated, exported)

    ballot_record = _ballot_record(ballot_receipt)
    payload = export_payload or _default_export_payload(ballot_receipt)
    if not isinstance(payload, dict):
        raise ValueError("export_payload must contain an object")
    if payload.get("schema") != BALLOT_SYSTEM_EXPORT_SCHEMA:
        payload = {"schema": BALLOT_SYSTEM_EXPORT_SCHEMA, "payload": payload}
    export_hash = content_hash(payload)
    resolved_export_ref = export_ref or content_hash(
        {
            "ballot_id": ballot_record.get("ballot_id"),
            "export_hash": export_hash,
            "generated_at": generated,
        }
    )[:32]
    path = request_path or f"/ballots/{ballot_record.get('ballot_ref')}/exports/{resolved_export_ref}"
    target_url = _target_url(endpoint_base, path)
    request_body = _request_body(ballot_record, resolved_export_ref, export_format)

    system = {
        "name": ballot_system,
        "endpoint_base": endpoint_base.rstrip("/"),
        "credential": {"ref": credential_ref, "redacted": True},
        "attestation_mode": "local-reference" if mode != "authenticated-export" else "authenticated-export",
        "production_replacement": "authenticated standards-body ballot-system session, export event, and provider response",
    }
    export = {
        "export_ref": resolved_export_ref,
        "format": export_format,
        "generated_at": generated,
        "content_hash": export_hash,
        "payload": payload,
        "record_count": _record_count(payload),
        "result_url": export_url,
        "actor_ref": actor_ref,
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    body: dict[str, Any] = {
        "schema": STANDARDS_BODY_BALLOT_SYSTEM_SCHEMA,
        "mode": mode,
        "exported_at": exported,
        "ballot_system": system,
        "ballot": ballot_record,
        "request": {
            "method": request_method.upper(),
            "path": path,
            "target_url": target_url,
            "body": request_body,
            "body_hash": content_hash(request_body),
            "idempotency_key": content_hash(
                {
                    "ballot_id": ballot_record.get("ballot_id"),
                    "target_url": target_url,
                    "export_ref": export["export_ref"],
                }
            )[:32],
        },
        "export": export,
        "source_artifacts": [_ballot_artifact(ballot_receipt)],
        "integration_payload_hash": content_hash(
            {
                "ballot": ballot_record,
                "system": system,
                "request": {
                    "method": request_method.upper(),
                    "path": path,
                    "target_url": target_url,
                    "body_hash": content_hash(request_body),
                },
                "export": without_keys(export, "payload"),
            }
        ),
        "controls": _controls_for(mode, bool(export_url), bool(actor_ref), response_status),
        "limitations": [
            "This receipt records local-reference hosted ballot-system export evidence for a standards-body ballot.",
            "It binds an accepted standards-body ballot receipt to request hashes, export payload hash, optional response hash, and source ballot hash.",
            "It does not claim live standards-body system access unless authenticated-export mode is backed by a provider response and actor reference.",
            "Production deployments should replace this local receipt with an authenticated standards-body ballot-system export, provider identity, and immutable response archive.",
        ],
    }
    if mode in {"recorded-response", "authenticated-export"}:
        body["response"] = {
            "status": response_status,
            "body_hash": content_hash(response_body),
            "accepted": response_status is not None and 200 <= response_status < 300,
        }
    integration_id = content_hash(body)
    return {
        **body,
        "integration_id": integration_id,
        "signatures": [sign_value({"integration_id": integration_id, "ballot_system": body}, key)],
    }


def verify_standards_body_ballot_system_receipt(
    receipt: dict[str, Any],
    *,
    ballot_receipt: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> StandardsBodyBallotSystemVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != STANDARDS_BODY_BALLOT_SYSTEM_SCHEMA:
        errors.append(f"unsupported standards-body ballot-system schema: {receipt.get('schema')}")
    body = without_keys(receipt, "integration_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("integration_id") != expected_id:
        errors.append("integration_id does not match canonical standards-body ballot-system body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("standards-body ballot-system receipt missing signature")
    else:
        signed_value = {"integration_id": receipt.get("integration_id"), "ballot_system": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("standards-body ballot-system receipt signature invalid")

    mode = receipt.get("mode")
    if mode not in BALLOT_SYSTEM_MODES:
        errors.append("standards-body ballot-system mode is unsupported")
    if mode == "dry-run":
        warnings.append("standards-body ballot-system receipt is a dry-run; no provider response is claimed")

    try:
        exported_at = str(receipt.get("exported_at"))
        generated_at = str((receipt.get("export") or {}).get("generated_at"))
        _validate_times(generated_at, exported_at)
        if now and parse_rfc3339(now) < parse_rfc3339(exported_at):
            errors.append("standards-body ballot-system export is in the future")
    except ValueError as exc:
        errors.append(f"invalid standards-body ballot-system time field: {exc}")

    system = receipt.get("ballot_system", {})
    credential = system.get("credential", {}) if isinstance(system, dict) else {}
    if not isinstance(system, dict) or not system.get("name") or not system.get("endpoint_base"):
        errors.append("standards-body ballot-system name and endpoint_base are required")
    if not isinstance(credential, dict) or not credential.get("ref") or credential.get("redacted") is not True:
        errors.append("standards-body ballot-system credential reference must be redacted")

    ballot = receipt.get("ballot", {})
    if not isinstance(ballot, dict) or not ballot.get("ballot_id") or not ballot.get("ballot_ref"):
        errors.append("standards-body ballot-system ballot_id and ballot_ref are required")
        ballot = {}
    if ballot.get("outcome") != "accepted":
        errors.append("standards-body ballot-system export requires an accepted ballot")

    request = receipt.get("request", {})
    if not isinstance(request, dict):
        errors.append("standards-body ballot-system request must be an object")
        request = {}
    request_body = request.get("body")
    if not isinstance(request_body, dict):
        errors.append("standards-body ballot-system request body must be an object")
    elif request.get("body_hash") != content_hash(request_body):
        errors.append("standards-body ballot-system request body_hash does not match body")
    if not request.get("method") or not request.get("path") or not request.get("target_url"):
        errors.append("standards-body ballot-system request method, path, and target_url are required")

    export = receipt.get("export", {})
    if not isinstance(export, dict):
        errors.append("standards-body ballot-system export must be an object")
        export = {}
    export_payload = export.get("payload")
    if not export.get("export_ref") or not export.get("format") or not export.get("content_hash"):
        errors.append("standards-body ballot-system export_ref, format, and content_hash are required")
    if not isinstance(export_payload, dict):
        errors.append("standards-body ballot-system export payload must be an object")
    elif export.get("content_hash") != content_hash(export_payload):
        errors.append("standards-body ballot-system export content_hash does not match payload")
    if mode == "authenticated-export" and not export.get("actor_ref"):
        errors.append("authenticated standards-body ballot-system export requires actor_ref")

    if mode in {"recorded-response", "authenticated-export"}:
        response = receipt.get("response", {})
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("recorded standards-body ballot-system export must include response status and body_hash")
        elif mode == "authenticated-export" and not response.get("accepted"):
            errors.append("authenticated standards-body ballot-system export requires an accepted provider response")
    elif "response" in receipt:
        warnings.append("standards-body ballot-system response is present on dry-run receipt")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("standards-body ballot-system receipt must include exactly one ballot source artifact")
        artifacts = []
    ballot_artifact = _artifact_by_name(artifacts, "standards_body_ballot_receipt")
    if ballot_artifact is None:
        errors.append("standards-body ballot-system missing standards_body_ballot_receipt source artifact")

    if ballot_receipt is None:
        warnings.append("standards-body ballot source not supplied; verified ballot-system binding only")
    else:
        ballot_result = verify_standards_body_ballot_receipt(
            ballot_receipt,
            submission_receipt=submission_receipt,
            status_receipt=status_receipt,
            standards_package=standards_package,
            verifier_release=verifier_release,
            conformance_report=conformance_report,
            root=root,
            key=key,
        )
        if not ballot_result.ok:
            errors.extend(f"source standards-body ballot receipt invalid: {error}" for error in ballot_result.errors)
        warnings.extend(f"source standards-body ballot warning: {warning}" for warning in ballot_result.warnings)
        if ballot_result.outcome != "accepted":
            errors.append("standards-body ballot-system export requires an accepted source ballot")
        _compare_artifact(ballot_artifact, _ballot_artifact(ballot_receipt), errors)
        if ballot != _ballot_record(ballot_receipt):
            errors.append("standards-body ballot-system ballot record does not match source ballot receipt")
        if isinstance(request_body, dict) and request_body != _request_body(_ballot_record(ballot_receipt), export.get("export_ref"), export.get("format")):
            errors.append("standards-body ballot-system request body does not match source ballot receipt")
        if isinstance(export_payload, dict) and export_payload.get("schema") == BALLOT_SYSTEM_EXPORT_SCHEMA:
            expected_payload = _default_export_payload(ballot_receipt)
            if export_payload != expected_payload:
                errors.append("standards-body ballot-system export payload does not match source ballot receipt")

    expected_payload_hash = content_hash(
        {
            "ballot": ballot,
            "system": system,
            "request": {
                "method": request.get("method"),
                "path": request.get("path"),
                "target_url": request.get("target_url"),
                "body_hash": request.get("body_hash"),
            },
            "export": without_keys(export, "payload"),
        }
    )
    if receipt.get("integration_payload_hash") != expected_payload_hash:
        errors.append("standards-body ballot-system integration payload hash does not match records")

    return StandardsBodyBallotSystemVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        export_ref=export.get("export_ref") if isinstance(export.get("export_ref"), str) else None,
        mode=mode if isinstance(mode, str) else None,
    )


def append_standards_body_ballot_system_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    ballot_receipt: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_standards_body_ballot_system_receipt(
        receipt,
        ballot_receipt=ballot_receipt,
        submission_receipt=submission_receipt,
        status_receipt=status_receipt,
        standards_package=standards_package,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid standards-body ballot-system receipt: " + "; ".join(result.errors))
    payload = {
        "integration_id": receipt["integration_id"],
        "integration_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "ballot_system": receipt.get("ballot_system"),
        "ballot": receipt.get("ballot"),
        "request": {
            "method": receipt.get("request", {}).get("method"),
            "path": receipt.get("request", {}).get("path"),
            "target_url": receipt.get("request", {}).get("target_url"),
            "body_hash": receipt.get("request", {}).get("body_hash"),
            "idempotency_key": receipt.get("request", {}).get("idempotency_key"),
        },
        "export": without_keys(receipt.get("export", {}), "payload"),
        "response": receipt.get("response"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(STANDARDS_BODY_BALLOT_SYSTEM_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("exported_at"))


def load_standards_body_ballot_system_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("standards-body ballot-system receipt must contain an object")
    return value


def write_standards_body_ballot_system_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _ballot_record(receipt: dict[str, Any]) -> dict[str, Any]:
    ballot = receipt.get("ballot", {})
    decision = receipt.get("decision", {})
    target = receipt.get("target_submission", {})
    body = target.get("standards_body", {}) if isinstance(target, dict) else {}
    return {
        "ballot_id": receipt.get("ballot_id"),
        "content_hash": content_hash(receipt),
        "ballot_ref": ballot.get("ballot_ref"),
        "outcome": decision.get("outcome"),
        "decision_ref": decision.get("decision_ref"),
        "effective_at": receipt.get("effective_at"),
        "submission_id": target.get("submission_id"),
        "submission_ref": target.get("submission_ref"),
        "standards_body": {
            "name": body.get("name"),
            "program_ref": body.get("program_ref"),
            "target_track": body.get("target_track"),
        },
        "conformance_report": target.get("conformance_report"),
    }


def _ballot_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    ballot = receipt.get("ballot", {})
    decision = receipt.get("decision", {})
    return {
        "name": "standards_body_ballot_receipt",
        "artifact_type": "trustai.standards-body-ballot",
        "content_hash": content_hash(receipt),
        "ballot_id": receipt.get("ballot_id"),
        "ballot_ref": ballot.get("ballot_ref"),
        "outcome": decision.get("outcome"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "ballot_id": artifact.get("ballot_id"),
    }


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"standards-body ballot-system missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _default_export_payload(ballot_receipt: dict[str, Any]) -> dict[str, Any]:
    ballot = ballot_receipt.get("ballot", {})
    decision = ballot_receipt.get("decision", {})
    target = ballot_receipt.get("target_submission", {})
    return {
        "schema": BALLOT_SYSTEM_EXPORT_SCHEMA,
        "ballot": {
            "ballot_id": ballot_receipt.get("ballot_id"),
            "content_hash": content_hash(ballot_receipt),
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
            "approval_met": ballot.get("approval_met"),
        },
        "decision": {
            "outcome": decision.get("outcome"),
            "decision_ref": decision.get("decision_ref"),
            "minutes_ref": decision.get("minutes_ref"),
            "decided_at": decision.get("decided_at"),
            "effective_at": decision.get("effective_at"),
        },
        "submission": {
            "submission_id": target.get("submission_id"),
            "submission_ref": target.get("submission_ref"),
            "standards_body": target.get("standards_body"),
            "conformance_report": target.get("conformance_report"),
        },
    }


def _request_body(ballot_record: dict[str, Any], export_ref: str | None, export_format: str | None) -> dict[str, Any]:
    return {
        "schema": "trustai.standards-body-ballot-system-request/0.1",
        "ballot_id": ballot_record.get("ballot_id"),
        "ballot_ref": ballot_record.get("ballot_ref"),
        "decision_ref": ballot_record.get("decision_ref"),
        "submission_id": ballot_record.get("submission_id"),
        "conformance_targets": ballot_record.get("conformance_report", {}).get("targets", []) if isinstance(ballot_record.get("conformance_report"), dict) else [],
        "source_provider_bundle": ballot_record.get("conformance_report", {}).get("source_provider_bundle") if isinstance(ballot_record.get("conformance_report"), dict) else None,
        "export_ref": export_ref,
        "export_format": export_format,
    }


def _target_url(endpoint_base: str, path: str) -> str:
    return f"{endpoint_base.rstrip('/')}/{path.lstrip('/')}"


def _record_count(payload: dict[str, Any]) -> int:
    records = payload.get("records")
    if isinstance(records, list):
        return len(records)
    return 1


def _controls_for(mode: str, has_export_url: bool, has_actor_ref: bool, response_status: int | None) -> list[dict[str, str]]:
    return [
        {
            "id": "accepted-ballot-binding",
            "status": "implemented-reference",
            "description": "Receipt binds a hosted ballot-system export to an accepted standards-body ballot receipt by canonical hash.",
        },
        {
            "id": "credentialed-ballot-system-request",
            "status": "local-reference" if mode == "dry-run" else "recorded-response",
            "description": "Receipt records target endpoint, redacted credential reference, request hash, and idempotency key.",
        },
        {
            "id": "ballot-system-export-hash",
            "status": "implemented-reference",
            "description": "Receipt binds a normalized ballot-system export payload by canonical hash.",
        },
        {
            "id": "provider-response-capture",
            "status": "recorded-response" if response_status is not None else "planned-production",
            "description": "Production deployments should preserve the standards-body provider response hash and accepted status.",
        },
        {
            "id": "authenticated-standards-body-actor",
            "status": "authenticated-reference" if has_actor_ref else "planned-production",
            "description": "Production deployments should bind the export to an authenticated standards-body actor or service account.",
        },
        {
            "id": "public-export-location",
            "status": "local-reference" if has_export_url else "planned-production",
            "description": "Production deployments should bind public or credentialed export URLs from the standards body.",
        },
    ]


def _validate_times(generated_at: str, exported_at: str) -> None:
    generated = parse_rfc3339(generated_at)
    exported = parse_rfc3339(exported_at)
    if exported < generated:
        raise ValueError("standards-body ballot-system exported_at must be at or after export generated_at")


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
