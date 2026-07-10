from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .standards_body_ballot_system import verify_standards_body_ballot_system_receipt

STANDARDS_BODY_PROVIDER_POSTING_SCHEMA = "trustai.standards-body-provider-posting/0.1"
STANDARDS_BODY_PROVIDER_POSTING_ENTRY_TYPE = "standards.body.provider_posting.recorded"

PROVIDER_POSTING_MODES = {"dry-run", "credential-exchange", "recorded-response", "provider-posted"}


@dataclass
class StandardsBodyProviderPostingVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    posting_id: str | None = None
    mode: str | None = None


def build_standards_body_provider_posting_receipt(
    ballot_system_receipt: dict[str, Any],
    *,
    ballot_receipt: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    provider: str = "local-standards-provider",
    endpoint_base: str = "local-standards-provider",
    credential_ref: str = "local-reference",
    credential_exchange_url: str | None = None,
    credential_audience: str | None = None,
    credential_scope: list[str] | None = None,
    mode: str = "dry-run",
    request_method: str = "POST",
    request_path: str | None = None,
    posting_ref: str | None = None,
    posting_url: str | None = None,
    actor_ref: str | None = None,
    credential_response_status: int | None = None,
    credential_response_body: Any | None = None,
    response_status: int | None = None,
    response_body: Any | None = None,
    evidence_refs: list[str] | None = None,
    posted_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(provider, "provider")
    _require_text(endpoint_base, "endpoint_base")
    _require_text(credential_ref, "credential_ref")
    _require_text(request_method, "request_method")
    if mode not in PROVIDER_POSTING_MODES:
        raise ValueError("mode must be dry-run, credential-exchange, recorded-response, or provider-posted")
    if mode in {"credential-exchange", "provider-posted"} and not actor_ref:
        raise ValueError("credential-exchange and provider-posted modes require actor_ref")
    if mode in {"credential-exchange", "provider-posted"} and credential_response_status is None:
        raise ValueError("credential_response_status is required for credential-exchange or provider-posted mode")
    if mode in {"recorded-response", "provider-posted"} and response_status is None:
        raise ValueError("response_status is required for recorded-response or provider-posted mode")

    source_result = verify_standards_body_ballot_system_receipt(
        ballot_system_receipt,
        ballot_receipt=ballot_receipt,
        submission_receipt=submission_receipt,
        status_receipt=status_receipt,
        standards_package=standards_package,
        verifier_release=verifier_release,
        conformance_report=conformance_report,
        root=root,
        key=key,
    )
    if not source_result.ok:
        raise ValueError("invalid standards-body ballot-system receipt: " + "; ".join(source_result.errors))
    if _source_record(ballot_system_receipt).get("ballot", {}).get("outcome") != "accepted":
        raise ValueError("standards-body provider posting requires an accepted ballot-system export")
    if mode == "provider-posted" and ballot_system_receipt.get("mode") == "dry-run":
        raise ValueError("provider-posted mode requires a non-dry-run ballot-system export receipt")

    posted = posted_at or utc_now()
    _validate_times(str(ballot_system_receipt.get("exported_at")), posted)
    source = _source_record(ballot_system_receipt)
    resolved_posting_ref = posting_ref or content_hash(
        {
            "integration_id": source.get("integration_id"),
            "export_ref": source.get("export", {}).get("export_ref"),
            "provider": provider,
            "posted_at": posted,
        }
    )[:32]
    path = request_path or _default_request_path(source, resolved_posting_ref)
    target_url = _target_url(endpoint_base, path)
    request_body = _request_body(source, resolved_posting_ref, provider)
    exchange_url = credential_exchange_url or _target_url(endpoint_base, "/oauth/token")
    credential_exchange: dict[str, Any] = {
        "url": exchange_url,
        "audience": credential_audience,
        "scope": sorted(set(credential_scope or [])),
        "credential": {"ref": credential_ref, "redacted": True},
        "actor_ref": actor_ref,
    }
    if mode in {"credential-exchange", "provider-posted"}:
        credential_exchange["response"] = {
            "status": credential_response_status,
            "body_hash": content_hash(credential_response_body),
            "accepted": credential_response_status is not None and 200 <= credential_response_status < 300,
        }

    posting = {
        "posting_ref": resolved_posting_ref,
        "posting_url": posting_url,
        "actor_ref": actor_ref,
        "evidence_refs": sorted(set(evidence_refs or [])),
    }
    provider_record = {
        "name": provider,
        "endpoint_base": endpoint_base.rstrip("/"),
        "attestation_mode": _provider_attestation_mode(mode),
        "production_replacement": "standards-body provider API posting with credential exchange transcript and immutable provider response archive",
    }
    body: dict[str, Any] = {
        "schema": STANDARDS_BODY_PROVIDER_POSTING_SCHEMA,
        "mode": mode,
        "posted_at": posted,
        "provider": provider_record,
        "source": source,
        "credential_exchange": credential_exchange,
        "request": {
            "method": request_method.upper(),
            "path": path,
            "target_url": target_url,
            "body": request_body,
            "body_hash": content_hash(request_body),
            "idempotency_key": content_hash(
                {
                    "source_integration_id": source.get("integration_id"),
                    "posting_ref": resolved_posting_ref,
                    "target_url": target_url,
                }
            )[:32],
        },
        "posting": posting,
        "source_artifacts": [_ballot_system_artifact(ballot_system_receipt)],
        "posting_payload_hash": content_hash(
            {
                "source": source,
                "provider": provider_record,
                "credential_exchange": without_keys(credential_exchange, "response"),
                "request": {
                    "method": request_method.upper(),
                    "path": path,
                    "target_url": target_url,
                    "body_hash": content_hash(request_body),
                },
                "posting": posting,
            }
        ),
        "controls": _controls_for(mode, bool(actor_ref), credential_response_status, response_status, bool(posting_url)),
        "limitations": [
            "This receipt records local-reference standards-body provider posting evidence for a hosted ballot-system export.",
            "It binds a verified ballot-system export receipt to redacted credential exchange metadata, request hash, optional response hash, and source export hash.",
            "It does not claim live provider posting unless provider-posted mode is backed by accepted credential exchange and provider response evidence.",
            "Production deployments should replace this local receipt with provider-owned authentication, immutable request/response archives, and revocation-aware credentials.",
        ],
    }
    if mode in {"recorded-response", "provider-posted"}:
        body["response"] = {
            "status": response_status,
            "body_hash": content_hash(response_body),
            "accepted": response_status is not None and 200 <= response_status < 300,
        }
    posting_id = content_hash(body)
    return {
        **body,
        "posting_id": posting_id,
        "signatures": [sign_value({"posting_id": posting_id, "provider_posting": body}, key)],
    }


def verify_standards_body_provider_posting_receipt(
    receipt: dict[str, Any],
    *,
    ballot_system_receipt: dict[str, Any] | None = None,
    ballot_receipt: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> StandardsBodyProviderPostingVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != STANDARDS_BODY_PROVIDER_POSTING_SCHEMA:
        errors.append(f"unsupported standards-body provider posting schema: {receipt.get('schema')}")
    body = without_keys(receipt, "posting_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("posting_id") != expected_id:
        errors.append("posting_id does not match canonical standards-body provider posting body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("standards-body provider posting receipt missing signature")
    else:
        signed_value = {"posting_id": receipt.get("posting_id"), "provider_posting": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("standards-body provider posting receipt signature invalid")

    mode = receipt.get("mode")
    if mode not in PROVIDER_POSTING_MODES:
        errors.append("standards-body provider posting mode is unsupported")
    if mode == "dry-run":
        warnings.append("standards-body provider posting receipt is a dry-run; no credential exchange or provider response is claimed")

    try:
        posted_at = str(receipt.get("posted_at"))
        source_exported_at = str((receipt.get("source") or {}).get("exported_at"))
        _validate_times(source_exported_at, posted_at)
        if now and parse_rfc3339(now) < parse_rfc3339(posted_at):
            errors.append("standards-body provider posting is in the future")
    except ValueError as exc:
        errors.append(f"invalid standards-body provider posting time field: {exc}")

    provider = receipt.get("provider", {})
    if not isinstance(provider, dict) or not provider.get("name") or not provider.get("endpoint_base"):
        errors.append("standards-body provider posting provider name and endpoint_base are required")
        provider = {}

    credential_exchange = receipt.get("credential_exchange", {})
    if not isinstance(credential_exchange, dict):
        errors.append("standards-body provider posting credential_exchange must be an object")
        credential_exchange = {}
    credential = credential_exchange.get("credential", {}) if isinstance(credential_exchange, dict) else {}
    if not isinstance(credential, dict) or not credential.get("ref") or credential.get("redacted") is not True:
        errors.append("standards-body provider posting credential reference must be redacted")
    if mode in {"credential-exchange", "provider-posted"}:
        if not credential_exchange.get("actor_ref"):
            errors.append("credential-exchange and provider-posted modes require actor_ref")
        exchange_response = credential_exchange.get("response", {})
        if not isinstance(exchange_response, dict) or exchange_response.get("status") is None or not exchange_response.get("body_hash"):
            errors.append("credential-exchange and provider-posted modes require credential exchange response status and body_hash")
        elif not exchange_response.get("accepted"):
            errors.append("credential exchange response must be accepted")
    elif "response" in credential_exchange:
        warnings.append("credential exchange response is present outside credential-exchange/provider-posted mode")

    source = receipt.get("source", {})
    if not isinstance(source, dict) or not source.get("integration_id") or not source.get("content_hash"):
        errors.append("standards-body provider posting source integration_id and content_hash are required")
        source = {}
    if source.get("ballot", {}).get("outcome") != "accepted":
        errors.append("standards-body provider posting requires an accepted source ballot")

    request = receipt.get("request", {})
    if not isinstance(request, dict):
        errors.append("standards-body provider posting request must be an object")
        request = {}
    request_body = request.get("body")
    if not isinstance(request_body, dict):
        errors.append("standards-body provider posting request body must be an object")
    elif request.get("body_hash") != content_hash(request_body):
        errors.append("standards-body provider posting request body_hash does not match body")
    if not request.get("method") or not request.get("path") or not request.get("target_url"):
        errors.append("standards-body provider posting request method, path, and target_url are required")

    posting = receipt.get("posting", {})
    if not isinstance(posting, dict) or not posting.get("posting_ref"):
        errors.append("standards-body provider posting posting_ref is required")
        posting = {}
    if mode == "provider-posted" and not posting.get("actor_ref"):
        errors.append("provider-posted mode requires posting actor_ref")

    if mode in {"recorded-response", "provider-posted"}:
        response = receipt.get("response", {})
        if not isinstance(response, dict) or response.get("status") is None or not response.get("body_hash"):
            errors.append("recorded-response and provider-posted modes require provider response status and body_hash")
        elif mode == "provider-posted" and not response.get("accepted"):
            errors.append("provider-posted mode requires an accepted provider response")
    elif "response" in receipt:
        warnings.append("provider response is present outside recorded-response/provider-posted mode")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("standards-body provider posting receipt must include exactly one ballot-system source artifact")
        artifacts = []
    source_artifact = _artifact_by_name(artifacts, "standards_body_ballot_system_receipt")
    if source_artifact is None:
        errors.append("standards-body provider posting missing standards_body_ballot_system_receipt source artifact")

    if ballot_system_receipt is None:
        warnings.append("standards-body ballot-system source not supplied; verified provider-posting binding only")
    else:
        source_result = verify_standards_body_ballot_system_receipt(
            ballot_system_receipt,
            ballot_receipt=ballot_receipt,
            submission_receipt=submission_receipt,
            status_receipt=status_receipt,
            standards_package=standards_package,
            verifier_release=verifier_release,
            conformance_report=conformance_report,
            root=root,
            key=key,
        )
        if not source_result.ok:
            errors.extend(f"source standards-body ballot-system receipt invalid: {error}" for error in source_result.errors)
        warnings.extend(f"source standards-body ballot-system warning: {warning}" for warning in source_result.warnings)
        if mode == "provider-posted" and ballot_system_receipt.get("mode") == "dry-run":
            errors.append("provider-posted mode requires a non-dry-run ballot-system source")
        _compare_artifact(source_artifact, _ballot_system_artifact(ballot_system_receipt), errors)
        expected_source = _source_record(ballot_system_receipt)
        if source != expected_source:
            errors.append("standards-body provider posting source record does not match source ballot-system receipt")
        if isinstance(request_body, dict) and request_body != _request_body(expected_source, posting.get("posting_ref"), provider.get("name")):
            errors.append("standards-body provider posting request body does not match source ballot-system receipt")

    expected_payload_hash = content_hash(
        {
            "source": source,
            "provider": provider,
            "credential_exchange": without_keys(credential_exchange, "response"),
            "request": {
                "method": request.get("method"),
                "path": request.get("path"),
                "target_url": request.get("target_url"),
                "body_hash": request.get("body_hash"),
            },
            "posting": posting,
        }
    )
    if receipt.get("posting_payload_hash") != expected_payload_hash:
        errors.append("standards-body provider posting payload hash does not match records")

    return StandardsBodyProviderPostingVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        posting_id=receipt.get("posting_id") if isinstance(receipt.get("posting_id"), str) else None,
        mode=mode if isinstance(mode, str) else None,
    )


def append_standards_body_provider_posting_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    ballot_system_receipt: dict[str, Any] | None = None,
    ballot_receipt: dict[str, Any] | None = None,
    submission_receipt: dict[str, Any] | None = None,
    status_receipt: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    verifier_release: dict[str, Any] | None = None,
    conformance_report: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_standards_body_provider_posting_receipt(
        receipt,
        ballot_system_receipt=ballot_system_receipt,
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
        raise ValueError("invalid standards-body provider posting receipt: " + "; ".join(result.errors))
    credential_exchange = receipt.get("credential_exchange", {})
    payload = {
        "posting_id": receipt["posting_id"],
        "posting_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "provider": receipt.get("provider"),
        "source": {
            "integration_id": receipt.get("source", {}).get("integration_id"),
            "content_hash": receipt.get("source", {}).get("content_hash"),
            "export": receipt.get("source", {}).get("export"),
            "ballot": receipt.get("source", {}).get("ballot"),
        },
        "credential_exchange": {
            "url": credential_exchange.get("url") if isinstance(credential_exchange, dict) else None,
            "audience": credential_exchange.get("audience") if isinstance(credential_exchange, dict) else None,
            "scope": credential_exchange.get("scope") if isinstance(credential_exchange, dict) else None,
            "credential": credential_exchange.get("credential") if isinstance(credential_exchange, dict) else None,
            "response": credential_exchange.get("response") if isinstance(credential_exchange, dict) else None,
        },
        "request": {
            "method": receipt.get("request", {}).get("method"),
            "path": receipt.get("request", {}).get("path"),
            "target_url": receipt.get("request", {}).get("target_url"),
            "body_hash": receipt.get("request", {}).get("body_hash"),
            "idempotency_key": receipt.get("request", {}).get("idempotency_key"),
        },
        "posting": receipt.get("posting"),
        "response": receipt.get("response"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(STANDARDS_BODY_PROVIDER_POSTING_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("posted_at"))


def load_standards_body_provider_posting_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("standards-body provider posting receipt must contain an object")
    return value


def write_standards_body_provider_posting_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _source_record(receipt: dict[str, Any]) -> dict[str, Any]:
    ballot_system = receipt.get("ballot_system", {})
    ballot = receipt.get("ballot", {})
    export = receipt.get("export", {})
    return {
        "integration_id": receipt.get("integration_id"),
        "content_hash": content_hash(receipt),
        "mode": receipt.get("mode"),
        "exported_at": receipt.get("exported_at"),
        "ballot_system": {
            "name": ballot_system.get("name"),
            "endpoint_base": ballot_system.get("endpoint_base"),
        },
        "ballot": {
            "ballot_id": ballot.get("ballot_id"),
            "ballot_ref": ballot.get("ballot_ref"),
            "outcome": ballot.get("outcome"),
            "decision_ref": ballot.get("decision_ref"),
            "submission_id": ballot.get("submission_id"),
            "submission_ref": ballot.get("submission_ref"),
            "conformance_report": ballot.get("conformance_report"),
        },
        "export": {
            "export_ref": export.get("export_ref"),
            "content_hash": export.get("content_hash"),
            "format": export.get("format"),
            "record_count": export.get("record_count"),
            "result_url": export.get("result_url"),
        },
    }


def _ballot_system_artifact(receipt: dict[str, Any]) -> dict[str, Any]:
    export = receipt.get("export", {})
    return {
        "name": "standards_body_ballot_system_receipt",
        "artifact_type": "trustai.standards-body-ballot-system",
        "content_hash": content_hash(receipt),
        "integration_id": receipt.get("integration_id"),
        "export_ref": export.get("export_ref"),
        "mode": receipt.get("mode"),
    }


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "integration_id": artifact.get("integration_id"),
        "export_ref": artifact.get("export_ref"),
    }


def _artifact_by_name(artifacts: list[Any], name: str) -> dict[str, Any] | None:
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return artifact
    return None


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"standards-body provider posting missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _request_body(source: dict[str, Any], posting_ref: str | None, provider_name: str | None) -> dict[str, Any]:
    export = source.get("export", {})
    ballot = source.get("ballot", {})
    return {
        "schema": "trustai.standards-body-provider-posting-request/0.1",
        "provider": provider_name,
        "posting_ref": posting_ref,
        "source_integration_id": source.get("integration_id"),
        "source_content_hash": source.get("content_hash"),
        "export_ref": export.get("export_ref"),
        "export_content_hash": export.get("content_hash"),
        "ballot_id": ballot.get("ballot_id"),
        "ballot_ref": ballot.get("ballot_ref"),
        "decision_ref": ballot.get("decision_ref"),
        "submission_id": ballot.get("submission_id"),
        "conformance_targets": ballot.get("conformance_report", {}).get("targets", []) if isinstance(ballot.get("conformance_report"), dict) else [],
        "source_provider_bundle": ballot.get("conformance_report", {}).get("source_provider_bundle") if isinstance(ballot.get("conformance_report"), dict) else None,
    }


def _default_request_path(source: dict[str, Any], posting_ref: str) -> str:
    ballot_ref = source.get("ballot", {}).get("ballot_ref") or "unknown-ballot"
    export_ref = source.get("export", {}).get("export_ref") or "unknown-export"
    return f"/ballots/{ballot_ref}/exports/{export_ref}/postings/{posting_ref}"


def _target_url(endpoint_base: str, path: str) -> str:
    return f"{endpoint_base.rstrip('/')}/{path.lstrip('/')}"


def _provider_attestation_mode(mode: str) -> str:
    if mode == "provider-posted":
        return "provider-posted"
    if mode == "credential-exchange":
        return "credential-exchange-recorded"
    if mode == "recorded-response":
        return "recorded-response"
    return "local-reference"


def _controls_for(
    mode: str,
    has_actor_ref: bool,
    credential_response_status: int | None,
    response_status: int | None,
    has_posting_url: bool,
) -> list[dict[str, str]]:
    return [
        {
            "id": "ballot-system-export-binding",
            "status": "implemented-reference",
            "description": "Receipt binds provider posting to a verified hosted ballot-system export by canonical hash.",
        },
        {
            "id": "credential-exchange-recording",
            "status": "recorded-response" if credential_response_status is not None else "planned-production",
            "description": "Production deployments should retain credential exchange response hashes without storing credentials.",
        },
        {
            "id": "provider-posting-response",
            "status": "provider-posted" if mode == "provider-posted" and response_status is not None else "planned-production",
            "description": "Provider posting captures the standards-body API response status and body hash.",
        },
        {
            "id": "authenticated-standards-provider-actor",
            "status": "authenticated-reference" if has_actor_ref else "planned-production",
            "description": "Provider posting binds the export to an authenticated standards-body actor or service account.",
        },
        {
            "id": "provider-posting-location",
            "status": "recorded-response" if has_posting_url else "planned-production",
            "description": "Production deployments should bind the provider-assigned posting URL or durable reference.",
        },
    ]


def _validate_times(source_exported_at: str, posted_at: str) -> None:
    source_time = parse_rfc3339(source_exported_at)
    posted_time = parse_rfc3339(posted_at)
    if posted_time < source_time:
        raise ValueError("standards-body provider posting posted_at must be at or after source exported_at")


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
