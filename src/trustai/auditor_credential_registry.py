from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auditor_accreditation import ACCREDITATION_STATUSES, verify_auditor_accreditation_receipt
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

AUDITOR_CREDENTIAL_REGISTRY_SCHEMA = "trustai.auditor-credential-registry/0.1"
AUDITOR_CREDENTIAL_REGISTRY_ENTRY_TYPE = "auditor.credential.registry.published"

CREDENTIAL_REGISTRY_VISIBILITIES = {"private", "partner", "public"}


@dataclass
class AuditorCredentialRegistryVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    status: str | None = None


def build_auditor_credential_registry_receipt(
    accreditation_receipt: dict[str, Any],
    *,
    certification_kit: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    root: str | Path = ".",
    registry_name: str = "trustai-local-auditor-credential-registry",
    registry_endpoint: str = "local-auditor-registry",
    namespace: str = "trustai-auditors",
    publication_ref: str | None = None,
    status: str | None = None,
    visibility: str = "public",
    terms_ref: str | None = None,
    revocation_endpoint: str | None = None,
    operator_ref: str | None = None,
    published_at: str | None = None,
    expires_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    _require_text(registry_name, "registry_name")
    _require_text(registry_endpoint, "registry_endpoint")
    _require_text(namespace, "namespace")
    if visibility not in CREDENTIAL_REGISTRY_VISIBILITIES:
        raise ValueError("visibility must be private, partner, or public")

    accreditation_result = verify_auditor_accreditation_receipt(
        accreditation_receipt,
        certification_kit=certification_kit,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        standards_package=standards_package,
        root=root,
        key=key,
    )
    if not accreditation_result.ok:
        raise ValueError("invalid auditor accreditation receipt: " + "; ".join(accreditation_result.errors))

    credential = accreditation_receipt.get("credential", {})
    if not isinstance(credential, dict):
        raise ValueError("auditor accreditation credential must be an object")
    source_status = credential.get("status")
    registry_status = status or source_status
    if registry_status not in ACCREDITATION_STATUSES:
        raise ValueError("status must be active, suspended, or revoked")
    if registry_status != source_status:
        raise ValueError("registry credential status must match auditor accreditation status")

    published = published_at or utc_now()
    parse_rfc3339(published)
    publication_expires = expires_at or accreditation_receipt.get("expires_at") or credential.get("expires_at")
    if publication_expires:
        _validate_after("expires_at", published, publication_expires)

    record = _credential_record(accreditation_receipt, registry_status)
    ref = publication_ref or content_hash(
        {
            "registry_name": registry_name,
            "namespace": namespace,
            "accreditation_id": accreditation_receipt.get("accreditation_id"),
            "credential_id": credential.get("credential_id"),
        }
    )[:32]
    publication = {
        "publication_ref": ref,
        "status": registry_status,
        "visibility": visibility,
        "terms_ref": terms_ref,
        "revocation_endpoint": revocation_endpoint,
        "operator_ref": operator_ref,
        "idempotency_key": content_hash(
            {
                "publication_ref": ref,
                "registry_endpoint": registry_endpoint.rstrip("/"),
                "accreditation_id": accreditation_receipt.get("accreditation_id"),
                "credential_id": credential.get("credential_id"),
            }
        )[:32],
    }
    body = {
        "schema": AUDITOR_CREDENTIAL_REGISTRY_SCHEMA,
        "published_at": published,
        "expires_at": publication_expires,
        "registry": {
            "name": registry_name,
            "endpoint": registry_endpoint.rstrip("/"),
            "namespace": namespace,
            "attestation_mode": "local-reference",
            "production_replacement": "authenticated public auditor credential registry publication event",
        },
        "publication": publication,
        "credential_record": record,
        "registry_payload_hash": content_hash({"publication": publication, "credential_record": record}),
        "source_artifacts": [_accreditation_artifact(accreditation_receipt)],
        "controls": _controls_for(visibility, bool(revocation_endpoint), bool(operator_ref)),
        "limitations": [
            "This receipt records a local-reference auditor credential registry publication.",
            "It binds the public credential record to a signed auditor accreditation receipt by canonical hash.",
            "It does not claim hosted registry authentication, public index propagation, or external standards-body governance.",
            "Production deployments should replace this local receipt with an authenticated public credential registry event and propagation audit.",
        ],
    }
    registry_id = content_hash(body)
    return {
        **body,
        "registry_id": registry_id,
        "signatures": [sign_value({"registry_id": registry_id, "registry": body}, key)],
    }


def verify_auditor_credential_registry_receipt(
    receipt: dict[str, Any],
    *,
    accreditation_receipt: dict[str, Any] | None = None,
    certification_kit: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
    now: str | None = None,
) -> AuditorCredentialRegistryVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if receipt.get("schema") != AUDITOR_CREDENTIAL_REGISTRY_SCHEMA:
        errors.append(f"unsupported auditor credential registry schema: {receipt.get('schema')}")
    body = without_keys(receipt, "registry_id", "signatures")
    expected_id = content_hash(body)
    if receipt.get("registry_id") != expected_id:
        errors.append("registry_id does not match canonical auditor credential registry body")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("auditor credential registry receipt missing signature")
    else:
        signed_value = {"registry_id": receipt.get("registry_id"), "registry": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("auditor credential registry receipt signature invalid")

    _verify_times(receipt, now, errors)
    registry = receipt.get("registry", {})
    if not isinstance(registry, dict) or not registry.get("name") or not registry.get("endpoint") or not registry.get("namespace"):
        errors.append("auditor credential registry name, endpoint, and namespace are required")

    publication = receipt.get("publication", {})
    if not isinstance(publication, dict):
        errors.append("auditor credential registry publication must be an object")
        publication = {}
    if not publication.get("publication_ref") or not publication.get("idempotency_key"):
        errors.append("auditor credential registry publication_ref and idempotency_key are required")
    status = publication.get("status")
    if status not in ACCREDITATION_STATUSES:
        errors.append("auditor credential registry status must be active, suspended, or revoked")
    if publication.get("visibility") not in CREDENTIAL_REGISTRY_VISIBILITIES:
        errors.append("auditor credential registry visibility must be private, partner, or public")

    record = receipt.get("credential_record", {})
    if not isinstance(record, dict):
        errors.append("auditor credential registry credential_record must be an object")
        record = {}
    if not record.get("credential_id") or not record.get("accreditation_id") or not record.get("auditor_subject_ref"):
        errors.append("auditor credential registry credential_id, accreditation_id, and auditor_subject_ref are required")
    if record.get("status") != status:
        errors.append("auditor credential registry credential_record status must match publication status")

    expected_payload_hash = content_hash({"publication": publication, "credential_record": record})
    if receipt.get("registry_payload_hash") != expected_payload_hash:
        errors.append("auditor credential registry payload hash does not match publication and credential record")

    artifacts = receipt.get("source_artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        errors.append("auditor credential registry must include exactly one accreditation source artifact")
        artifacts = []
    artifact = artifacts[0] if artifacts and isinstance(artifacts[0], dict) else None
    if artifact and artifact.get("name") != "auditor_accreditation_receipt":
        errors.append("auditor credential registry source artifact must be auditor_accreditation_receipt")

    if accreditation_receipt is None:
        warnings.append("auditor accreditation receipt source not supplied; verified registry binding only")
    else:
        accreditation_result = verify_auditor_accreditation_receipt(
            accreditation_receipt,
            certification_kit=certification_kit,
            proof_pack=proof_pack,
            regulator_disclosure=regulator_disclosure,
            standards_package=standards_package,
            root=root,
            key=key,
        )
        if not accreditation_result.ok:
            errors.extend(f"source auditor accreditation receipt invalid: {error}" for error in accreditation_result.errors)
        warnings.extend(f"source auditor accreditation warning: {warning}" for warning in accreditation_result.warnings)
        _compare_artifact(artifact, _accreditation_artifact(accreditation_receipt), errors)
        expected_record = _credential_record(accreditation_receipt, accreditation_receipt.get("credential", {}).get("status"))
        if record != expected_record:
            errors.append("auditor credential registry record does not match source accreditation receipt")
        if status != accreditation_receipt.get("credential", {}).get("status"):
            errors.append("auditor credential registry status does not match source accreditation receipt")
        _verify_publication_expiry_against_source(receipt, accreditation_receipt, errors)

    return AuditorCredentialRegistryVerification(ok=not errors, errors=errors, warnings=warnings, status=status)


def append_auditor_credential_registry_receipt(
    chain: EvidenceChain,
    receipt: dict[str, Any],
    *,
    accreditation_receipt: dict[str, Any] | None = None,
    certification_kit: dict[str, Any] | None = None,
    proof_pack: dict[str, Any] | None = None,
    regulator_disclosure: dict[str, Any] | None = None,
    standards_package: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_auditor_credential_registry_receipt(
        receipt,
        accreditation_receipt=accreditation_receipt,
        certification_kit=certification_kit,
        proof_pack=proof_pack,
        regulator_disclosure=regulator_disclosure,
        standards_package=standards_package,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid auditor credential registry receipt: " + "; ".join(result.errors))
    payload = {
        "registry_id": receipt["registry_id"],
        "registry_hash": content_hash(receipt),
        "registry": receipt.get("registry"),
        "publication": receipt.get("publication"),
        "credential_record": receipt.get("credential_record"),
        "source_refs": [_artifact_ref(artifact) for artifact in receipt.get("source_artifacts", [])],
        "limitations": receipt.get("limitations", []),
    }
    return chain.append(AUDITOR_CREDENTIAL_REGISTRY_ENTRY_TYPE, payload, key=key, timestamp=receipt.get("published_at"))


def load_auditor_credential_registry_receipt(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("auditor credential registry receipt must contain an object")
    return value


def write_auditor_credential_registry_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")


def _credential_record(accreditation: dict[str, Any], status: Any) -> dict[str, Any]:
    credential = accreditation.get("credential", {})
    auditor = accreditation.get("auditor", {})
    body = accreditation.get("accreditation_body", {})
    return {
        "credential_id": credential.get("credential_id"),
        "status": status,
        "scope": credential.get("scope"),
        "issued_at": credential.get("issued_at") or accreditation.get("issued_at"),
        "expires_at": credential.get("expires_at") or accreditation.get("expires_at"),
        "renewal_due_at": credential.get("renewal_due_at"),
        "auditor_name": auditor.get("name"),
        "auditor_organization": auditor.get("organization"),
        "auditor_subject_ref": auditor.get("subject_ref"),
        "auditor_role": auditor.get("role"),
        "accreditation_id": accreditation.get("accreditation_id"),
        "accreditation_body": body.get("name"),
        "program_ref": body.get("program_ref"),
    }


def _accreditation_artifact(accreditation: dict[str, Any]) -> dict[str, Any]:
    credential = accreditation.get("credential", {})
    auditor = accreditation.get("auditor", {})
    body = accreditation.get("accreditation_body", {})
    return {
        "name": "auditor_accreditation_receipt",
        "artifact_type": "trustai.auditor-accreditation",
        "content_hash": content_hash(accreditation),
        "accreditation_id": accreditation.get("accreditation_id"),
        "credential_id": credential.get("credential_id"),
        "status": credential.get("status"),
        "auditor_subject_ref": auditor.get("subject_ref"),
        "program_ref": body.get("program_ref"),
    }


def _controls_for(visibility: str, has_revocation_endpoint: bool, has_operator: bool) -> list[dict[str, str]]:
    return [
        {
            "id": "accreditation-source-binding",
            "status": "implemented-reference",
            "description": "Receipt binds the registry entry to a verified auditor accreditation receipt by canonical hash.",
        },
        {
            "id": "public-credential-record",
            "status": "local-reference" if visibility == "public" else "planned-production",
            "description": "Receipt produces a portable public credential record with auditor subject, scope, status, and expiry.",
        },
        {
            "id": "credential-revocation-endpoint",
            "status": "local-reference" if has_revocation_endpoint else "planned-production",
            "description": "Production registries should expose a stable credential status and revocation lookup endpoint.",
        },
        {
            "id": "registry-operator-authentication",
            "status": "local-reference" if has_operator else "planned-production",
            "description": "Production registries should bind publication to an authenticated registry operator workflow.",
        },
        {
            "id": "registry-propagation-audit",
            "status": "planned-production",
            "description": "Production registries should prove propagation to public indexes, subscribers, and verifier caches.",
        },
    ]


def _verify_times(receipt: dict[str, Any], now: str | None, errors: list[str]) -> None:
    try:
        published = parse_rfc3339(str(receipt.get("published_at")))
        expires_at = receipt.get("expires_at")
        if expires_at:
            expires = parse_rfc3339(str(expires_at))
            if expires <= published:
                errors.append("auditor credential registry expires_at must be after published_at")
            if now and parse_rfc3339(now) > expires:
                errors.append("auditor credential registry receipt is expired")
    except ValueError as exc:
        errors.append(f"invalid auditor credential registry time field: {exc}")


def _validate_after(field_name: str, published_at: Any, value: Any) -> None:
    published = parse_rfc3339(str(published_at))
    parsed = parse_rfc3339(str(value))
    if parsed <= published:
        raise ValueError(f"auditor credential registry {field_name} must be after published_at")


def _verify_publication_expiry_against_source(
    receipt: dict[str, Any],
    accreditation: dict[str, Any],
    errors: list[str],
) -> None:
    source_expires = accreditation.get("expires_at") or accreditation.get("credential", {}).get("expires_at")
    receipt_expires = receipt.get("expires_at")
    if source_expires and receipt_expires:
        try:
            if parse_rfc3339(str(receipt_expires)) > parse_rfc3339(str(source_expires)):
                errors.append("auditor credential registry expiry exceeds source accreditation expiry")
        except ValueError as exc:
            errors.append(f"invalid auditor credential registry source expiry: {exc}")


def _compare_artifact(actual: dict[str, Any] | None, expected: dict[str, Any], errors: list[str]) -> None:
    if actual is None:
        errors.append(f"auditor credential registry missing source artifact: {expected['name']}")
        return
    for field, value in expected.items():
        if actual.get(field) != value:
            errors.append(f"source artifact {expected['name']} {field} mismatch")


def _artifact_ref(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact.get("name"),
        "artifact_type": artifact.get("artifact_type"),
        "content_hash": artifact.get("content_hash"),
        "accreditation_id": artifact.get("accreditation_id"),
        "credential_id": artifact.get("credential_id"),
    }


def _require_text(value: str | None, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
