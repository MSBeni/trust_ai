from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from .byoc_operator import verify_byoc_operator_attestation
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .deployment import verify_deployment_manifest
from .external_evidence import AUTHORITY_KINDS

BYOC_AUTHORITY_SCHEMA = "trustai.byoc-production-authority-dossier/0.1"
BYOC_AUTHORITY_ENTRY_TYPE = "deployment.byoc_production_authority_recorded"
BYOC_AUTHORITY_MODES = {"local-dossier", "operator-dossier", "production-dossier"}
SECRET_KEY_MARKERS = ("authorization", "cookie", "token", "secret", "private_key", "client_secret", "password", "credential")

PRODUCTION_AUTHORITY_REQUIREMENTS = [
    {
        "id": "live-cloud-account-binding",
        "title": "Customer cloud-account ownership and live deployment account binding",
        "authority_kinds": ["provider-api", "customer"],
    },
    {
        "id": "object-lock-compliance-mode",
        "title": "Provider-native Object Lock, immutability policy, or bucket-lock compliance mode",
        "authority_kinds": ["cloud-object-lock", "provider-api", "customer"],
    },
    {
        "id": "legal-hold-retention-export",
        "title": "Legal hold and retention export for retained proof packs and audit artifacts",
        "authority_kinds": ["cloud-object-lock", "customer"],
    },
    {
        "id": "air-gapped-installation-evidence",
        "title": "Air-gapped install bundle, checksum, and offline operator installation evidence",
        "authority_kinds": ["customer", "hosted-service"],
    },
    {
        "id": "helm-release-and-namespace-state",
        "title": "Helm release, namespace, service account, and workload state export",
        "authority_kinds": ["provider-api", "hosted-service"],
    },
    {
        "id": "network-policy-admission-audit-export",
        "title": "Kubernetes NetworkPolicy admission, namespace selector, and egress audit export evidence",
        "authority_kinds": ["provider-api", "hosted-service", "customer"],
    },
    {
        "id": "operator-controller-reconciliation",
        "title": "BYOC operator controller reconciliation, upgrade, and rollback evidence",
        "authority_kinds": ["hosted-service", "provider-api"],
    },
    {
        "id": "customer-controlled-kms-key-custody",
        "title": "Customer-controlled KMS/HSM key custody and deny-export policy evidence",
        "authority_kinds": ["kms-hsm", "customer", "provider-api"],
    },
    {
        "id": "backup-restore-dr-evidence",
        "title": "Backup, restore drill, RPO, and RTO evidence for the customer data plane",
        "authority_kinds": ["hosted-service", "provider-api", "customer"],
    },
    {
        "id": "network-egress-private-ingress-controls",
        "title": "Private ingress, deny-by-default egress, and allowed-egress control evidence",
        "authority_kinds": ["hosted-service", "provider-api", "customer"],
    },
    {
        "id": "immutable-provider-audit-logs",
        "title": "Immutable provider audit logs and retained operator/service event roots",
        "authority_kinds": ["provider-api", "cloud-object-lock", "customer"],
    },
    {
        "id": "tenant-data-plane-isolation",
        "title": "Per-tenant data-plane isolation, customer account, keyring, and namespace evidence",
        "authority_kinds": ["hosted-service", "customer", "provider-api"],
    },
]
PRODUCTION_AUTHORITY_REQUIREMENT_IDS = [item["id"] for item in PRODUCTION_AUTHORITY_REQUIREMENTS]


@dataclass
class BYOCAuthorityVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0
    replayed_artifact_count: int = 0


def load_byoc_authority_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("BYOC authority dossier must contain an object")
    return value


def write_byoc_authority_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def parse_byoc_authority_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 4)
    if len(parts) != 5:
        raise ValueError("authority evidence must be requirement_id,authority_kind,evidence_ref,evidence_hash,description[;key=value...]")
    requirement_id, authority_kind, evidence_ref, evidence_hash, description = [part.strip() for part in parts]
    description_parts = [part.strip() for part in description.split(";")]
    metadata: dict[str, Any] = {}
    allowed_metadata = {"issuer", "subject", "source_uri", "issued_at", "expires_at"}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("authority evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in allowed_metadata:
            raise ValueError(f"unsupported authority evidence metadata key: {key}")
        metadata[key] = metadata_value
    return {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "description": description_parts[0],
        **metadata,
    }


def parse_byoc_authority_artifact_arg(value: str) -> dict[str, Any]:
    parts = [part.strip() for part in value.split(",", 2)]
    if len(parts) not in {2, 3}:
        raise ValueError("authority artifact must be requirement_id,path[,evidence_ref]")
    artifact = {"requirement_id": parts[0], "path": parts[1]}
    if len(parts) == 3 and parts[2]:
        artifact["evidence_ref"] = parts[2]
    return artifact


def build_byoc_authority_dossier(
    deployment_manifest: dict[str, Any],
    byoc_operator: dict[str, Any],
    *,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    mode: str = "operator-dossier",
    environment: str = "local",
    dossier_ref: str,
    authority_ref: str,
    producer_ref: str,
    authority_evidence: list[dict[str, Any]] | None = None,
    authority_artifacts: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in BYOC_AUTHORITY_MODES:
        raise ValueError(f"mode must be one of {sorted(BYOC_AUTHORITY_MODES)}")
    for value, field in ((environment, "environment"), (dossier_ref, "dossier_ref"), (authority_ref, "authority_ref"), (producer_ref, "producer_ref")):
        _require_text(value, field)

    deployment_result = verify_deployment_manifest(deployment_manifest, root=root, key=key)
    if not deployment_result.ok:
        raise ValueError("invalid deployment manifest source: " + "; ".join(deployment_result.errors))
    operator_result = verify_byoc_operator_attestation(
        byoc_operator,
        deployment_manifest,
        worm_receipt,
        legal_hold=legal_hold,
        root=root,
        store=store,
        key=key,
    )
    if not operator_result.ok:
        raise ValueError("invalid BYOC operator source: " + "; ".join(operator_result.errors))

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    evidence_items = [_build_authority_evidence_item(item) for item in (authority_evidence or [])]
    artifact_items = [_build_authority_artifact(Path(root), item, evidence_items) for item in (authority_artifacts or [])]
    summary = _summary(evidence_items)
    artifact_summary = _artifact_summary(artifact_items)
    binding = _source_binding(deployment_manifest, byoc_operator)
    body: dict[str, Any] = {
        "schema": BYOC_AUTHORITY_SCHEMA,
        "mode": mode,
        "environment": environment,
        "generated_at": timestamp,
        "dossier_ref": dossier_ref,
        "authority_ref": authority_ref,
        "producer_ref": producer_ref,
        "source_binding": binding,
        "required_production_authority": PRODUCTION_AUTHORITY_REQUIREMENTS,
        "authority_evidence": evidence_items,
        "authority_artifacts": artifact_items,
        "summary": summary,
        "artifact_summary": artifact_summary,
        "controls": _controls(mode, binding, evidence_items, summary, artifact_summary),
        "limitations": [
            "This dossier binds a signed deployment manifest and BYOC operator attestation to production-authority evidence for BYOC/self-hosted claims.",
            "It records cloud-account, Object Lock, legal hold, air-gap, Helm, NetworkPolicy admission/audit, operator, KMS, backup, network, audit-log, and tenant-isolation evidence requirements.",
            "It does not claim production BYOC/self-hosted readiness unless mode is production-dossier and every required authority category has fresh external evidence.",
        ],
    }
    dossier_id = content_hash(body)
    signed_value = {"dossier_id": dossier_id, "byoc_authority": body}
    return {**body, "dossier_id": dossier_id, "signatures": [sign_value(signed_value, key)]}


def verify_byoc_authority_dossier(
    dossier: dict[str, Any],
    *,
    deployment_manifest: dict[str, Any] | None = None,
    byoc_operator: dict[str, Any] | None = None,
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
    authority_artifacts: list[dict[str, Any]] | None = None,
) -> BYOCAuthorityVerification:
    errors: list[str] = []
    warnings: list[str] = []
    freshness_now = _freshness_reference(dossier, now, errors)

    if dossier.get("schema") != BYOC_AUTHORITY_SCHEMA:
        errors.append(f"unsupported BYOC authority schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical BYOC authority body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("BYOC authority dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "byoc_authority": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("BYOC authority signature verification failed")

    mode = dossier.get("mode")
    if mode not in BYOC_AUTHORITY_MODES:
        errors.append("BYOC authority mode is unsupported")
    elif mode != "production-dossier":
        warnings.append(f"BYOC authority mode is {mode}; live BYOC production authority is not claimed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"BYOC authority generated_at invalid: {exc}")
    for field in ("environment", "dossier_ref", "authority_ref", "producer_ref"):
        if not dossier.get(field):
            errors.append(f"BYOC authority {field} is required")

    _verify_source_binding(
        dossier.get("source_binding"),
        deployment_manifest,
        byoc_operator,
        errors,
        warnings,
        root=root,
        store=store,
        worm_receipt=worm_receipt,
        legal_hold=legal_hold,
        key=key,
    )
    _verify_required_authority(dossier.get("required_production_authority"), errors)

    evidence = dossier.get("authority_evidence", [])
    if not isinstance(evidence, list):
        errors.append("BYOC authority authority_evidence must be a list")
        evidence = []
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("BYOC authority evidence item must be an object")
            freshness_counts["missing"] += 1
            continue
        status = _verify_authority_evidence_item(item, errors, warnings, now=freshness_now, require_fresh=require_fresh)
        freshness_counts[status] += 1

    evidence_dicts = [item for item in evidence if isinstance(item, dict)]
    expected_summary = _summary(evidence_dicts)
    if dossier.get("summary") != expected_summary:
        errors.append("BYOC authority summary does not match authority evidence")
    artifact_items = dossier.get("authority_artifacts", [])
    if not isinstance(artifact_items, list):
        errors.append("BYOC authority authority_artifacts must be a list")
        artifact_items = []
    replayed_artifact_count = _verify_authority_artifacts(Path(root), artifact_items, evidence_dicts, errors, warnings)
    expected_artifact_summary = _artifact_summary([item for item in artifact_items if isinstance(item, dict)])
    if dossier.get("artifact_summary") != expected_artifact_summary:
        errors.append("BYOC authority artifact_summary does not match authority artifacts")
    if authority_artifacts is not None:
        try:
            expected_artifacts = [_build_authority_artifact(Path(root), item, evidence_dicts) for item in authority_artifacts]
        except ValueError as exc:
            errors.append(f"invalid supplied BYOC authority artifact: {exc}")
            expected_artifacts = []
        if artifact_items != expected_artifacts:
            errors.append("BYOC authority authority_artifacts do not match supplied artifact paths")
    missing = expected_summary["missing_requirement_ids"]
    if missing:
        warnings.append("BYOC authority evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("BYOC authority dossier is incomplete")
    if mode == "production-dossier" and missing:
        errors.append("production-dossier mode requires every BYOC authority requirement to be covered")
    if mode == "production-dossier" and (freshness_counts["stale"] or freshness_counts["missing"]):
        errors.append("production-dossier mode requires every BYOC authority evidence item to be fresh")
    binding_for_controls = dossier.get("source_binding") if isinstance(dossier.get("source_binding"), dict) else {}
    if mode == "production-dossier" and not _source_binding_complete(binding_for_controls):
        errors.append("production-dossier mode requires deployment, BYOC operator, Object Lock, legal hold, customer account, keyring, backup, network, and audit-log bindings")
    if not isinstance(dossier.get("controls"), list) or not dossier.get("controls"):
        errors.append("BYOC authority controls are required")
    elif dossier.get("controls") != _controls(str(mode), binding_for_controls, evidence_dicts, expected_summary, expected_artifact_summary):
        errors.append("BYOC authority controls do not match dossier body")
    _check_no_secret_values(dossier, errors)

    return BYOCAuthorityVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=expected_summary["covered_requirement_count"],
        required_count=expected_summary["required_requirement_count"],
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
        replayed_artifact_count=replayed_artifact_count,
    )


def append_byoc_authority_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    deployment_manifest: dict[str, Any],
    byoc_operator: dict[str, Any],
    root: str | Path = ".",
    store: str | Path = ".trustai/worm",
    worm_receipt: dict[str, Any] | None = None,
    legal_hold: dict[str, Any] | None = None,
    key: str | None = None,
    require_complete: bool = False,
    require_fresh: bool = False,
    now: str | None = None,
    authority_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result = verify_byoc_authority_dossier(
        dossier,
        deployment_manifest=deployment_manifest,
        byoc_operator=byoc_operator,
        root=root,
        store=store,
        worm_receipt=worm_receipt,
        legal_hold=legal_hold,
        key=key,
        require_complete=require_complete,
        require_fresh=require_fresh,
        now=now,
        authority_artifacts=authority_artifacts,
    )
    if not result.ok:
        raise ValueError("invalid BYOC authority dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "generated_at": dossier.get("generated_at"),
        "dossier_ref": dossier.get("dossier_ref"),
        "authority_ref": dossier.get("authority_ref"),
        "producer_ref": dossier.get("producer_ref"),
        "source_binding": dossier.get("source_binding"),
        "summary": dossier.get("summary"),
        "artifact_summary": dossier.get("artifact_summary"),
        "control_summary": _status_summary(dossier.get("controls", [])),
        "authority_evidence": [
            {
                "requirement_id": item.get("requirement_id"),
                "authority_kind": item.get("authority_kind"),
                "evidence_ref": item.get("evidence_ref"),
                "evidence_hash": item.get("evidence_hash"),
                "evidence_id": item.get("evidence_id"),
                "issued_at": item.get("issued_at"),
                "expires_at": item.get("expires_at"),
            }
            for item in dossier.get("authority_evidence", [])
            if isinstance(item, dict)
        ],
        "authority_artifacts": [
            {
                "requirement_id": item.get("requirement_id"),
                "evidence_ref": item.get("evidence_ref"),
                "evidence_id": item.get("evidence_id"),
                "path": item.get("path"),
                "sha256": item.get("sha256"),
                "artifact_id": item.get("artifact_id"),
            }
            for item in dossier.get("authority_artifacts", [])
            if isinstance(item, dict)
        ],
    }
    return chain.append(BYOC_AUTHORITY_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def _source_binding(deployment_manifest: dict[str, Any], byoc_operator: dict[str, Any]) -> dict[str, Any]:
    return {
        "deployment_manifest": _deployment_binding(deployment_manifest),
        "byoc_operator": _operator_binding(byoc_operator),
        "object_lock": _object_lock_binding(byoc_operator),
        "tenancy": _copy_record(byoc_operator.get("tenancy")),
        "network": _copy_record(byoc_operator.get("network")),
        "backup": _copy_record(byoc_operator.get("backup")),
        "audit_log": _copy_record(byoc_operator.get("audit_log")),
    }


def _deployment_binding(manifest: dict[str, Any]) -> dict[str, Any]:
    deployment = manifest.get("deployment", {}) if isinstance(manifest, dict) else {}
    return {
        "manifest_id": manifest.get("manifest_id"),
        "manifest_hash": content_hash(manifest),
        "schema": manifest.get("schema"),
        "name": deployment.get("name") if isinstance(deployment, dict) else None,
        "mode": deployment.get("mode") if isinstance(deployment, dict) else None,
        "environment": deployment.get("environment") if isinstance(deployment, dict) else None,
        "artifact_type": deployment.get("artifact_type") if isinstance(deployment, dict) else None,
        "source_file_count": len(manifest.get("source_files", [])) if isinstance(manifest.get("source_files"), list) else 0,
    }


def _operator_binding(attestation: dict[str, Any]) -> dict[str, Any]:
    operator = attestation.get("operator", {}) if isinstance(attestation, dict) else {}
    return {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_hash": content_hash(attestation),
        "schema": attestation.get("schema"),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "operator_ref": operator.get("operator_ref") if isinstance(operator, dict) else None,
        "version": operator.get("version") if isinstance(operator, dict) else None,
        "image_digest": operator.get("image_digest") if isinstance(operator, dict) else None,
        "namespace": operator.get("namespace") if isinstance(operator, dict) else None,
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }


def _object_lock_binding(attestation: dict[str, Any]) -> dict[str, Any]:
    object_lock = attestation.get("object_lock", {}) if isinstance(attestation, dict) else {}
    receipt = object_lock.get("worm_receipt") if isinstance(object_lock, dict) else None
    legal_hold = object_lock.get("legal_hold") if isinstance(object_lock, dict) else None
    return {
        "provider": object_lock.get("provider") if isinstance(object_lock, dict) else None,
        "mode": object_lock.get("mode") if isinstance(object_lock, dict) else None,
        "bucket_ref": object_lock.get("bucket_ref") if isinstance(object_lock, dict) else None,
        "region": object_lock.get("region") if isinstance(object_lock, dict) else None,
        "object_lock_enabled": object_lock.get("object_lock_enabled") if isinstance(object_lock, dict) else None,
        "versioning_enabled": object_lock.get("versioning_enabled") if isinstance(object_lock, dict) else None,
        "retention_mode": object_lock.get("retention_mode") if isinstance(object_lock, dict) else None,
        "retention_until": object_lock.get("retention_until") if isinstance(object_lock, dict) else None,
        "legal_hold_required": object_lock.get("legal_hold_required") if isinstance(object_lock, dict) else None,
        "worm_receipt": _copy_record(receipt),
        "legal_hold": _copy_record(legal_hold),
    }


def _copy_record(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, dict) else None


def _verify_source_binding(
    binding: Any,
    deployment_manifest: dict[str, Any] | None,
    byoc_operator: dict[str, Any] | None,
    errors: list[str],
    warnings: list[str],
    *,
    root: str | Path,
    store: str | Path,
    worm_receipt: dict[str, Any] | None,
    legal_hold: dict[str, Any] | None,
    key: str | None,
) -> None:
    if not isinstance(binding, dict):
        errors.append("BYOC authority source_binding is required")
        return
    _verify_binding_completeness(binding, errors)
    if deployment_manifest is None:
        warnings.append("BYOC authority deployment manifest source was not supplied; manifest binding hashes were not replayed")
        return
    deployment_result = verify_deployment_manifest(deployment_manifest, root=root, key=key)
    errors.extend(f"BYOC authority deployment source: {error}" for error in deployment_result.errors)
    warnings.extend(f"BYOC authority deployment source: {warning}" for warning in deployment_result.warnings)
    if byoc_operator is None:
        warnings.append("BYOC authority BYOC operator source was not supplied; operator binding hashes were not replayed")
        return
    operator_result = verify_byoc_operator_attestation(
        byoc_operator,
        deployment_manifest,
        worm_receipt,
        legal_hold=legal_hold,
        root=root,
        store=store,
        key=key,
    )
    errors.extend(f"BYOC authority operator source: {error}" for error in operator_result.errors)
    warnings.extend(f"BYOC authority operator source: {warning}" for warning in operator_result.warnings)
    expected = _source_binding(deployment_manifest, byoc_operator)
    if binding != expected:
        errors.append("BYOC authority source_binding does not match supplied source artifacts")


def _verify_binding_completeness(binding: dict[str, Any], errors: list[str]) -> None:
    deployment = _binding_section(binding, "deployment_manifest", errors)
    for field in ("manifest_id", "manifest_hash", "schema", "name", "mode", "environment", "artifact_type"):
        _require_binding_field(deployment, f"source_binding.deployment_manifest.{field}", errors)
    _require_positive_binding_count(deployment, "source_binding.deployment_manifest.source_file_count", errors)

    operator = _binding_section(binding, "byoc_operator", errors)
    for field in ("attestation_id", "attestation_hash", "schema", "mode", "environment", "attested_at", "operator_ref", "version", "image_digest", "namespace"):
        _require_binding_field(operator, f"source_binding.byoc_operator.{field}", errors)
    _require_binding_field(operator, "source_binding.byoc_operator.control_summary", errors)
    _verify_source_artifact_bindings(operator.get("source_artifacts"), "source_binding.byoc_operator.source_artifacts", errors)

    object_lock = _binding_section(binding, "object_lock", errors)
    for field in ("provider", "mode", "bucket_ref", "region", "object_lock_enabled", "versioning_enabled", "retention_mode", "retention_until", "legal_hold_required"):
        _require_binding_field(object_lock, f"source_binding.object_lock.{field}", errors)
    receipt = object_lock.get("worm_receipt")
    if not isinstance(receipt, dict):
        errors.append("BYOC authority source_binding.object_lock.worm_receipt is required")
        receipt = {}
    for field in ("receipt_id", "receipt_hash", "content_hash", "artifact_type", "object_path", "retention_until"):
        _require_binding_field(receipt, f"source_binding.object_lock.worm_receipt.{field}", errors)
    _require_positive_binding_count(receipt, "source_binding.object_lock.worm_receipt.size_bytes", errors)
    legal_hold = object_lock.get("legal_hold")
    if not isinstance(legal_hold, dict):
        errors.append("BYOC authority source_binding.object_lock.legal_hold is required")
        legal_hold = {}
    for field in ("legal_hold_id", "legal_hold_hash", "case_id", "status", "applied_at"):
        _require_binding_field(legal_hold, f"source_binding.object_lock.legal_hold.{field}", errors)

    tenancy = _binding_section(binding, "tenancy", errors)
    for field in ("tenant_id", "customer_account_ref", "data_plane_ref", "control_plane_ref", "keyring_ref"):
        _require_binding_field(tenancy, f"source_binding.tenancy.{field}", errors)

    network = _binding_section(binding, "network", errors)
    for field in ("ingress_mode", "egress_policy_ref", "private_endpoint", "allowed_egress_refs", "airgap_bundle_ref", "airgap_bundle_hash"):
        _require_binding_field(network, f"source_binding.network.{field}", errors)

    backup = _binding_section(binding, "backup", errors)
    for field in ("backup_policy_ref", "schedule", "restore_test_ref", "restore_test_at"):
        _require_binding_field(backup, f"source_binding.backup.{field}", errors)
    for field in ("rpo_minutes", "rto_minutes"):
        _require_nonnegative_binding_count(backup, f"source_binding.backup.{field}", errors)

    audit_log = _binding_section(binding, "audit_log", errors)
    for field in ("audit_log_ref", "root", "retention_until"):
        _require_binding_field(audit_log, f"source_binding.audit_log.{field}", errors)


def _binding_section(binding: dict[str, Any], section: str, errors: list[str]) -> dict[str, Any]:
    value = binding.get(section)
    if not isinstance(value, dict):
        errors.append(f"BYOC authority source_binding.{section} is required")
        return {}
    return value


def _verify_source_artifact_bindings(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"BYOC authority {path} is required")
        return
    for index, artifact in enumerate(value):
        if not isinstance(artifact, dict):
            errors.append(f"BYOC authority {path}[{index}] must be an object")
            continue
        for field in ("type", "id", "schema", "hash"):
            _require_binding_field(artifact, f"{path}[{index}].{field}", errors)


def _require_binding_field(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if value is None or value == "" or value == [] or value == {}:
        errors.append(f"BYOC authority {path} is required")


def _require_positive_binding_count(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if not isinstance(value, int) or value <= 0:
        errors.append(f"BYOC authority {path} is required")


def _require_nonnegative_binding_count(container: dict[str, Any], path: str, errors: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    value = container.get(field)
    if not isinstance(value, int) or value < 0:
        errors.append(f"BYOC authority {path} is required")


def _source_binding_complete(binding: dict[str, Any]) -> bool:
    errors: list[str] = []
    _verify_binding_completeness(binding, errors)
    deployment = binding.get("deployment_manifest") if isinstance(binding.get("deployment_manifest"), dict) else {}
    operator = binding.get("byoc_operator") if isinstance(binding.get("byoc_operator"), dict) else {}
    object_lock = binding.get("object_lock") if isinstance(binding.get("object_lock"), dict) else {}
    tenancy = binding.get("tenancy") if isinstance(binding.get("tenancy"), dict) else {}
    network = binding.get("network") if isinstance(binding.get("network"), dict) else {}
    backup = binding.get("backup") if isinstance(binding.get("backup"), dict) else {}
    audit_log = binding.get("audit_log") if isinstance(binding.get("audit_log"), dict) else {}
    receipt = object_lock.get("worm_receipt") if isinstance(object_lock.get("worm_receipt"), dict) else {}
    legal_hold = object_lock.get("legal_hold") if isinstance(object_lock.get("legal_hold"), dict) else {}
    return bool(
        not errors
        and deployment.get("manifest_id")
        and operator.get("attestation_id")
        and operator.get("mode") == "byoc-operator-attested"
        and object_lock.get("object_lock_enabled") is True
        and object_lock.get("versioning_enabled") is True
        and receipt.get("receipt_id")
        and legal_hold.get("legal_hold_id")
        and tenancy.get("customer_account_ref")
        and tenancy.get("data_plane_ref")
        and tenancy.get("keyring_ref")
        and network.get("ingress_mode")
        and network.get("egress_policy_ref")
        and network.get("private_endpoint") is True
        and backup.get("restore_test_ref")
        and audit_log.get("root")
        and audit_log.get("retention_until")
    )


def _build_authority_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority evidence item must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    evidence_ref = str(item.get("evidence_ref") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    description = str(item.get("description") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported BYOC authority requirement: {requirement_id}")
    requirement = next(req for req in PRODUCTION_AUTHORITY_REQUIREMENTS if req["id"] == requirement_id)
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if authority_kind not in requirement["authority_kinds"]:
        raise ValueError(f"authority kind {authority_kind} is not valid for requirement {requirement_id}")
    for value, field in ((evidence_ref, "evidence_ref"), (evidence_hash, "evidence_hash"), (description, "description")):
        _require_text(value, field)
    if not evidence_hash.startswith("sha256:"):
        raise ValueError("evidence_hash must start with sha256:")
    built = {"requirement_id": requirement_id, "authority_kind": authority_kind, "evidence_ref": evidence_ref, "evidence_hash": evidence_hash, "description": description}
    for field in ("issuer", "subject", "source_uri", "issued_at", "expires_at"):
        if item.get(field):
            built[field] = str(item[field])
    for field in ("issued_at", "expires_at"):
        if built.get(field):
            parse_rfc3339(str(built[field]))
    if built.get("issued_at") and built.get("expires_at") and parse_rfc3339(str(built["issued_at"])) > parse_rfc3339(str(built["expires_at"])):
        raise ValueError("authority evidence issued_at must not be after expires_at")
    built["evidence_id"] = content_hash(built)
    return built


def _verify_authority_evidence_item(item: dict[str, Any], errors: list[str], warnings: list[str], *, now, require_fresh: bool) -> str:
    try:
        expected = _build_authority_evidence_item(item)
    except ValueError as exc:
        errors.append(f"invalid BYOC authority evidence: {exc}")
        return "missing"
    if item != expected:
        errors.append("BYOC authority evidence_id does not match evidence body")
    issued_at = item.get("issued_at")
    expires_at = item.get("expires_at")
    if not issued_at or not expires_at:
        if require_fresh:
            errors.append(f"BYOC authority evidence {item.get('requirement_id')} freshness metadata missing")
        return "missing"
    issued = parse_rfc3339(str(issued_at))
    expires = parse_rfc3339(str(expires_at))
    if issued > expires:
        errors.append(f"BYOC authority evidence {item.get('requirement_id')} issued_at is after expires_at")
        return "stale"
    if now < issued or now > expires:
        message = f"BYOC authority evidence {item.get('requirement_id')} is outside its freshness window"
        if require_fresh:
            errors.append(message)
        else:
            warnings.append(message)
        return "stale"
    return "fresh"


def _build_authority_artifact(root: Path, item: dict[str, Any], evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("authority artifact must be an object")
    requirement_id = str(item.get("requirement_id") or "")
    relative_path = str(item.get("path") or "").replace("\\", "/")
    evidence_ref = str(item.get("evidence_ref") or "")
    if requirement_id not in PRODUCTION_AUTHORITY_REQUIREMENT_IDS:
        raise ValueError(f"unsupported BYOC authority artifact requirement: {requirement_id}")
    _require_text(relative_path, "authority_artifact.path")
    path_obj = Path(relative_path)
    if path_obj.is_absolute() or ".." in path_obj.parts:
        raise ValueError("authority artifact path must be repository-relative")
    matching = [evidence for evidence in evidence_items if evidence.get("requirement_id") == requirement_id]
    if evidence_ref:
        matching = [evidence for evidence in matching if evidence.get("evidence_ref") == evidence_ref]
    if not matching:
        raise ValueError(f"authority artifact has no matching evidence item: {requirement_id}")
    if len(matching) > 1:
        raise ValueError(f"authority artifact evidence_ref is required when multiple evidence items cover {requirement_id}")
    evidence = matching[0]
    target = root / relative_path
    if not target.is_file():
        raise ValueError(f"authority artifact file missing: {relative_path}")
    data = target.read_bytes()
    sha = "sha256:" + sha256(data).hexdigest()
    if sha != evidence.get("evidence_hash"):
        raise ValueError(f"authority artifact hash does not match authority evidence: {requirement_id}")
    body = {
        "requirement_id": requirement_id,
        "evidence_ref": evidence.get("evidence_ref"),
        "evidence_id": evidence.get("evidence_id"),
        "path": relative_path,
        "sha256": sha,
        "size_bytes": len(data),
    }
    return {**body, "artifact_id": content_hash(body)}


def _verify_authority_artifacts(root: Path, artifacts: list[Any], evidence_items: list[dict[str, Any]], errors: list[str], warnings: list[str]) -> int:
    replayed = 0
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict):
            errors.append(f"BYOC authority artifact {index + 1} must be an object")
            continue
        try:
            expected = _build_authority_artifact(root, item, evidence_items)
        except ValueError as exc:
            errors.append(f"invalid BYOC authority artifact {index + 1}: {exc}")
            continue
        if item != expected:
            errors.append(f"BYOC authority artifact {index + 1} does not match replayed file metadata")
            continue
        replayed += 1
    if not artifacts:
        warnings.append("BYOC authority dossier has no replayable authority evidence artifacts")
    return replayed


def _artifact_summary(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    requirement_ids = sorted({str(item.get("requirement_id")) for item in artifacts if item.get("requirement_id")})
    return {
        "artifact_count": len(artifacts),
        "requirement_count": len(requirement_ids),
        "requirement_ids": requirement_ids,
        "artifact_hash_root": content_hash([item.get("sha256") for item in artifacts]),
    }


def _verify_required_authority(value: Any, errors: list[str]) -> None:
    if value != PRODUCTION_AUTHORITY_REQUIREMENTS:
        errors.append("BYOC authority required_production_authority does not match the required checklist")


def _summary(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted({item.get("requirement_id") for item in evidence_items if item.get("requirement_id")})
    missing = [req_id for req_id in PRODUCTION_AUTHORITY_REQUIREMENT_IDS if req_id not in covered]
    return {
        "required_requirement_count": len(PRODUCTION_AUTHORITY_REQUIREMENT_IDS),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
        "authority_evidence_count": len(evidence_items),
    }


def _controls(mode: str, binding: dict[str, Any], evidence_items: list[dict[str, Any]], summary: dict[str, Any], artifact_summary: dict[str, Any]) -> list[dict[str, str]]:
    freshness = _freshness_summary(evidence_items)
    missing = summary.get("missing_requirement_count", 0)
    deployment = binding.get("deployment_manifest") if isinstance(binding.get("deployment_manifest"), dict) else {}
    operator = binding.get("byoc_operator") if isinstance(binding.get("byoc_operator"), dict) else {}
    object_lock = binding.get("object_lock") if isinstance(binding.get("object_lock"), dict) else {}
    tenancy = binding.get("tenancy") if isinstance(binding.get("tenancy"), dict) else {}
    network = binding.get("network") if isinstance(binding.get("network"), dict) else {}
    backup = binding.get("backup") if isinstance(binding.get("backup"), dict) else {}
    audit_log = binding.get("audit_log") if isinstance(binding.get("audit_log"), dict) else {}
    receipt = object_lock.get("worm_receipt") if isinstance(object_lock.get("worm_receipt"), dict) else {}
    legal_hold = object_lock.get("legal_hold") if isinstance(object_lock.get("legal_hold"), dict) else {}
    covered_ids = set(summary.get("covered_requirement_ids", []))
    network_policy_authority_covered = "network-policy-admission-audit-export" in covered_ids
    artifact_count = int(artifact_summary.get("artifact_count", 0) or 0)
    production_ready = mode == "production-dossier" and _source_binding_complete(binding) and not missing and freshness["missing"] == 0
    return [
        {"id": "deployment-manifest-bound", "status": "passed" if deployment.get("manifest_id") else "failed", "detail": "Dossier binds the signed Docker/Helm deployment manifest, source file hashes, mode, and environment."},
        {"id": "byoc-operator-attestation-bound", "status": "passed" if operator.get("attestation_id") else "failed", "detail": "Dossier binds the signed BYOC operator attestation, image digest, namespace, source artifacts, and control summary."},
        {"id": "worm-retention-legal-hold-bound", "status": "passed" if receipt.get("receipt_id") and legal_hold.get("legal_hold_id") else "deferred", "detail": "Object Lock, WORM receipt, retention, and legal-hold evidence are hash-bound when supplied through the operator attestation."},
        {"id": "customer-account-and-key-custody-bound", "status": "passed" if tenancy.get("customer_account_ref") and tenancy.get("keyring_ref") else "deferred", "detail": "Customer account, tenant data plane, control plane, and keyring references are bound."},
        {"id": "backup-and-network-controls-bound", "status": "passed" if backup.get("restore_test_ref") and network.get("egress_policy_ref") and network.get("private_endpoint") is True else "deferred", "detail": "Backup/restore drill, RPO/RTO, private ingress, egress policy, and optional air-gap bundle references are bound."},
        {"id": "audit-log-retention-bound", "status": "passed" if audit_log.get("root") and audit_log.get("retention_until") else "deferred", "detail": "Immutable operator audit-log root and retention-until timestamp are bound."},
        {"id": "authority-evidence-checklist-covered", "status": "passed" if not missing else "deferred", "detail": f"{summary.get('covered_requirement_count', 0)}/{summary.get('required_requirement_count', 0)} BYOC production authority categories are covered."},
        {"id": "network-policy-admission-audit-export-covered", "status": "passed" if network_policy_authority_covered else "deferred", "detail": "Provider/customer Kubernetes NetworkPolicy admission and audit evidence is tracked separately from local Helm chart validation."},
        {"id": "freshness-windows-tracked", "status": "passed" if evidence_items and freshness["missing"] == 0 else "deferred", "detail": f"windowed={freshness['windowed']} missing_freshness={freshness['missing']}"},
        {"id": "authority-artifacts-replayed", "status": "passed" if artifact_count else "deferred", "detail": f"replayed={artifact_count} authority evidence artifacts hash-match retained source files."},
        {"id": "production-mode-gated", "status": "passed" if production_ready else "deferred", "detail": "Production BYOC authority is claimed only when deployment, operator, WORM/legal hold, tenancy, backup, network, audit, and every authority category are covered with timestamped evidence windows."},
        {"id": "raw-secret-exclusion", "status": "passed", "detail": "Dossier stores hashes and references instead of raw customer cloud, KMS, Kubernetes, or operator credentials."},
    ]


def _freshness_summary(evidence_items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"windowed": 0, "missing": 0}
    for item in evidence_items:
        if item.get("issued_at") and item.get("expires_at"):
            counts["windowed"] += 1
        else:
            counts["missing"] += 1
    return counts


def _freshness_reference(dossier: dict[str, Any], now: str | None, errors: list[str]):
    value = now or dossier.get("generated_at") or utc_now()
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"freshness reference time invalid: {exc}")
        return parse_rfc3339(utc_now())


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if not isinstance(controls, list):
        return summary
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _check_no_secret_values(value: Any, errors: list[str], path: str = "dossier") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            nested_path = f"{path}.{key_text}"
            if any(marker in key_text.lower() for marker in SECRET_KEY_MARKERS) and not _allowed_secret_reference_key(key_text):
                if isinstance(nested, str) and not _is_redacted_reference(nested):
                    errors.append(f"raw secret-like value is not allowed at {nested_path}")
            _check_no_secret_values(nested, errors, nested_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _check_no_secret_values(nested, errors, f"{path}[{index}]")


def _allowed_secret_reference_key(key: str) -> bool:
    lowered = key.lower()
    return lowered.endswith(("_ref", "_hash", "_root", "_id"))


def _is_redacted_reference(value: str) -> bool:
    return value.startswith(("env:", "vault:", "kms:", "secret-ref:", "sha256:", "hash:"))


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"BYOC authority {field} is required")
