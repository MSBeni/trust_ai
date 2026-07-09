from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .byoc_operator import verify_byoc_operator_attestation
from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value
from .deployment import verify_deployment_manifest
from .eu_ai_act import verify_eu_ai_act_document

EU_DATA_PLANE_SCHEMA = "trustai.eu-data-plane-attestation/0.1"
EU_DATA_PLANE_ENTRY_TYPE = "deployment.eu_data_plane_attested"
EU_DATA_PLANE_MODES = {"local-reference", "eu-data-plane-attested", "production-design"}

EU_CLOUD_REGIONS = {
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-3",
    "eu-south-1",
    "eu-south-2",
    "eu-north-1",
    "europe-west1",
    "europe-west3",
    "europe-west4",
    "europe-west8",
    "europe-west9",
    "europe-west10",
    "europe-west12",
    "europe-north1",
    "europe-southwest1",
    "germanywestcentral",
    "westeurope",
    "northeurope",
    "francecentral",
    "swedencentral",
    "italynorth",
    "polandcentral",
    "spaincentral",
}
SECRET_KEY_MARKERS = ("token", "secret", "private_key", "client_secret", "password", "credential")


@dataclass
class EUDataPlaneVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_eu_data_plane_attestation(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("EU data-plane attestation must contain an object")
    return value


def write_eu_data_plane_attestation(path: str | Path, attestation: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")


def build_eu_data_plane_attestation(
    deployment_manifest: dict[str, Any],
    byoc_operator: dict[str, Any],
    *,
    eu_ai_act_document: dict[str, Any] | None = None,
    root: str | Path = ".",
    mode: str = "eu-data-plane-attested",
    environment: str = "local",
    tenant_id: str,
    data_plane_ref: str,
    control_plane_ref: str | None = None,
    primary_region: str,
    primary_location: str = "Frankfurt, Germany",
    availability_zones: list[str] | None = None,
    replica_regions: list[str] | None = None,
    backup_regions: list[str] | None = None,
    analytics_region: str | None = None,
    log_region: str | None = None,
    data_categories: list[str] | None = None,
    subprocessor_refs: list[str] | None = None,
    residency_policy_ref: str,
    data_classification_policy_ref: str,
    dpa_ref: str,
    transfer_impact_assessment_ref: str,
    scc_ref: str | None = None,
    deletion_policy_ref: str,
    data_export_policy_ref: str,
    encryption_key_ref: str,
    kms_key_region: str,
    key_access_policy_ref: str,
    hsm_ref: str | None = None,
    customer_managed_keys: bool = True,
    cross_border_egress_allowed: bool = False,
    network_policy_ref: str,
    support_access_policy_ref: str,
    support_access_jit: bool = True,
    breakglass_policy_ref: str,
    audit_log_ref: str,
    audit_log_root: str,
    access_log_ref: str,
    access_log_root: str,
    transfer_log_ref: str,
    transfer_log_root: str,
    retention_until: str,
    actor_ref: str,
    credential_ref: str,
    evidence_refs: list[str] | None = None,
    attested_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in EU_DATA_PLANE_MODES:
        raise ValueError(f"mode must be one of {sorted(EU_DATA_PLANE_MODES)}")

    deploy_result = verify_deployment_manifest(deployment_manifest, root=root, key=key)
    if not deploy_result.ok:
        raise ValueError("invalid deployment manifest: " + "; ".join(deploy_result.errors))

    byoc_result = verify_byoc_operator_attestation(byoc_operator, key=key)
    if not byoc_result.ok:
        raise ValueError("invalid BYOC operator attestation: " + "; ".join(byoc_result.errors))

    if eu_ai_act_document is not None:
        document_result = verify_eu_ai_act_document(eu_ai_act_document, key=key)
        if not document_result.ok:
            raise ValueError("invalid EU AI Act document: " + "; ".join(document_result.errors))

    timestamp = attested_at or utc_now()
    parse_rfc3339(timestamp)
    if parse_rfc3339(retention_until) <= parse_rfc3339(timestamp):
        raise ValueError("retention_until must be after attested_at")

    byoc_tenancy = byoc_operator.get("tenancy", {}) if isinstance(byoc_operator, dict) else {}
    if tenant_id != byoc_tenancy.get("tenant_id"):
        raise ValueError("tenant_id must match BYOC operator tenancy.tenant_id")
    if data_plane_ref != byoc_tenancy.get("data_plane_ref"):
        raise ValueError("data_plane_ref must match BYOC operator tenancy.data_plane_ref")
    if control_plane_ref and byoc_tenancy.get("control_plane_ref") and control_plane_ref != byoc_tenancy.get("control_plane_ref"):
        raise ValueError("control_plane_ref must match BYOC operator tenancy.control_plane_ref when both are supplied")

    for field, value in {
        "tenant_id": tenant_id,
        "data_plane_ref": data_plane_ref,
        "primary_region": primary_region,
        "primary_location": primary_location,
        "residency_policy_ref": residency_policy_ref,
        "data_classification_policy_ref": data_classification_policy_ref,
        "dpa_ref": dpa_ref,
        "transfer_impact_assessment_ref": transfer_impact_assessment_ref,
        "deletion_policy_ref": deletion_policy_ref,
        "data_export_policy_ref": data_export_policy_ref,
        "encryption_key_ref": encryption_key_ref,
        "kms_key_region": kms_key_region,
        "key_access_policy_ref": key_access_policy_ref,
        "network_policy_ref": network_policy_ref,
        "support_access_policy_ref": support_access_policy_ref,
        "breakglass_policy_ref": breakglass_policy_ref,
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "transfer_log_ref": transfer_log_ref,
        "transfer_log_root": transfer_log_root,
        "actor_ref": actor_ref,
        "credential_ref": credential_ref,
    }.items():
        _require_text(value, field)

    byoc_network = byoc_operator.get("network", {}) if isinstance(byoc_operator, dict) else {}
    byoc_object_lock = byoc_operator.get("object_lock", {}) if isinstance(byoc_operator, dict) else {}
    deployment = deployment_manifest.get("deployment", {}) if isinstance(deployment_manifest, dict) else {}
    regions = {
        "primary_region": primary_region,
        "primary_location": primary_location,
        "availability_zones": sorted(availability_zones or []),
        "replica_regions": sorted(replica_regions or []),
        "backup_regions": sorted(backup_regions or []),
        "analytics_region": analytics_region or primary_region,
        "log_region": log_region or primary_region,
        "object_lock_region": byoc_object_lock.get("region"),
    }
    residency = {
        "tenant_id": tenant_id,
        "data_plane_ref": data_plane_ref,
        "control_plane_ref": control_plane_ref or byoc_tenancy.get("control_plane_ref"),
        "customer_account_ref": byoc_tenancy.get("customer_account_ref"),
        "data_categories": sorted(data_categories or []),
        "subprocessor_refs": sorted(subprocessor_refs or []),
        "residency_policy_ref": residency_policy_ref,
        "data_classification_policy_ref": data_classification_policy_ref,
        "dpa_ref": dpa_ref,
        "transfer_impact_assessment_ref": transfer_impact_assessment_ref,
        "scc_ref": scc_ref,
        "cross_border_egress_allowed": cross_border_egress_allowed,
        "deletion_policy_ref": deletion_policy_ref,
        "data_export_policy_ref": data_export_policy_ref,
    }
    sovereignty = {
        "customer_managed_keys": customer_managed_keys,
        "keyring_ref": byoc_tenancy.get("keyring_ref"),
        "encryption_key_ref": encryption_key_ref,
        "kms_key_region": kms_key_region,
        "key_access_policy_ref": key_access_policy_ref,
        "hsm_ref": hsm_ref,
    }
    network = {
        "ingress_mode": byoc_network.get("ingress_mode"),
        "private_endpoint": byoc_network.get("private_endpoint") is True,
        "egress_policy_ref": byoc_network.get("egress_policy_ref"),
        "allowed_egress_refs": sorted(byoc_network.get("allowed_egress_refs") or []),
        "network_policy_ref": network_policy_ref,
        "support_access_policy_ref": support_access_policy_ref,
        "support_access_jit": support_access_jit,
        "breakglass_policy_ref": breakglass_policy_ref,
    }
    audit = {
        "audit_log_ref": audit_log_ref,
        "audit_log_root": audit_log_root,
        "access_log_ref": access_log_ref,
        "access_log_root": access_log_root,
        "transfer_log_ref": transfer_log_ref,
        "transfer_log_root": transfer_log_root,
        "retention_until": retention_until,
    }
    operation = {
        "actor_ref": actor_ref,
        "credential": _redacted_ref(credential_ref),
        "evidence_refs": sorted(evidence_refs or []),
    }
    source = _source_record(deployment_manifest, byoc_operator, eu_ai_act_document)
    body: dict[str, Any] = {
        "schema": EU_DATA_PLANE_SCHEMA,
        "mode": mode,
        "environment": environment,
        "attested_at": timestamp,
        "source": source,
        "deployment": {
            "manifest_id": deployment_manifest.get("manifest_id"),
            "manifest_hash": content_hash(deployment_manifest),
            "name": deployment.get("name"),
            "mode": deployment.get("mode"),
            "environment": deployment.get("environment"),
        },
        "regions": regions,
        "residency": residency,
        "sovereignty": sovereignty,
        "network": network,
        "audit": audit,
        "operation": operation,
        "source_artifacts": _source_artifacts(deployment_manifest, byoc_operator, eu_ai_act_document),
        "controls": _controls(
            source=source,
            mode=mode,
            regions=regions,
            residency=residency,
            sovereignty=sovereignty,
            network=network,
            has_eu_ai_act_document=eu_ai_act_document is not None,
        ),
        "limitations": [
            "This attestation binds EU data-plane residency and sovereignty controls to signed deployment and BYOC operator evidence.",
            "It records region, backup, log, transfer, subprocessor, key-residency, network, access, and audit-log controls without storing raw credentials or customer payloads.",
            "Local-reference evidence does not prove a continuously operated Frankfurt cloud deployment or live cloud KMS/HSM policy enforcement.",
            "Production deployments should preserve cloud provider region exports, KMS/HSM policy exports, data transfer logs, access logs, subprocessor records, and independently retained audit roots.",
        ],
    }
    attestation_id = content_hash(body)
    return {
        **body,
        "attestation_id": attestation_id,
        "signatures": [sign_value({"attestation_id": attestation_id, "eu_data_plane": body}, key)],
    }


def verify_eu_data_plane_attestation(
    attestation: dict[str, Any],
    deployment_manifest: dict[str, Any] | None = None,
    byoc_operator: dict[str, Any] | None = None,
    *,
    eu_ai_act_document: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> EUDataPlaneVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if attestation.get("schema") != EU_DATA_PLANE_SCHEMA:
        errors.append(f"unsupported EU data-plane attestation schema: {attestation.get('schema')}")
    body = without_keys(attestation, "attestation_id", "signatures")
    expected_id = content_hash(body)
    if attestation.get("attestation_id") != expected_id:
        errors.append("attestation_id does not match canonical EU data-plane attestation body")

    signatures = attestation.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("EU data-plane attestation must include at least one signature")
    else:
        signed_value = {"attestation_id": attestation.get("attestation_id"), "eu_data_plane": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("EU data-plane attestation signature verification failed")

    try:
        attested = parse_rfc3339(str(attestation.get("attested_at") or ""))
    except ValueError as exc:
        errors.append(f"EU data-plane attested_at invalid: {exc}")
        attested = None

    mode = attestation.get("mode")
    if mode not in EU_DATA_PLANE_MODES:
        errors.append("EU data-plane mode is unsupported")
    elif mode != "eu-data-plane-attested":
        warnings.append(f"EU data-plane mode is {mode}; live EU data-plane enforcement is not fully claimed")

    _verify_source_record(attestation.get("source"), errors)
    _verify_deployment_record(attestation.get("deployment"), errors)
    _verify_regions(attestation.get("regions"), errors, warnings)
    _verify_residency(attestation.get("residency"), errors, warnings)
    _verify_sovereignty(attestation.get("sovereignty"), errors)
    _verify_network(attestation.get("network"), errors, warnings)
    _verify_audit(attestation.get("audit"), attested, errors)
    _verify_operation(attestation.get("operation"), errors)

    controls = attestation.get("controls", [])
    if not isinstance(controls, list) or not controls:
        errors.append("EU data-plane controls are required")

    source_artifacts = attestation.get("source_artifacts", [])
    if not isinstance(source_artifacts, list) or len(source_artifacts) < 2:
        errors.append("EU data-plane source_artifacts must contain at least deployment and BYOC sources")

    supplied_sources = _source_artifacts(deployment_manifest, byoc_operator, eu_ai_act_document)
    if supplied_sources:
        if source_artifacts != supplied_sources:
            errors.append("EU data-plane source_artifacts do not match supplied source artifacts")
        expected_source = _source_record(deployment_manifest, byoc_operator, eu_ai_act_document)
        if attestation.get("source") != expected_source:
            errors.append("EU data-plane source record does not match supplied artifacts")

    if deployment_manifest is not None:
        deploy_result = verify_deployment_manifest(deployment_manifest, root=root, key=key)
        errors.extend(f"deployment manifest invalid: {error}" for error in deploy_result.errors)
        warnings.extend(f"deployment manifest: {warning}" for warning in deploy_result.warnings)
    else:
        warnings.append("deployment manifest not supplied; source file hashes were not replayed")

    if byoc_operator is not None:
        byoc_result = verify_byoc_operator_attestation(byoc_operator, key=key)
        errors.extend(f"BYOC operator attestation invalid: {error}" for error in byoc_result.errors)
        warnings.extend(f"BYOC operator attestation: {warning}" for warning in byoc_result.warnings)
        _verify_byoc_matches_attestation(attestation, byoc_operator, errors)
    else:
        warnings.append("BYOC operator attestation not supplied; operator source hash was not replayed")

    if eu_ai_act_document is not None:
        document_result = verify_eu_ai_act_document(eu_ai_act_document, key=key)
        errors.extend(f"EU AI Act document invalid: {error}" for error in document_result.errors)
        warnings.extend(f"EU AI Act document: {warning}" for warning in document_result.warnings)
    elif attestation.get("source", {}).get("eu_ai_act_document_id"):
        warnings.append("EU AI Act document source was not supplied for deep verification")

    _check_no_secret_values(attestation, errors)
    return EUDataPlaneVerification(ok=not errors, errors=errors, warnings=warnings)


def append_eu_data_plane_attestation(
    chain: EvidenceChain,
    attestation: dict[str, Any],
    deployment_manifest: dict[str, Any] | None = None,
    byoc_operator: dict[str, Any] | None = None,
    *,
    eu_ai_act_document: dict[str, Any] | None = None,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_eu_data_plane_attestation(
        attestation,
        deployment_manifest,
        byoc_operator,
        eu_ai_act_document=eu_ai_act_document,
        root=root,
        key=key,
    )
    if not result.ok:
        raise ValueError("invalid EU data-plane attestation: " + "; ".join(result.errors))
    payload = {
        "attestation_id": attestation["attestation_id"],
        "attestation_hash": content_hash(attestation),
        "mode": attestation.get("mode"),
        "environment": attestation.get("environment"),
        "attested_at": attestation.get("attested_at"),
        "source": attestation.get("source"),
        "deployment": attestation.get("deployment"),
        "regions": attestation.get("regions"),
        "residency": attestation.get("residency"),
        "sovereignty": attestation.get("sovereignty"),
        "network": attestation.get("network"),
        "audit": attestation.get("audit"),
        "operation": attestation.get("operation"),
        "source_artifacts": attestation.get("source_artifacts"),
        "control_summary": _status_summary(attestation.get("controls", [])),
    }
    return chain.append(EU_DATA_PLANE_ENTRY_TYPE, payload, key=key, timestamp=attestation.get("attested_at"))


def _source_record(
    deployment_manifest: dict[str, Any] | None,
    byoc_operator: dict[str, Any] | None,
    eu_ai_act_document: dict[str, Any] | None,
) -> dict[str, Any]:
    byoc_tenancy = byoc_operator.get("tenancy", {}) if isinstance(byoc_operator, dict) else {}
    return {
        "deployment_manifest_id": deployment_manifest.get("manifest_id") if isinstance(deployment_manifest, dict) else None,
        "deployment_manifest_hash": content_hash(deployment_manifest) if isinstance(deployment_manifest, dict) else None,
        "byoc_attestation_id": byoc_operator.get("attestation_id") if isinstance(byoc_operator, dict) else None,
        "byoc_attestation_hash": content_hash(byoc_operator) if isinstance(byoc_operator, dict) else None,
        "byoc_mode": byoc_operator.get("mode") if isinstance(byoc_operator, dict) else None,
        "byoc_tenant_id": byoc_tenancy.get("tenant_id") if isinstance(byoc_tenancy, dict) else None,
        "byoc_data_plane_ref": byoc_tenancy.get("data_plane_ref") if isinstance(byoc_tenancy, dict) else None,
        "eu_ai_act_document_id": eu_ai_act_document.get("document_id") if isinstance(eu_ai_act_document, dict) else None,
        "eu_ai_act_document_hash": content_hash(eu_ai_act_document) if isinstance(eu_ai_act_document, dict) else None,
    }


def _source_artifacts(
    deployment_manifest: dict[str, Any] | None,
    byoc_operator: dict[str, Any] | None,
    eu_ai_act_document: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if isinstance(deployment_manifest, dict):
        artifacts.append(
            {
                "type": "deployment-manifest",
                "id": deployment_manifest.get("manifest_id"),
                "schema": deployment_manifest.get("schema"),
                "hash": content_hash(deployment_manifest),
            }
        )
    if isinstance(byoc_operator, dict):
        artifacts.append(
            {
                "type": "byoc-operator-attestation",
                "id": byoc_operator.get("attestation_id"),
                "schema": byoc_operator.get("schema"),
                "hash": content_hash(byoc_operator),
            }
        )
    if isinstance(eu_ai_act_document, dict):
        artifacts.append(
            {
                "type": "eu-ai-act-technical-documentation",
                "id": eu_ai_act_document.get("document_id"),
                "schema": eu_ai_act_document.get("schema"),
                "hash": content_hash(eu_ai_act_document),
            }
        )
    return artifacts


def _controls(
    *,
    source: dict[str, Any],
    mode: str,
    regions: dict[str, Any],
    residency: dict[str, Any],
    sovereignty: dict[str, Any],
    network: dict[str, Any],
    has_eu_ai_act_document: bool,
) -> list[dict[str, str]]:
    eu_regions = [
        regions.get("primary_region"),
        regions.get("analytics_region"),
        regions.get("log_region"),
        regions.get("object_lock_region"),
        sovereignty.get("kms_key_region"),
        *regions.get("replica_regions", []),
        *regions.get("backup_regions", []),
    ]
    all_regions_eu = all(_is_eu_region(region) for region in eu_regions if region)
    return [
        {
            "id": "source-deployment-byoc-binding",
            "status": "sovereignty-attested" if source.get("deployment_manifest_id") and source.get("byoc_attestation_id") else "planned-production",
            "description": "Signed deployment and BYOC operator source artifacts are bound by canonical hash.",
        },
        {
            "id": "frankfurt-eu-region-boundary",
            "status": "sovereignty-attested" if mode == "eu-data-plane-attested" and _is_eu_region(regions.get("primary_region")) else "planned-production",
            "description": "Primary data-plane region, location, replicas, backups, logs, and analytics regions are recorded.",
        },
        {
            "id": "eu-storage-and-backup-residency",
            "status": "sovereignty-attested" if all_regions_eu else "planned-production",
            "description": "Object Lock, backup, replica, analytics, log, and key regions remain within the EU region allowlist.",
        },
        {
            "id": "customer-managed-key-residency",
            "status": "sovereignty-attested" if sovereignty.get("customer_managed_keys") and _is_eu_region(sovereignty.get("kms_key_region")) else "planned-production",
            "description": "Customer-managed key, keyring, access policy, and key-region references are bound.",
        },
        {
            "id": "transfer-governance",
            "status": "sovereignty-attested" if not residency.get("cross_border_egress_allowed") and residency.get("transfer_impact_assessment_ref") and residency.get("dpa_ref") else "planned-production",
            "description": "Cross-border transfer posture, DPA, SCC, and transfer-impact references are recorded.",
        },
        {
            "id": "subprocessor-disclosure",
            "status": "sovereignty-attested" if residency.get("subprocessor_refs") and residency.get("dpa_ref") else "planned-production",
            "description": "Subprocessor references and data-processing agreement evidence are bound.",
        },
        {
            "id": "private-network-support-access",
            "status": "sovereignty-attested" if network.get("private_endpoint") and network.get("support_access_jit") else "planned-production",
            "description": "Private endpoint, network policy, support access, and break-glass policy evidence are bound.",
        },
        {
            "id": "eu-ai-act-document-binding",
            "status": "sovereignty-attested" if has_eu_ai_act_document else "planned-production",
            "description": "Optional EU AI Act technical documentation source is bound for regulator-facing review.",
        },
    ]


def _verify_source_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("EU data-plane source must be an object")
        return
    for field in ("deployment_manifest_id", "deployment_manifest_hash", "byoc_attestation_id", "byoc_attestation_hash", "byoc_tenant_id", "byoc_data_plane_ref"):
        if not value.get(field):
            errors.append(f"EU data-plane source.{field} is required")


def _verify_deployment_record(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("EU data-plane deployment must be an object")
        return
    for field in ("manifest_id", "manifest_hash", "name", "mode", "environment"):
        if not value.get(field):
            errors.append(f"EU data-plane deployment.{field} is required")


def _verify_regions(value: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("EU data-plane regions must be an object")
        return
    for field in ("primary_region", "primary_location", "analytics_region", "log_region", "object_lock_region"):
        if not value.get(field):
            errors.append(f"EU data-plane regions.{field} is required")
    for field in ("primary_region", "analytics_region", "log_region", "object_lock_region"):
        if value.get(field) and not _is_eu_region(value.get(field)):
            errors.append(f"EU data-plane regions.{field} must be an EU cloud region")
    for field in ("replica_regions", "backup_regions"):
        items = value.get(field)
        if not isinstance(items, list) or not items:
            errors.append(f"EU data-plane regions.{field} must contain at least one region")
            continue
        for region in items:
            if not _is_eu_region(region):
                errors.append(f"EU data-plane regions.{field} contains non-EU region: {region}")
    if "frankfurt" not in str(value.get("primary_location", "")).lower() and value.get("primary_region") != "eu-central-1":
        warnings.append("EU data-plane primary location is not explicitly Frankfurt")


def _verify_residency(value: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("EU data-plane residency must be an object")
        return
    for field in ("tenant_id", "data_plane_ref", "customer_account_ref", "residency_policy_ref", "data_classification_policy_ref", "dpa_ref", "transfer_impact_assessment_ref", "deletion_policy_ref", "data_export_policy_ref"):
        if not value.get(field):
            errors.append(f"EU data-plane residency.{field} is required")
    for field in ("data_categories", "subprocessor_refs"):
        if not isinstance(value.get(field), list) or not value.get(field):
            errors.append(f"EU data-plane residency.{field} must contain at least one item")
    if value.get("cross_border_egress_allowed") is True:
        warnings.append("EU data-plane residency allows cross-border egress")
        if not value.get("scc_ref"):
            errors.append("EU data-plane residency.scc_ref is required when cross_border_egress_allowed is true")


def _verify_sovereignty(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("EU data-plane sovereignty must be an object")
        return
    for field in ("keyring_ref", "encryption_key_ref", "kms_key_region", "key_access_policy_ref"):
        if not value.get(field):
            errors.append(f"EU data-plane sovereignty.{field} is required")
    if value.get("customer_managed_keys") is not True:
        errors.append("EU data-plane sovereignty.customer_managed_keys must be true")
    if value.get("kms_key_region") and not _is_eu_region(value.get("kms_key_region")):
        errors.append("EU data-plane sovereignty.kms_key_region must be an EU cloud region")


def _verify_network(value: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("EU data-plane network must be an object")
        return
    for field in ("ingress_mode", "egress_policy_ref", "network_policy_ref", "support_access_policy_ref", "breakglass_policy_ref"):
        if not value.get(field):
            errors.append(f"EU data-plane network.{field} is required")
    if value.get("private_endpoint") is not True:
        errors.append("EU data-plane network.private_endpoint must be true")
    if value.get("support_access_jit") is not True:
        warnings.append("EU data-plane network.support_access_jit is not true")


def _verify_audit(value: Any, attested: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("EU data-plane audit must be an object")
        return
    for field in ("audit_log_ref", "audit_log_root", "access_log_ref", "access_log_root", "transfer_log_ref", "transfer_log_root", "retention_until"):
        if not value.get(field):
            errors.append(f"EU data-plane audit.{field} is required")
    for field in ("audit_log_root", "access_log_root", "transfer_log_root"):
        if value.get(field) and not _is_sha256_ref(str(value.get(field))):
            errors.append(f"EU data-plane audit.{field} must be a sha256 reference")
    try:
        retention = parse_rfc3339(str(value.get("retention_until") or ""))
        if attested and retention <= attested:
            errors.append("EU data-plane audit.retention_until must be after attested_at")
    except ValueError as exc:
        errors.append(f"EU data-plane audit.retention_until invalid: {exc}")


def _verify_operation(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("EU data-plane operation must be an object")
        return
    if not value.get("actor_ref"):
        errors.append("EU data-plane operation.actor_ref is required")
    _verify_redacted_ref(value.get("credential"), "EU data-plane operation.credential", errors)


def _verify_byoc_matches_attestation(attestation: dict[str, Any], byoc_operator: dict[str, Any], errors: list[str]) -> None:
    source = attestation.get("source", {})
    if source.get("byoc_attestation_id") != byoc_operator.get("attestation_id"):
        errors.append("EU data-plane source.byoc_attestation_id does not match supplied BYOC operator")
    if source.get("byoc_attestation_hash") != content_hash(byoc_operator):
        errors.append("EU data-plane source.byoc_attestation_hash does not match supplied BYOC operator")

    tenancy = byoc_operator.get("tenancy", {}) if isinstance(byoc_operator, dict) else {}
    residency = attestation.get("residency", {}) if isinstance(attestation.get("residency"), dict) else {}
    sovereignty = attestation.get("sovereignty", {}) if isinstance(attestation.get("sovereignty"), dict) else {}
    if residency.get("tenant_id") != tenancy.get("tenant_id"):
        errors.append("EU data-plane residency.tenant_id does not match BYOC tenancy")
    if residency.get("data_plane_ref") != tenancy.get("data_plane_ref"):
        errors.append("EU data-plane residency.data_plane_ref does not match BYOC tenancy")
    if sovereignty.get("keyring_ref") != tenancy.get("keyring_ref"):
        errors.append("EU data-plane sovereignty.keyring_ref does not match BYOC tenancy")

    object_lock = byoc_operator.get("object_lock", {}) if isinstance(byoc_operator.get("object_lock"), dict) else {}
    regions = attestation.get("regions", {}) if isinstance(attestation.get("regions"), dict) else {}
    if regions.get("object_lock_region") != object_lock.get("region"):
        errors.append("EU data-plane regions.object_lock_region does not match BYOC object_lock.region")
    if object_lock.get("region") and not _is_eu_region(object_lock.get("region")):
        errors.append("EU data-plane BYOC object_lock.region must be an EU cloud region")


def _status_summary(controls: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        status = str(control.get("status", "unknown"))
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _redacted_ref(ref: str | None) -> dict[str, Any] | None:
    if not ref:
        return None
    return {"ref": ref, "redacted": True}


def _verify_redacted_ref(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value.get("ref") or value.get("redacted") is not True:
        errors.append(f"{name} must be a redacted reference")


def _check_no_secret_values(value: Any, errors: list[str], path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                if not (isinstance(child, dict) and child.get("redacted") is True and child.get("ref")):
                    errors.append(f"EU data-plane secret-like field must be redacted reference: {child_path}")
            _check_no_secret_values(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_secret_values(child, errors, f"{path}[{index}]")


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _is_sha256_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        return bool(value[7:])
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


def _is_eu_region(value: Any) -> bool:
    return isinstance(value, str) and value in EU_CLOUD_REGIONS
