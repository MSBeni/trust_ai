from __future__ import annotations

import base64
import binascii
import json
import shlex
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PureWindowsPath
from typing import Any

from .canonical import canonical_file_bytes, content_hash, file_sha256_ref, parse_rfc3339, utc_now, without_keys
from .chain import CHAIN_SPEC_VERSION, EvidenceChain
from .merkle import merkle_root, verify_inclusion
from .roadmap_audit import ROADMAP_AUDIT_ENTRY_TYPE, STATUS_REFERENCE_ATTESTED, verify_roadmap_audit

EXTERNAL_EVIDENCE_SCHEMA = "trustai.external-evidence-manifest/0.1"
EXTERNAL_EVIDENCE_ENTRY_TYPE = "trustai.external_evidence_manifest.attested"
EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE = "trustai.external_evidence_collection_run.attested"
ROADMAP_EVIDENCE_REPORT_SCHEMA = "trustai.roadmap-evidence-report/0.1"
ROADMAP_EVIDENCE_BUNDLE_SCHEMA = "trustai.roadmap-evidence-bundle/0.1"
EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA = "trustai.external-evidence-collection-plan/0.1"
EXTERNAL_EVIDENCE_INTAKE_SCHEMA = "trustai.external-evidence-intake/0.1"
EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA = "trustai.external-evidence-source-snapshot/0.1"
EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA = "trustai.external-evidence-source-map/0.1"
EXTERNAL_EVIDENCE_COLLECTION_RUN_SCHEMA = "trustai.external-evidence-collection-run/0.1"
EXTERNAL_EVIDENCE_GAP_REPORT_SCHEMA = "trustai.external-evidence-gap-report/0.1"
EXTERNAL_EVIDENCE_WORK_PACKAGE_SCHEMA = "trustai.external-evidence-work-package/0.1"
EXTERNAL_EVIDENCE_OWNER_PACKET_SCHEMA = "trustai.external-evidence-owner-packet-bundle/0.1"
EXTERNAL_EVIDENCE_OWNER_PACKET_STATUS_SCHEMA = "trustai.external-evidence-owner-packet-status/0.1"
EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_TEMPLATE_SCHEMA = "trustai.external-evidence-owner-fulfillment-template/0.1"
EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_REVIEW_SCHEMA = "trustai.external-evidence-owner-fulfillment-review/0.1"
EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_CLOSURE_SCHEMA = "trustai.external-evidence-owner-fulfillment-closure/0.1"
EXTERNAL_EVIDENCE_READINESS_SCHEMA = "trustai.external-evidence-readiness/0.1"
EXTERNAL_EVIDENCE_PRODUCTION_REPLACEMENT_PLAN_SCHEMA = "trustai.external-evidence-production-replacement-plan/0.1"
EXTERNAL_EVIDENCE_GIT_REMOTE_REF_EXPORT_SCHEMA = "trustai.external-evidence-git-remote-ref-export/0.1"

BUNDLE_SOURCE_ARTIFACT_KINDS = {
    "roadmap-audit",
    "external-evidence-manifest",
    "external-evidence-collection-run",
    "external-evidence-source-map",
    "external-evidence-source-snapshot",
    "external-evidence-intake",
    "external-evidence-file",
    "other",
}


AUTHORITY_KIND_ORDER = (
    "ci-run",
    "kms-hsm",
    "tsa",
    "cloud-object-lock",
    "provider-api",
    "hosted-service",
    "identity-provider",
    "regulator",
    "insurer",
    "standards-body",
    "customer",
    "other",
)
EXTERNAL_EVIDENCE_PLAN_STATUS_FILTERS = {"all", "missing", "covered"}
SOURCE_MAP_FULFILLMENT_FIELDS = {
    "source_uri",
    "description",
    "source_file",
    "retrieval_method",
    "content_type",
    "issuer",
    "subject",
    "issued_at",
    "expires_at",
    "timeout_seconds",
}
SOURCE_MAP_FULFILLMENT_TASK_KEYS = ("task", "task_ref", "task_id", "unit_id", "unit_ref")
AUTHORITY_KINDS = {
    "ci-run",
    "kms-hsm",
    "tsa",
    "cloud-object-lock",
    "provider-api",
    "hosted-service",
    "identity-provider",
    "regulator",
    "insurer",
    "standards-body",
    "customer",
    "other",
}
EXTERNAL_EVIDENCE_WORK_PACKAGE_GROUP_BY = {
    "owner_hint",
    "authority_kind",
    "phase",
    "priority",
    "requirement_id",
}

AUTHORITY_KIND_KEYWORDS = {
    "ci-run": ("ci", "workflow", "github actions", "gitlab", "build", "release run"),
    "kms-hsm": ("kms", "hsm", "key custody", "signing key"),
    "tsa": ("tsa", "rfc 3161", "timestamp"),
    "cloud-object-lock": ("object lock", "worm", "retention", "cloud"),
    "provider-api": ("provider", "api", "github", "gitlab", "slack", "cloud", "kubernetes"),
    "hosted-service": ("hosted", "service", "portal", "registry", "marketplace"),
    "identity-provider": ("identity", "okta", "entra", "oidc"),
    "regulator": ("regulator", "supervisor", "conformity"),
    "insurer": ("insurer", "underwriter", "premium"),
    "standards-body": ("standards", "standards-body", "iso", "ieee", "etsi", "linux foundation"),
    "customer": ("customer", "partner", "contract", "procurement", "payment", "arr"),
}



AUTHORITY_KIND_OWNER_HINTS = {
    "ci-run": "release engineering",
    "kms-hsm": "security/platform KMS owner",
    "tsa": "security timestamping owner",
    "cloud-object-lock": "cloud storage owner",
    "provider-api": "integration/platform owner",
    "hosted-service": "service owner",
    "identity-provider": "IAM/identity owner",
    "regulator": "legal/compliance owner",
    "insurer": "risk/insurance owner",
    "standards-body": "standards/governance owner",
    "customer": "customer success/account owner",
    "other": "evidence owner",
}

AUTHORITY_KIND_EVIDENCE_HINTS = {
    "ci-run": ["completed CI workflow export", "release run URL or provider-native run record", "artifact/check provenance"],
    "kms-hsm": ["KMS/HSM key policy export", "signing operation receipt", "custody or audit-log root"],
    "tsa": ["RFC 3161 timestamp response", "TSA certificate chain", "timestamp verification receipt"],
    "cloud-object-lock": ["Object Lock retention export", "legal-hold report", "bucket/versioning policy evidence"],
    "provider-api": ["provider API response export", "request/response transcript", "provider-owned audit event"],
    "hosted-service": ["hosted service health or deployment export", "service audit root", "operational SLO/status evidence"],
    "identity-provider": ["identity-provider event export", "OIDC/session/lifecycle evidence", "RBAC or account-state report"],
    "regulator": ["regulator acknowledgement", "supervisor portal receipt", "conformity-assessment record"],
    "insurer": ["underwriter response", "premium or policy-system quote", "insurer API response export"],
    "standards-body": ["standards-body submission receipt", "working-group status record", "ballot or docket export"],
    "customer": ["customer acceptance artifact", "contract/payment/procurement evidence", "deployment or signoff record"],
    "other": ["issuer-signed authority artifact", "source-system export", "reviewable evidence file"],
}

@dataclass
class ExternalEvidenceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0
    fresh_evidence_count: int = 0
    stale_evidence_count: int = 0
    missing_freshness_count: int = 0
    covered_authority_kind_count: int = 0
    required_authority_kind_count: int = 0
    missing_authority_kind_count: int = 0


@dataclass
class RoadmapEvidenceChainVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    audit_entry_count: int = 0
    external_evidence_entry_count: int = 0
    external_evidence_collection_run_entry_count: int = 0
    complete_external_evidence_entry_count: int = 0
    fresh_external_evidence_entry_count: int = 0



@dataclass
class RoadmapEvidenceReportVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]



@dataclass
class RoadmapEvidenceBundleVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]

@dataclass
class ExternalEvidenceCollectionPlanVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceSourceMapVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    entry_count: int = 0


@dataclass
class ExternalEvidenceCollectionRunVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    collected_count: int = 0


@dataclass
class ExternalEvidenceGapReportVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceWorkPackageVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceOwnerPacketVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceOwnerPacketStatusVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceOwnerFulfillmentTemplateVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceOwnerFulfillmentReviewVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceOwnerFulfillmentClosureVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceReadinessVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceProductionReplacementPlanVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceSourceSnapshotVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


@dataclass
class ExternalEvidenceIntakeVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_external_evidence_manifest(
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    evidence: list[dict[str, Any]] | None = None,
    manifest_ref: str = "production-external-evidence",
    status: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root)
    requirements = _reference_attested_requirements(roadmap_audit)
    required_ids = [requirement["id"] for requirement in requirements]
    required_authority_kinds = {
        requirement["id"]: _allowed_authority_kinds_for_requirement(requirement)
        for requirement in requirements
    }
    evidence_items = [
        _build_evidence_item(root_path, item, required_ids, required_authority_kinds)
        for item in (evidence or [])
    ]
    summary = _summary(required_ids, evidence_items, required_authority_kinds, status=status)
    body = {
        "schema": EXTERNAL_EVIDENCE_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "manifest_ref": manifest_ref,
        "source_roadmap_audit": {
            "audit_id": roadmap_audit.get("audit_id"),
            "audit_hash": content_hash(roadmap_audit),
            "completion_position": roadmap_audit.get("completion_position"),
        },
        "required_external_requirements": [
            {
                "id": requirement["id"],
                "phase": requirement.get("phase"),
                "priority": requirement.get("priority"),
                "title": requirement.get("title"),
                "external_authority_required": requirement.get("external_authority_required", []),
                "allowed_authority_kinds": required_authority_kinds.get(requirement["id"], ["other"]),
            }
            for requirement in requirements
        ],
        "required_authority_evidence_units": _authority_evidence_units(requirements, required_authority_kinds, summary),
        "evidence": evidence_items,
        "summary": summary,
        "limitations": [
            "This manifest verifies supplied external evidence artifacts by hash; it does not fetch live provider state.",
            "A complete manifest requires evidence for every reference-attested roadmap requirement and every accepted authority kind for that requirement.",
            "Evidence quality still depends on the authority that issued each supplied artifact.",
        ],
    }
    return {**body, "manifest_id": content_hash(body)}


def verify_external_evidence_manifest(
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    require_complete: bool = False,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_source_snapshot_artifacts: bool = False,
    require_fresh_source_snapshot_artifacts: bool = False,
    now: str | None = None,
) -> ExternalEvidenceVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if require_fresh_source_snapshot_artifacts and not require_source_snapshot_artifacts:
        errors.append("source snapshot artifact freshness requires source snapshot artifact verification")
    root_path = Path(root)
    freshness_now = _freshness_reference(manifest, now, errors)

    if manifest.get("schema") != EXTERNAL_EVIDENCE_SCHEMA:
        errors.append(f"unsupported external evidence schema: {manifest.get('schema')}")
    if manifest.get("manifest_id") != content_hash(without_keys(manifest, "manifest_id")):
        errors.append("manifest_id does not match canonical manifest body")

    audit_result = verify_roadmap_audit(roadmap_audit, root=root_path)
    if not audit_result.ok:
        errors.extend(f"source roadmap audit: {error}" for error in audit_result.errors)
    expected_audit = {
        "audit_id": roadmap_audit.get("audit_id"),
        "audit_hash": content_hash(roadmap_audit),
        "completion_position": roadmap_audit.get("completion_position"),
    }
    if manifest.get("source_roadmap_audit") != expected_audit:
        errors.append("source_roadmap_audit does not match supplied roadmap audit")

    requirements = _reference_attested_requirements(roadmap_audit)
    required_ids = [requirement["id"] for requirement in requirements]
    required_set = set(required_ids)
    required_authority_kinds = {
        requirement["id"]: _allowed_authority_kinds_for_requirement(requirement)
        for requirement in requirements
    }
    declared_requirements = manifest.get("required_external_requirements", [])
    if not isinstance(declared_requirements, list):
        errors.append("required_external_requirements must be a list")
        declared_requirements = []
    declared_ids = [item.get("id") for item in declared_requirements if isinstance(item, dict)]
    if declared_ids != required_ids:
        errors.append("required_external_requirements do not match reference-attested roadmap requirements")
    expected_declared_requirements = [
        {
            "id": requirement["id"],
            "phase": requirement.get("phase"),
            "priority": requirement.get("priority"),
            "title": requirement.get("title"),
            "external_authority_required": requirement.get("external_authority_required", []),
            "allowed_authority_kinds": required_authority_kinds.get(requirement["id"], ["other"]),
        }
        for requirement in requirements
    ]
    if declared_requirements != expected_declared_requirements:
        errors.append("required_external_requirements authority-kind policy does not match reference-attested roadmap requirements")

    evidence = manifest.get("evidence", [])
    if not isinstance(evidence, list):
        errors.append("evidence must be a list")
        evidence = []
    covered_ids: set[str] = set()
    freshness_counts = {"fresh": 0, "stale": 0, "missing": 0}
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("external evidence item must be an object")
            continue
        requirement_id = str(item.get("requirement_id") or "")
        if requirement_id not in required_set:
            errors.append(f"external evidence requirement_id is not reference-attested: {requirement_id}")
        else:
            covered_ids.add(requirement_id)
        freshness_status = _verify_evidence_item(
            root_path,
            item,
            errors,
            warnings,
            now=freshness_now,
            require_fresh=require_fresh,
            require_live_source_uris=require_live_source_uris,
            allowed_authority_kinds=required_authority_kinds.get(requirement_id, []),
        )
        freshness_counts[freshness_status] += 1
        if require_source_snapshot_artifacts:
            _verify_evidence_item_source_snapshot_artifact(
                root_path,
                item,
                errors,
                warnings,
                require_fresh=require_fresh_source_snapshot_artifacts,
                now=now,
                label="external evidence",
            )

    expected_summary = _summary(required_ids, [item for item in evidence if isinstance(item, dict)], required_authority_kinds)
    if manifest.get("summary") != expected_summary:
        errors.append("summary does not match evidence coverage")
    expected_units = _authority_evidence_units(requirements, required_authority_kinds, expected_summary)
    if manifest.get("required_authority_evidence_units") != expected_units:
        errors.append("required_authority_evidence_units do not match authority-kind coverage policy")

    missing = [requirement_id for requirement_id in required_ids if requirement_id not in covered_ids]
    missing_authority_kinds = expected_summary.get("missing_authority_kinds_by_requirement", {})
    if missing:
        warnings.append("external evidence missing for: " + ", ".join(missing))
    if missing_authority_kinds:
        warnings.append(
            "external evidence authority kinds missing for: "
            + "; ".join(
                f"{requirement_id}: {', '.join(kinds)}"
                for requirement_id, kinds in missing_authority_kinds.items()
            )
        )
    if require_complete and missing:
        errors.append("external evidence manifest is incomplete")
    if require_complete and missing_authority_kinds:
        errors.append("external evidence authority-kind coverage is incomplete")

    return ExternalEvidenceVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=len(covered_ids),
        required_count=len(required_ids),
        fresh_evidence_count=freshness_counts["fresh"],
        stale_evidence_count=freshness_counts["stale"],
        missing_freshness_count=freshness_counts["missing"],
        covered_authority_kind_count=expected_summary.get("covered_authority_kind_count", 0),
        required_authority_kind_count=expected_summary.get("required_authority_kind_count", 0),
        missing_authority_kind_count=expected_summary.get("missing_authority_kind_count", 0),
    )



def build_external_evidence_collection_plan(
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    status_filter: str = "missing",
    generated_at: str | None = None,
) -> dict[str, Any]:
    if status_filter not in EXTERNAL_EVIDENCE_PLAN_STATUS_FILTERS:
        raise ValueError(f"unsupported external evidence plan status_filter: {status_filter}")
    result = verify_external_evidence_manifest(manifest, roadmap_audit, root=root)
    if not result.ok:
        raise ValueError("invalid source external evidence manifest: " + "; ".join(result.errors))
    units = manifest.get("required_authority_evidence_units", [])
    if not isinstance(units, list):
        raise ValueError("required_authority_evidence_units must be a list")
    tasks = [
        _authority_collection_task(unit)
        for unit in units
        if isinstance(unit, dict) and _collection_status_matches(unit, status_filter)
    ]
    body = {
        "schema": EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "status_filter": status_filter,
        "source_manifest": {
            "manifest_id": manifest.get("manifest_id"),
            "manifest_hash": content_hash(manifest),
            "manifest_ref": manifest.get("manifest_ref"),
            "status": manifest.get("summary", {}).get("status") if isinstance(manifest.get("summary"), dict) else None,
            "generated_at": manifest.get("generated_at"),
        },
        "source_roadmap_audit": manifest.get("source_roadmap_audit"),
        "summary": _collection_plan_summary(manifest, tasks),
        "tasks": tasks,
        "limitations": [
            "This plan assigns external authority evidence collection work; it does not satisfy any task by itself.",
            "A task is covered only after a matching evidence artifact is supplied to an external evidence manifest and verified.",
            "Freshness and issuer authority remain bounded by the supplied evidence artifact and manifest verification options.",
        ],
    }
    return {**body, "plan_id": content_hash(body)}


def verify_external_evidence_collection_plan(
    plan: dict[str, Any],
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
) -> ExternalEvidenceCollectionPlanVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if plan.get("schema") != EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA:
        errors.append(f"unsupported external evidence collection plan schema: {plan.get('schema')}")
    if plan.get("plan_id") != content_hash(without_keys(plan, "plan_id")):
        errors.append("plan_id does not match canonical collection plan body")

    manifest_result = verify_external_evidence_manifest(manifest, roadmap_audit, root=root)
    warnings.extend(manifest_result.warnings)
    if not manifest_result.ok:
        errors.extend(f"source manifest: {error}" for error in manifest_result.errors)

    status_filter = str(plan.get("status_filter") or "")
    if status_filter not in EXTERNAL_EVIDENCE_PLAN_STATUS_FILTERS:
        errors.append(f"unsupported external evidence plan status_filter: {status_filter}")

    if manifest_result.ok and status_filter in EXTERNAL_EVIDENCE_PLAN_STATUS_FILTERS:
        expected = build_external_evidence_collection_plan(
            manifest,
            roadmap_audit,
            root=root,
            status_filter=status_filter,
            generated_at=str(plan.get("generated_at") or ""),
        )
        if without_keys(plan, "plan_id") != without_keys(expected, "plan_id"):
            errors.append("collection plan body does not match source manifest and status filter")

    return ExternalEvidenceCollectionPlanVerification(ok=not errors, errors=errors, warnings=warnings)


def _source_map_path_segment(value: str) -> str:
    segment = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value.strip())
    segment = segment.strip("-._")
    return segment or "unknown"


def _source_map_join_path(base: str, requirement_id: str, authority_kind: str) -> str:
    normalized_base = str(base or "").replace("\\", "/").rstrip("/")
    if not normalized_base:
        normalized_base = "artifacts/external-evidence"
    return "/".join(
        [
            normalized_base,
            _source_map_path_segment(requirement_id),
            _source_map_path_segment(authority_kind) + ".json",
        ]
    )


def _source_map_is_placeholder_uri(source_uri: str) -> bool:
    normalized = str(source_uri or "").strip().lower()
    if not normalized:
        return True
    placeholder_markers = (
        "authority.example",
        "provider.example",
        "example.com",
        "example.net",
        "example.org",
        "<source-uri>",
    )
    return normalized.startswith("todo:") or any(marker in normalized for marker in placeholder_markers)


def _source_map_source_uri_counts(entries: list[dict[str, Any]]) -> dict[str, int]:
    placeholder_count = 0
    for entry in entries:
        if _source_map_is_placeholder_uri(str(entry.get("source_uri") or "")):
            placeholder_count += 1
    return {
        "placeholder_source_uri_count": placeholder_count,
        "live_source_uri_count": len(entries) - placeholder_count,
    }


def _resolve_source_map_snapshot_path(root: str | Path, snapshot_out: str) -> Path:
    if not snapshot_out:
        raise ValueError("snapshot_out is required")
    root_path = Path(root).resolve()
    target = Path(snapshot_out)
    if not target.is_absolute():
        target = root_path / target
    resolved = target.resolve()
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise ValueError(f"snapshot_out is outside root: {snapshot_out}") from exc
    return resolved


def _resolve_evidence_item_artifact_path(root: str | Path, artifact_path: str) -> Path:
    if not artifact_path:
        raise ValueError("path is required")
    if not _is_safe_relative_path(artifact_path):
        raise ValueError(f"path must be repository-relative: {artifact_path}")
    root_path = Path(root).resolve()
    resolved = (root_path / artifact_path).resolve()
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise ValueError(f"path is outside root: {artifact_path}") from exc
    return resolved


def _format_source_map_template(template: str, fields: dict[str, str], label: str) -> str:
    if not template:
        raise ValueError(f"external evidence source map {label} is required")
    try:
        return template.format(**fields)
    except KeyError as exc:
        raise ValueError(f"external evidence source map {label} references unknown field: {exc.args[0]}") from exc


def build_external_evidence_source_map_template(
    plan: dict[str, Any],
    *,
    status_filter: str = "missing",
    authority_kinds: list[str] | None = None,
    source_uri_template: str = "TODO://authority/{requirement_id}/{authority_kind}",
    description_template: str = "{authority_kind} evidence for {requirement_id}",
    source_file: str | None = None,
    retrieval_method: str | None = None,
    content_type: str | None = None,
    issuer: str | None = None,
    subject: str | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
    timeout_seconds: float | None = None,
    snapshot_dir: str = "artifacts/external-evidence-sources",
    intake_dir: str = "artifacts/external-evidence-intakes",
    limit: int | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if plan.get("schema") != EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA:
        raise ValueError(f"unsupported external evidence collection plan schema: {plan.get('schema')}")
    if plan.get("plan_id") != content_hash(without_keys(plan, "plan_id")):
        raise ValueError("external evidence collection plan_id does not match canonical body")
    if status_filter not in EXTERNAL_EVIDENCE_PLAN_STATUS_FILTERS:
        raise ValueError(f"unsupported external evidence source map status_filter: {status_filter}")
    authority_filter = list(authority_kinds or [])
    invalid_authorities = sorted(set(authority_filter) - AUTHORITY_KINDS)
    if invalid_authorities:
        raise ValueError(f"unsupported external evidence source map authority kind: {', '.join(invalid_authorities)}")
    if limit is not None and limit < 1:
        raise ValueError("external evidence source map limit must be positive")

    tasks = plan.get("tasks", [])
    if not isinstance(tasks, list):
        raise ValueError("external evidence collection plan tasks must be a list")
    selected_tasks = [
        task
        for task in tasks
        if isinstance(task, dict)
        and _collection_status_matches(task, status_filter)
        and (not authority_filter or str(task.get("authority_kind") or "") in authority_filter)
    ]
    if limit is not None:
        selected_tasks = selected_tasks[:limit]

    defaults: dict[str, Any] = {}
    for key, value in (
        ("source_file", source_file),
        ("retrieval_method", retrieval_method),
        ("content_type", content_type),
        ("issuer", issuer),
        ("subject", subject),
        ("issued_at", issued_at),
        ("expires_at", expires_at),
        ("timeout_seconds", timeout_seconds),
    ):
        if value is not None:
            defaults[key] = value

    entries: list[dict[str, Any]] = []
    for task in selected_tasks:
        fields = {
            "task_id": str(task.get("task_id") or ""),
            "task_ref": str(task.get("task_ref") or ""),
            "unit_id": str(task.get("unit_id") or ""),
            "unit_ref": str(task.get("unit_ref") or ""),
            "requirement_id": str(task.get("requirement_id") or ""),
            "authority_kind": str(task.get("authority_kind") or ""),
            "phase": str(task.get("phase") or ""),
            "priority": str(task.get("priority") or ""),
            "title": str(task.get("title") or ""),
        }
        entries.append(
            {
                "task": fields["unit_ref"],
                "task_ref": fields["task_ref"],
                "task_id": fields["task_id"],
                "unit_id": fields["unit_id"],
                "unit_ref": fields["unit_ref"],
                "requirement_id": fields["requirement_id"],
                "authority_kind": fields["authority_kind"],
                "title": fields["title"],
                "coverage_status": task.get("coverage_status"),
                "source_uri": _format_source_map_template(source_uri_template, fields, "source_uri_template"),
                "description": _format_source_map_template(description_template, fields, "description_template"),
                "snapshot_out": _source_map_join_path(snapshot_dir, fields["requirement_id"], fields["authority_kind"]),
                "intake_out": _source_map_join_path(intake_dir, fields["requirement_id"], fields["authority_kind"]),
                "owner_hint": task.get("owner_hint"),
                "suggested_evidence_sources": task.get("suggested_evidence_sources", []),
                "external_authority_required": task.get("external_authority_required", []),
            }
        )

    source_uri_counts = _source_map_source_uri_counts(entries)
    body = {
        "schema": EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "source_plan": _collection_plan_source_record(plan),
        "summary": {
            "status_filter": status_filter,
            "authority_kinds": authority_filter,
            "entry_count": len(entries),
            "source_plan_task_count": len(tasks),
            "snapshot_dir": snapshot_dir,
            "intake_dir": intake_dir,
            **source_uri_counts,
        },
        "defaults": defaults,
        "entries": entries,
        "limitations": [
            "This source map is an operator collection template; it does not prove external authority coverage until external-evidence-collect-batch creates verified source snapshots and intake receipts.",
            "Placeholder source URIs, issuer fields, or freshness windows must be replaced with real authority-owned values before production use.",
            "Each entry remains bound to the source collection plan through task IDs, unit refs, and generated snapshot/intake paths.",
        ],
    }
    return {**body, "source_map_id": content_hash(body)}


def verify_external_evidence_source_map_template(
    source_map: dict[str, Any],
    plan: dict[str, Any],
    *,
    root: str | Path = ".",
    require_live_source_uris: bool = False,
    require_source_snapshots: bool = False,
    require_fresh_source_snapshots: bool = False,
    now: str | None = None,
) -> ExternalEvidenceSourceMapVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if require_fresh_source_snapshots and not require_source_snapshots:
        errors.append("source snapshot freshness requires --require-source-snapshots")

    if source_map.get("schema") != EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA:
        errors.append(f"unsupported external evidence source map schema: {source_map.get('schema')}")
    if source_map.get("source_map_id") != content_hash(without_keys(source_map, "source_map_id")):
        errors.append("source_map_id does not match canonical source map body")
    if plan.get("schema") != EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA:
        errors.append(f"unsupported external evidence collection plan schema: {plan.get('schema')}")
    if plan.get("plan_id") != content_hash(without_keys(plan, "plan_id")):
        errors.append("source collection plan_id does not match canonical body")

    expected_source_plan = _collection_plan_source_record(plan) if plan.get("schema") == EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA else None
    if expected_source_plan is not None and source_map.get("source_plan") != expected_source_plan:
        errors.append("source map source_plan does not match supplied collection plan")

    summary = source_map.get("summary")
    if not isinstance(summary, dict):
        errors.append("source map summary must be an object")
        summary = {}
    status_filter = str(summary.get("status_filter") or "")
    if status_filter not in EXTERNAL_EVIDENCE_PLAN_STATUS_FILTERS:
        errors.append(f"unsupported source map status_filter: {status_filter}")
    authority_kinds = summary.get("authority_kinds", [])
    if not isinstance(authority_kinds, list) or any(not isinstance(value, str) for value in authority_kinds):
        errors.append("source map authority_kinds must be a list of strings")
        authority_kinds = []
    invalid_authorities = sorted(set(authority_kinds) - AUTHORITY_KINDS)
    if invalid_authorities:
        errors.append(f"unsupported source map authority kind: {', '.join(invalid_authorities)}")
    snapshot_dir = str(summary.get("snapshot_dir") or "artifacts/external-evidence-sources")
    intake_dir = str(summary.get("intake_dir") or "artifacts/external-evidence-intakes")

    tasks = plan.get("tasks", [])
    if not isinstance(tasks, list):
        errors.append("source collection plan tasks must be a list")
        tasks = []
    task_by_ref = {str(task.get("unit_ref") or ""): task for task in tasks if isinstance(task, dict)}
    task_by_task_ref = {str(task.get("task_ref") or ""): task for task in tasks if isinstance(task, dict)}

    entries = source_map.get("entries")
    if not isinstance(entries, list):
        errors.append("source map entries must be a list")
        entries = []
    if summary.get("entry_count") != len(entries):
        errors.append("source map summary entry_count does not match entries length")
    if summary.get("source_plan_task_count") != len(tasks):
        errors.append("source map summary source_plan_task_count does not match supplied plan")
    source_uri_counts = _source_map_source_uri_counts([entry for entry in entries if isinstance(entry, dict)])
    for key, expected_count in source_uri_counts.items():
        if summary.get(key) != expected_count:
            errors.append(f"source map summary {key} does not match entries")
    if source_uri_counts["placeholder_source_uri_count"]:
        placeholder_message = f"source map contains {source_uri_counts['placeholder_source_uri_count']} placeholder source_uri values"
        warnings.append(placeholder_message)
        if require_live_source_uris:
            errors.append(placeholder_message + " but live source URIs are required")

    seen_tasks: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"source map entry {index} must be an object")
            continue
        task_ref = str(entry.get("task") or "")
        full_task_ref = str(entry.get("task_ref") or "")
        task = task_by_ref.get(task_ref) or task_by_task_ref.get(full_task_ref)
        if task is None:
            errors.append(f"source map entry {index} does not match a collection-plan task: {task_ref or full_task_ref}")
            continue
        canonical_ref = str(task.get("unit_ref") or "")
        if canonical_ref in seen_tasks:
            errors.append(f"source map entry duplicates task: {canonical_ref}")
        seen_tasks.add(canonical_ref)
        if status_filter in EXTERNAL_EVIDENCE_PLAN_STATUS_FILTERS and not _collection_status_matches(task, status_filter):
            errors.append(f"source map entry {canonical_ref} does not match status_filter {status_filter}")
        authority_kind = str(task.get("authority_kind") or "")
        if authority_kinds and authority_kind not in authority_kinds:
            errors.append(f"source map entry {canonical_ref} does not match authority_kinds filter")
        for key in ("task_id", "unit_id", "unit_ref", "requirement_id", "authority_kind", "title"):
            if str(entry.get(key) or "") != str(task.get(key) or ""):
                errors.append(f"source map entry {canonical_ref} has mismatched {key}")
        if str(entry.get("task_ref") or "") != str(task.get("task_ref") or ""):
            errors.append(f"source map entry {canonical_ref} has mismatched task_ref")
        if str(entry.get("coverage_status") or "") != str(task.get("coverage_status") or ""):
            errors.append(f"source map entry {canonical_ref} has mismatched coverage_status")
        if str(entry.get("snapshot_out") or "") != _source_map_join_path(snapshot_dir, str(task.get("requirement_id") or ""), authority_kind):
            errors.append(f"source map entry {canonical_ref} has mismatched snapshot_out")
        if str(entry.get("intake_out") or "") != _source_map_join_path(intake_dir, str(task.get("requirement_id") or ""), authority_kind):
            errors.append(f"source map entry {canonical_ref} has mismatched intake_out")
        if not str(entry.get("source_uri") or ""):
            errors.append(f"source map entry {canonical_ref} is missing source_uri")
        if not str(entry.get("description") or ""):
            errors.append(f"source map entry {canonical_ref} is missing description")
        if require_source_snapshots:
            snapshot_out = str(entry.get("snapshot_out") or "")
            try:
                snapshot_path = _resolve_source_map_snapshot_path(root, snapshot_out)
            except ValueError as exc:
                errors.append(f"source map entry {canonical_ref} {exc}")
                continue
            if not snapshot_path.is_file():
                errors.append(f"source map entry {canonical_ref} snapshot_out does not exist: {snapshot_out}")
                continue
            try:
                snapshot = load_external_evidence_source_snapshot(snapshot_path)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                errors.append(f"source map entry {canonical_ref} snapshot_out is not a readable source snapshot: {exc}")
                continue
            snapshot_result = verify_external_evidence_source_snapshot(
                snapshot,
                require_fresh=require_fresh_source_snapshots,
                now=now,
            )
            warnings.extend(f"source map entry {canonical_ref} snapshot: {warning}" for warning in snapshot_result.warnings)
            if not snapshot_result.ok:
                errors.extend(f"source map entry {canonical_ref} snapshot: {error}" for error in snapshot_result.errors)
            if str(snapshot.get("source_uri") or "") != str(entry.get("source_uri") or ""):
                errors.append(f"source map entry {canonical_ref} snapshot source_uri does not match source_uri")
            status_code = snapshot.get("status_code")
            if isinstance(status_code, int) and (status_code < 200 or status_code >= 400):
                errors.append(f"source map entry {canonical_ref} snapshot status_code is not successful: {status_code}")

    if status_filter in EXTERNAL_EVIDENCE_PLAN_STATUS_FILTERS:
        eligible = [
            task
            for task in tasks
            if isinstance(task, dict)
            and _collection_status_matches(task, status_filter)
            and (not authority_kinds or str(task.get("authority_kind") or "") in authority_kinds)
        ]
        if len(entries) < len(eligible):
            warnings.append("source map contains a subset of matching collection-plan tasks")
        if len(entries) > len(eligible):
            errors.append("source map contains more entries than matching collection-plan tasks")

    return ExternalEvidenceSourceMapVerification(ok=not errors, errors=errors, warnings=warnings, entry_count=len(entries))


def parse_source_map_fulfillment_arg(value: str) -> dict[str, Any]:
    parts = [part.strip() for part in value.split(";")]
    if len(parts) < 2 or not parts[0]:
        raise ValueError("source map fulfillment must be task;key=value[;key=value...]")
    fulfillment: dict[str, Any] = {"task": parts[0]}
    for token in parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("source map fulfillment metadata must be key=value")
        key, raw_value = [part.strip() for part in token.split("=", 1)]
        if key not in SOURCE_MAP_FULFILLMENT_FIELDS:
            raise ValueError(f"unsupported source map fulfillment key: {key}")
        if key == "timeout_seconds":
            try:
                timeout = float(raw_value)
            except ValueError as exc:
                raise ValueError("source map fulfillment timeout_seconds must be numeric") from exc
            if timeout <= 0:
                raise ValueError("source map fulfillment timeout_seconds must be positive")
            fulfillment[key] = timeout
        else:
            if key in {"source_uri", "description"} and not raw_value:
                raise ValueError(f"source map fulfillment {key} is required")
            fulfillment[key] = raw_value
    if len(fulfillment) == 1:
        raise ValueError("source map fulfillment must include at least one metadata key")
    return fulfillment


def _source_map_fulfillment_task_ref(fulfillment: dict[str, Any]) -> str:
    for key in SOURCE_MAP_FULFILLMENT_TASK_KEYS:
        value = str(fulfillment.get(key) or "").strip()
        if value:
            return value
    return ""


def _source_map_entry_refs(entry: dict[str, Any]) -> set[str]:
    return {
        value
        for key in SOURCE_MAP_FULFILLMENT_TASK_KEYS
        for value in [str(entry.get(key) or "").strip()]
        if value
    }


def fulfill_external_evidence_source_map(
    source_map: dict[str, Any],
    fulfillments: list[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if source_map.get("schema") != EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA:
        raise ValueError(f"unsupported external evidence source map schema: {source_map.get('schema')}")
    if source_map.get("source_map_id") != content_hash(without_keys(source_map, "source_map_id")):
        raise ValueError("external evidence source map_id does not match canonical body")
    body = json.loads(json.dumps(without_keys(source_map, "source_map_id"), sort_keys=True))
    entries = body.get("entries")
    if not isinstance(entries, list):
        raise ValueError("external evidence source map entries must be a list")
    summary = body.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("external evidence source map summary must be an object")
    defaults = body.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ValueError("external evidence source map defaults must be an object")
    if not fulfillments and entries:
        raise ValueError("at least one source map fulfillment is required")

    fulfilled_refs: set[str] = set()
    for index, fulfillment in enumerate(fulfillments):
        if not isinstance(fulfillment, dict):
            raise ValueError(f"source map fulfillment {index} must be an object")
        task_ref = _source_map_fulfillment_task_ref(fulfillment)
        if not task_ref:
            raise ValueError(f"source map fulfillment {index} is missing task reference")
        matches = [entry for entry in entries if isinstance(entry, dict) and task_ref in _source_map_entry_refs(entry)]
        if not matches:
            raise ValueError(f"source map fulfillment task not found: {task_ref}")
        if len(matches) > 1:
            raise ValueError(f"source map fulfillment task is ambiguous: {task_ref}")
        entry = matches[0]
        canonical_ref = str(entry.get("unit_ref") or entry.get("task") or task_ref)
        if canonical_ref in fulfilled_refs:
            raise ValueError(f"duplicate source map fulfillment for task: {canonical_ref}")
        fulfilled_refs.add(canonical_ref)
        for key, value in fulfillment.items():
            if key in SOURCE_MAP_FULFILLMENT_TASK_KEYS:
                continue
            if key not in SOURCE_MAP_FULFILLMENT_FIELDS:
                raise ValueError(f"unsupported source map fulfillment key: {key}")
            if key == "timeout_seconds":
                try:
                    timeout = float(value)
                except (TypeError, ValueError) as exc:
                    raise ValueError("source map fulfillment timeout_seconds must be numeric") from exc
                if timeout <= 0:
                    raise ValueError("source map fulfillment timeout_seconds must be positive")
                entry[key] = timeout
            else:
                text = str(value or "").strip()
                if key in {"source_uri", "description"} and not text:
                    raise ValueError(f"source map fulfillment {key} is required")
                entry[key] = text

    summary["entry_count"] = len(entries)
    summary.update(_source_map_source_uri_counts([entry for entry in entries if isinstance(entry, dict)]))
    body["generated_at"] = generated_at or utc_now()
    return {**body, "source_map_id": content_hash(body)}


def _gap_report_source_record(document: dict[str, Any], id_key: str, hash_key: str) -> dict[str, Any]:
    return {
        id_key: document.get(id_key),
        hash_key: content_hash(document),
        "schema": document.get("schema"),
        "generated_at": document.get("generated_at"),
    }


def _gap_report_group_counts(gaps: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for gap in gaps:
        value = str(gap.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return {name: counts[name] for name in sorted(counts)}


def _source_map_effective_value(entry: dict[str, Any], defaults: dict[str, Any], key: str) -> Any:
    return entry[key] if key in entry else defaults.get(key)


def build_external_evidence_gap_report(
    manifest: dict[str, Any],
    plan: dict[str, Any],
    source_map: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_source_snapshots: bool = False,
    require_fresh_source_snapshots: bool = False,
    now: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    manifest_result = verify_external_evidence_manifest(
        manifest,
        roadmap_audit,
        root=root,
        require_fresh=require_fresh,
        now=now,
    )
    plan_result = verify_external_evidence_collection_plan(plan, manifest, roadmap_audit, root=root)
    source_map_result = verify_external_evidence_source_map_template(
        source_map,
        plan,
        root=root,
        require_live_source_uris=require_live_source_uris,
        require_source_snapshots=require_source_snapshots,
        require_fresh_source_snapshots=require_fresh_source_snapshots,
        now=now,
    )
    if not manifest_result.ok:
        raise ValueError("external evidence manifest is not valid for gap report: " + "; ".join(manifest_result.errors))
    if not plan_result.ok:
        raise ValueError("external evidence collection plan is not valid for gap report: " + "; ".join(plan_result.errors))
    if not source_map_result.ok:
        raise ValueError("external evidence source map is not valid for gap report: " + "; ".join(source_map_result.errors))

    defaults = source_map.get("defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    gaps: list[dict[str, Any]] = []
    optional_collection_fields = (
        "source_file",
        "retrieval_method",
        "content_type",
        "issuer",
        "subject",
        "issued_at",
        "expires_at",
        "timeout_seconds",
    )
    for entry in source_map.get("entries", []):
        if not isinstance(entry, dict):
            continue
        gap = {
            "task": entry.get("task"),
            "task_ref": entry.get("task_ref"),
            "task_id": entry.get("task_id"),
            "unit_id": entry.get("unit_id"),
            "unit_ref": entry.get("unit_ref"),
            "requirement_id": entry.get("requirement_id"),
            "authority_kind": entry.get("authority_kind"),
            "title": entry.get("title"),
            "owner_hint": entry.get("owner_hint"),
            "source_uri": _source_map_effective_value(entry, defaults, "source_uri"),
            "description": _source_map_effective_value(entry, defaults, "description"),
            "snapshot_out": _source_map_effective_value(entry, defaults, "snapshot_out"),
            "intake_out": _source_map_effective_value(entry, defaults, "intake_out"),
            "suggested_evidence_sources": entry.get("suggested_evidence_sources", []),
            "external_authority_required": entry.get("external_authority_required", []),
        }
        for key in optional_collection_fields:
            value = _source_map_effective_value(entry, defaults, key)
            if value is not None:
                gap[key] = value
        gaps.append(gap)

    manifest_summary = manifest.get("summary", {}) if isinstance(manifest.get("summary"), dict) else {}
    plan_summary = plan.get("summary", {}) if isinstance(plan.get("summary"), dict) else {}
    source_map_summary = source_map.get("summary", {}) if isinstance(source_map.get("summary"), dict) else {}
    body = {
        "schema": EXTERNAL_EVIDENCE_GAP_REPORT_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "verification_options": {
            "require_fresh": require_fresh,
            "require_live_source_uris": require_live_source_uris,
            "require_source_snapshots": require_source_snapshots,
            "require_fresh_source_snapshots": require_fresh_source_snapshots,
            "now": now,
        },
        "sources": {
            "manifest": _gap_report_source_record(manifest, "manifest_id", "manifest_hash"),
            "collection_plan": _gap_report_source_record(plan, "plan_id", "plan_hash"),
            "source_map": _gap_report_source_record(source_map, "source_map_id", "source_map_hash"),
            "roadmap_audit": _gap_report_source_record(roadmap_audit, "audit_id", "audit_hash"),
        },
        "summary": {
            "status": manifest_summary.get("status"),
            "covered_requirement_count": manifest_summary.get("covered_requirement_count", 0),
            "required_requirement_count": manifest_summary.get("required_requirement_count", 0),
            "missing_requirement_count": manifest_summary.get("missing_requirement_count", 0),
            "covered_authority_kind_count": manifest_summary.get("covered_authority_kind_count", 0),
            "required_authority_kind_count": manifest_summary.get("required_authority_kind_count", 0),
            "missing_authority_kind_count": manifest_summary.get("missing_authority_kind_count", 0),
            "remaining_task_count": plan_summary.get("selected_task_count", len(gaps)),
            "remaining_missing_task_count": plan_summary.get("selected_missing_task_count", len(gaps)),
            "source_map_entry_count": source_map_summary.get("entry_count", len(gaps)),
            "placeholder_source_uri_count": source_map_summary.get("placeholder_source_uri_count", 0),
            "live_source_uri_count": source_map_summary.get("live_source_uri_count", 0),
            "gap_count_by_authority_kind": _gap_report_group_counts(gaps, "authority_kind"),
            "gap_count_by_requirement": _gap_report_group_counts(gaps, "requirement_id"),
        },
        "covered_authority_kinds_by_requirement": manifest_summary.get("covered_authority_kinds_by_requirement", {}),
        "missing_authority_kinds_by_requirement": manifest_summary.get("missing_authority_kinds_by_requirement", {}),
        "gaps": gaps,
        "verification": {
            "manifest_warnings": manifest_result.warnings,
            "plan_warnings": plan_result.warnings,
            "source_map_warnings": source_map_result.warnings,
        },
        "limitations": [
            "This gap report verifies the retained manifest, remaining collection plan, and source-map worklist; it does not satisfy missing external authority evidence.",
            "A gap is closed only by collecting a matching authority artifact, verifying its source snapshot and intake receipt, then rebuilding the external evidence manifest.",
            "Live authority access, issuer quality, and production status remain outside this report unless supplied as external evidence artifacts.",
        ],
    }
    return {**body, "gap_report_id": content_hash(body)}


def verify_external_evidence_gap_report(
    report: dict[str, Any],
    manifest: dict[str, Any],
    plan: dict[str, Any],
    source_map: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_source_snapshots: bool = False,
    require_fresh_source_snapshots: bool = False,
    now: str | None = None,
) -> ExternalEvidenceGapReportVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if report.get("schema") != EXTERNAL_EVIDENCE_GAP_REPORT_SCHEMA:
        errors.append(f"unsupported external evidence gap report schema: {report.get('schema')}")
    if report.get("gap_report_id") != content_hash(without_keys(report, "gap_report_id")):
        errors.append("gap_report_id does not match canonical gap report body")
    expected_options = {
        "require_fresh": require_fresh,
        "require_live_source_uris": require_live_source_uris,
        "require_source_snapshots": require_source_snapshots,
        "require_fresh_source_snapshots": require_fresh_source_snapshots,
        "now": now,
    }
    if report.get("verification_options") != expected_options:
        errors.append("verification_options do not match verifier options")

    try:
        expected = build_external_evidence_gap_report(
            manifest,
            plan,
            source_map,
            roadmap_audit,
            root=root,
            require_fresh=require_fresh,
            require_live_source_uris=require_live_source_uris,
            require_source_snapshots=require_source_snapshots,
            require_fresh_source_snapshots=require_fresh_source_snapshots,
            now=now,
            generated_at=str(report.get("generated_at") or ""),
        )
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if without_keys(report, "gap_report_id") != without_keys(expected, "gap_report_id"):
            errors.append("gap report body does not match supplied manifest, plan, source map, and roadmap audit")
        warnings.extend(expected.get("verification", {}).get("manifest_warnings", []))
        warnings.extend(expected.get("verification", {}).get("plan_warnings", []))
        warnings.extend(expected.get("verification", {}).get("source_map_warnings", []))

    return ExternalEvidenceGapReportVerification(ok=not errors, errors=errors, warnings=warnings)

def _external_evidence_work_package_gap_options(gap_report: dict[str, Any]) -> dict[str, Any]:
    options = gap_report.get("verification_options", {})
    if not isinstance(options, dict):
        options = {}
    return {
        "require_fresh": bool(options.get("require_fresh")),
        "require_live_source_uris": bool(options.get("require_live_source_uris")),
        "require_source_snapshots": bool(options.get("require_source_snapshots")),
        "require_fresh_source_snapshots": bool(options.get("require_fresh_source_snapshots")),
        "now": options.get("now"),
    }


def _external_evidence_work_package_command_context(command_context: dict[str, Any] | None) -> dict[str, str]:
    defaults = {
        "python": "python",
        "module": "trustai",
        "root": ".",
        "manifest_path": "<external-evidence-manifest.json>",
        "plan_path": "<external-evidence-plan.json>",
        "source_map_path": "<external-evidence-source-map.json>",
        "roadmap_audit_path": "<roadmap-audit.json>",
        "intake_dir": "artifacts/external-evidence-intakes",
        "collection_run_out": "artifacts/external-evidence-collection-run.json",
        "rebuilt_manifest_out": "artifacts/external-evidence-manifest-from-intakes.json",
    }
    supplied = command_context if isinstance(command_context, dict) else {}
    for key in list(defaults):
        value = supplied.get(key)
        if value is not None and str(value):
            defaults[key] = str(value)
    return defaults


def _external_evidence_work_package_command(args: list[str]) -> str:
    return " ".join(shlex.quote(str(arg)) for arg in args)


def _external_evidence_work_package_append_optional(args: list[str], flag: str, value: Any) -> None:
    if value is not None and str(value):
        args.extend([flag, str(value)])


def _external_evidence_work_package_collect_args(task: dict[str, Any], context: dict[str, str]) -> list[str]:
    args = [
        context["python"],
        "-m",
        context["module"],
        "external-evidence-collect",
        context["plan_path"],
        context["manifest_path"],
        context["roadmap_audit_path"],
        str(task.get("source_uri") or "<source-uri>"),
        "--root",
        context["root"],
        "--task",
        str(task.get("unit_ref") or task.get("task_ref") or task.get("task_id") or ""),
        "--description",
        str(task.get("description") or ""),
        "--snapshot-out",
        str(task.get("snapshot_out") or ""),
        "--intake-out",
        str(task.get("intake_out") or ""),
    ]
    for key, flag in (
        ("source_file", "--source-file"),
        ("retrieval_method", "--retrieval-method"),
        ("content_type", "--content-type"),
        ("issuer", "--issuer"),
        ("subject", "--subject"),
        ("issued_at", "--issued-at"),
        ("expires_at", "--expires-at"),
        ("timeout_seconds", "--timeout-seconds"),
    ):
        _external_evidence_work_package_append_optional(args, flag, task.get(key))
    return args


def _external_evidence_work_package_verify_intake_args(task: dict[str, Any], context: dict[str, str]) -> list[str]:
    return [
        context["python"],
        "-m",
        context["module"],
        "external-evidence-intake-verify",
        str(task.get("intake_out") or "<intake.json>"),
        context["plan_path"],
        context["manifest_path"],
        context["roadmap_audit_path"],
        "--root",
        context["root"],
    ]


def _external_evidence_work_package_collect_batch_args(context: dict[str, str]) -> list[str]:
    return [
        context["python"],
        "-m",
        context["module"],
        "external-evidence-collect-batch",
        context["plan_path"],
        context["manifest_path"],
        context["roadmap_audit_path"],
        context["source_map_path"],
        "--root",
        context["root"],
        "--out",
        context["collection_run_out"],
    ]


def _external_evidence_work_package_rebuild_manifest_args(context: dict[str, str]) -> list[str]:
    return [
        context["python"],
        "-m",
        context["module"],
        "external-evidence-manifest-from-intakes",
        context["plan_path"],
        context["manifest_path"],
        context["roadmap_audit_path"],
        "--root",
        context["root"],
        "--intake-dir",
        context["intake_dir"],
        "--out",
        context["rebuilt_manifest_out"],
    ]


def _external_evidence_work_package_next_actions(task: dict[str, Any]) -> list[str]:
    actions = []
    if _source_map_is_placeholder_uri(str(task.get("source_uri") or "")):
        actions.append("Replace the placeholder source_uri with an authority-owned source export URI before collection.")
    missing_metadata = [field for field in ("issuer", "subject", "issued_at", "expires_at") if not task.get(field)]
    if missing_metadata:
        actions.append("Fill authority metadata before strict verification: " + ", ".join(missing_metadata) + ".")
    actions.extend(
        [
            "Run the collect command to create a source snapshot and intake receipt for this task.",
            "Verify the generated intake receipt before rebuilding the external evidence manifest.",
            "Rebuild and verify the external evidence manifest after all assigned intakes are collected.",
        ]
    )
    return actions


def _external_evidence_work_package_task_record(
    gap: dict[str, Any],
    plan_task: dict[str, Any],
    context: dict[str, str],
) -> dict[str, Any]:
    task = {
        "task_id": plan_task.get("task_id") or gap.get("task_id"),
        "task_ref": plan_task.get("task_ref") or gap.get("task_ref"),
        "unit_id": plan_task.get("unit_id") or gap.get("unit_id"),
        "unit_ref": plan_task.get("unit_ref") or gap.get("unit_ref"),
        "requirement_id": plan_task.get("requirement_id") or gap.get("requirement_id"),
        "phase": plan_task.get("phase") or gap.get("phase"),
        "priority": plan_task.get("priority") or gap.get("priority"),
        "title": plan_task.get("title") or gap.get("title"),
        "authority_kind": plan_task.get("authority_kind") or gap.get("authority_kind"),
        "coverage_status": plan_task.get("coverage_status") or gap.get("coverage_status"),
        "owner_hint": plan_task.get("owner_hint") or gap.get("owner_hint"),
        "source_uri": gap.get("source_uri"),
        "source_uri_status": "placeholder" if _source_map_is_placeholder_uri(str(gap.get("source_uri") or "")) else "live",
        "description": gap.get("description"),
        "snapshot_out": gap.get("snapshot_out"),
        "intake_out": gap.get("intake_out"),
        "suggested_artifact_path": plan_task.get("suggested_artifact_path"),
        "evidence_argument_template": plan_task.get("evidence_argument_template"),
        "suggested_evidence_sources": plan_task.get("suggested_evidence_sources", []),
        "acceptance_criteria": plan_task.get("acceptance_criteria", []),
        "external_authority_required": plan_task.get("external_authority_required", []),
    }
    for key in (
        "source_file",
        "retrieval_method",
        "content_type",
        "issuer",
        "subject",
        "issued_at",
        "expires_at",
        "timeout_seconds",
    ):
        if key in gap:
            task[key] = gap[key]
    collect_args = _external_evidence_work_package_collect_args(task, context)
    verify_args = _external_evidence_work_package_verify_intake_args(task, context)
    task["commands"] = {
        "collect_args": collect_args,
        "collect_command": _external_evidence_work_package_command(collect_args),
        "verify_intake_args": verify_args,
        "verify_intake_command": _external_evidence_work_package_command(verify_args),
    }
    task["next_actions"] = _external_evidence_work_package_next_actions(task)
    return task


def _authority_kind_sort_index(authority_kind: str) -> int:
    try:
        return AUTHORITY_KIND_ORDER.index(authority_kind)
    except ValueError:
        return len(AUTHORITY_KIND_ORDER)


def _external_evidence_work_package_task_sort_key(task: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(task.get("phase") or ""),
        str(task.get("priority") or ""),
        _authority_kind_sort_index(str(task.get("authority_kind") or "")),
        str(task.get("requirement_id") or ""),
        str(task.get("unit_ref") or ""),
    )


def _external_evidence_work_package_values(tasks: list[dict[str, Any]], key: str) -> list[str]:
    return sorted({str(task.get(key) or "unknown") for task in tasks})


def build_external_evidence_work_package(
    gap_report: dict[str, Any],
    manifest: dict[str, Any],
    plan: dict[str, Any],
    source_map: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    group_by: str = "owner_hint",
    command_context: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if group_by not in EXTERNAL_EVIDENCE_WORK_PACKAGE_GROUP_BY:
        raise ValueError(f"unsupported external evidence work package group_by: {group_by}")
    gap_options = _external_evidence_work_package_gap_options(gap_report)
    gap_result = verify_external_evidence_gap_report(
        gap_report,
        manifest,
        plan,
        source_map,
        roadmap_audit,
        root=root,
        **gap_options,
    )
    if not gap_result.ok:
        raise ValueError("external evidence gap report is not valid for work packages: " + "; ".join(gap_result.errors))

    context = _external_evidence_work_package_command_context(command_context)
    gaps = gap_report.get("gaps", [])
    if not isinstance(gaps, list):
        raise ValueError("external evidence gap report gaps must be a list")
    task_records: list[dict[str, Any]] = []
    for index, gap in enumerate(gaps):
        if not isinstance(gap, dict):
            raise ValueError(f"external evidence gap {index} must be an object")
        plan_task = (
            _find_collection_task(plan, str(gap.get("unit_ref") or ""))
            or _find_collection_task(plan, str(gap.get("task_ref") or ""))
            or _find_collection_task(plan, str(gap.get("task_id") or ""))
        )
        if plan_task is None:
            raise ValueError(f"external evidence gap does not match collection plan task: {gap.get('unit_ref') or gap.get('task_ref')}")
        task_records.append(_external_evidence_work_package_task_record(gap, plan_task, context))
    task_records.sort(key=_external_evidence_work_package_task_sort_key)

    grouped: dict[str, list[dict[str, Any]]] = {}
    for task in task_records:
        group_key = str(task.get(group_by) or "unknown")
        grouped.setdefault(group_key, []).append(task)

    collect_batch_args = _external_evidence_work_package_collect_batch_args(context)
    rebuild_manifest_args = _external_evidence_work_package_rebuild_manifest_args(context)
    packages = []
    for group_key in sorted(grouped):
        package_tasks = grouped[group_key]
        source_uri_counts = _source_map_source_uri_counts(package_tasks)
        package_body = {
            "package_ref": f"{group_by}:{_source_map_path_segment(group_key)}",
            "group_by": group_by,
            "group_key": group_key,
            group_by: group_key,
            "task_count": len(package_tasks),
            "missing_task_count": sum(1 for task in package_tasks if task.get("coverage_status") == "missing"),
            "covered_task_count": sum(1 for task in package_tasks if task.get("coverage_status") == "covered"),
            "placeholder_source_uri_count": source_uri_counts["placeholder_source_uri_count"],
            "live_source_uri_count": source_uri_counts["live_source_uri_count"],
            "authority_kinds": _external_evidence_work_package_values(package_tasks, "authority_kind"),
            "requirement_ids": _external_evidence_work_package_values(package_tasks, "requirement_id"),
            "phases": _external_evidence_work_package_values(package_tasks, "phase"),
            "priorities": _external_evidence_work_package_values(package_tasks, "priority"),
            "commands": {
                "collect_batch_args": collect_batch_args,
                "collect_batch_command": _external_evidence_work_package_command(collect_batch_args),
                "rebuild_manifest_args": rebuild_manifest_args,
                "rebuild_manifest_command": _external_evidence_work_package_command(rebuild_manifest_args),
            },
            "tasks": package_tasks,
        }
        packages.append({**package_body, "package_id": content_hash(package_body)})

    source_uri_counts = _source_map_source_uri_counts(task_records)
    body = {
        "schema": EXTERNAL_EVIDENCE_WORK_PACKAGE_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "group_by": group_by,
        "command_context": context,
        "sources": {
            "gap_report": _gap_report_source_record(gap_report, "gap_report_id", "gap_report_hash"),
            "manifest": _gap_report_source_record(manifest, "manifest_id", "manifest_hash"),
            "collection_plan": _gap_report_source_record(plan, "plan_id", "plan_hash"),
            "source_map": _gap_report_source_record(source_map, "source_map_id", "source_map_hash"),
            "roadmap_audit": _gap_report_source_record(roadmap_audit, "audit_id", "audit_hash"),
        },
        "summary": {
            "source_status": gap_report.get("summary", {}).get("status") if isinstance(gap_report.get("summary"), dict) else None,
            "package_count": len(packages),
            "task_count": len(task_records),
            "missing_task_count": sum(1 for task in task_records if task.get("coverage_status") == "missing"),
            "covered_task_count": sum(1 for task in task_records if task.get("coverage_status") == "covered"),
            "placeholder_source_uri_count": source_uri_counts["placeholder_source_uri_count"],
            "live_source_uri_count": source_uri_counts["live_source_uri_count"],
            "task_count_by_owner_hint": _gap_report_group_counts(task_records, "owner_hint"),
            "task_count_by_authority_kind": _gap_report_group_counts(task_records, "authority_kind"),
            "task_count_by_phase": _gap_report_group_counts(task_records, "phase"),
            "task_count_by_priority": _gap_report_group_counts(task_records, "priority"),
            "task_count_by_requirement": _gap_report_group_counts(task_records, "requirement_id"),
            "task_count_by_package": {package["package_ref"]: package["task_count"] for package in packages},
        },
        "packages": packages,
        "limitations": [
            "This work package is an assignment and command artifact; it does not satisfy missing external authority evidence by itself.",
            "Placeholder source URIs and missing authority metadata must be replaced with authority-owned values before strict production collection.",
            "A task is closed only after the resulting source snapshot, intake receipt, rebuilt manifest, and evidence chain entry verify successfully.",
        ],
    }
    return {**body, "work_package_id": content_hash(body)}


def verify_external_evidence_work_package(
    work_package: dict[str, Any],
    gap_report: dict[str, Any],
    manifest: dict[str, Any],
    plan: dict[str, Any],
    source_map: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
) -> ExternalEvidenceWorkPackageVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if work_package.get("schema") != EXTERNAL_EVIDENCE_WORK_PACKAGE_SCHEMA:
        errors.append(f"unsupported external evidence work package schema: {work_package.get('schema')}")
    if work_package.get("work_package_id") != content_hash(without_keys(work_package, "work_package_id")):
        errors.append("work_package_id does not match canonical work package body")
    group_by = str(work_package.get("group_by") or "")
    if group_by not in EXTERNAL_EVIDENCE_WORK_PACKAGE_GROUP_BY:
        errors.append(f"unsupported external evidence work package group_by: {group_by}")
    command_context = work_package.get("command_context")
    if not isinstance(command_context, dict):
        errors.append("external evidence work package command_context must be an object")
        command_context = {}
    try:
        expected = build_external_evidence_work_package(
            gap_report,
            manifest,
            plan,
            source_map,
            roadmap_audit,
            root=root,
            group_by=group_by if group_by in EXTERNAL_EVIDENCE_WORK_PACKAGE_GROUP_BY else "owner_hint",
            command_context=command_context,
            generated_at=str(work_package.get("generated_at") or ""),
        )
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if without_keys(work_package, "work_package_id") != without_keys(expected, "work_package_id"):
            errors.append("work package body does not match supplied gap report, manifest, plan, source map, and roadmap audit")
        gap_result = verify_external_evidence_gap_report(
            gap_report,
            manifest,
            plan,
            source_map,
            roadmap_audit,
            root=root,
            **_external_evidence_work_package_gap_options(gap_report),
        )
        warnings.extend(gap_result.warnings)
    return ExternalEvidenceWorkPackageVerification(ok=not errors, errors=errors, warnings=warnings)



def _external_evidence_owner_packet_task(task: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "task_id",
        "task_ref",
        "unit_id",
        "unit_ref",
        "requirement_id",
        "phase",
        "priority",
        "title",
        "authority_kind",
        "coverage_status",
        "owner_hint",
        "suggested_artifact_path",
        "source_uri",
        "source_uri_status",
        "snapshot_out",
        "intake_out",
        "description",
        "evidence_argument_template",
        "suggested_evidence_sources",
        "acceptance_criteria",
        "external_authority_required",
        "next_actions",
    )
    packet_task = {key: task.get(key) for key in keys if key in task}
    commands = task.get("commands")
    if isinstance(commands, dict):
        packet_task["commands"] = {
            key: commands.get(key)
            for key in ("collect_args", "collect_command", "verify_intake_args", "verify_intake_command")
            if key in commands
        }
    return packet_task


def build_external_evidence_owner_packets(
    work_package: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if work_package.get("schema") != EXTERNAL_EVIDENCE_WORK_PACKAGE_SCHEMA:
        raise ValueError(f"unsupported external evidence work package schema: {work_package.get('schema')}")
    if work_package.get("work_package_id") != content_hash(without_keys(work_package, "work_package_id")):
        raise ValueError("work_package_id does not match canonical work package body")
    packages = work_package.get("packages")
    if not isinstance(packages, list):
        raise ValueError("external evidence work package packages must be a list")

    packet_records: list[dict[str, Any]] = []
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise ValueError(f"external evidence work package package {index} must be an object")
        tasks = package.get("tasks")
        if not isinstance(tasks, list):
            raise ValueError(f"external evidence work package package {index} tasks must be a list")
        commands = package.get("commands") if isinstance(package.get("commands"), dict) else {}
        package_ref = str(package.get("package_ref") or f"package:{index}")
        packet_body = {
            "packet_ref": f"owner-packet:{package_ref}",
            "package_ref": package_ref,
            "package_id": package.get("package_id"),
            "package_hash": content_hash(package),
            "group_by": package.get("group_by"),
            "group_key": package.get("group_key"),
            "owner_hint": package.get("owner_hint") or package.get("group_key"),
            "task_count": package.get("task_count", len(tasks)),
            "missing_task_count": package.get("missing_task_count", 0),
            "covered_task_count": package.get("covered_task_count", 0),
            "placeholder_source_uri_count": package.get("placeholder_source_uri_count", 0),
            "live_source_uri_count": package.get("live_source_uri_count", 0),
            "authority_kinds": package.get("authority_kinds", []),
            "requirement_ids": package.get("requirement_ids", []),
            "phases": package.get("phases", []),
            "priorities": package.get("priorities", []),
            "handoff": {
                "collect_batch_command": commands.get("collect_batch_command"),
                "rebuild_manifest_command": commands.get("rebuild_manifest_command"),
                "completion_gate": "Every task must have a live authority source URI, a verified source snapshot, a verified intake receipt, and a rebuilt external-evidence manifest before readiness can pass.",
                "requires_placeholder_replacement": bool(package.get("placeholder_source_uri_count", 0)),
            },
            "tasks": [_external_evidence_owner_packet_task(task) for task in tasks if isinstance(task, dict)],
        }
        packet_records.append({**packet_body, "packet_id": content_hash(packet_body)})

    packet_records.sort(key=lambda packet: str(packet.get("packet_ref") or ""))
    work_summary = work_package.get("summary", {}) if isinstance(work_package.get("summary"), dict) else {}
    body = {
        "schema": EXTERNAL_EVIDENCE_OWNER_PACKET_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "source_work_package": {
            "work_package_id": work_package.get("work_package_id"),
            "work_package_hash": content_hash(work_package),
            "group_by": work_package.get("group_by"),
            "generated_at": work_package.get("generated_at"),
        },
        "summary": {
            "packet_count": len(packet_records),
            "task_count": sum(int(packet.get("task_count") or 0) for packet in packet_records),
            "missing_task_count": sum(int(packet.get("missing_task_count") or 0) for packet in packet_records),
            "covered_task_count": sum(int(packet.get("covered_task_count") or 0) for packet in packet_records),
            "placeholder_source_uri_count": sum(int(packet.get("placeholder_source_uri_count") or 0) for packet in packet_records),
            "live_source_uri_count": sum(int(packet.get("live_source_uri_count") or 0) for packet in packet_records),
            "source_work_package_task_count": work_summary.get("task_count", 0),
            "task_count_by_authority_kind": work_summary.get("task_count_by_authority_kind", {}),
            "task_count_by_owner_hint": work_summary.get("task_count_by_owner_hint", {}),
        },
        "packets": packet_records,
        "limitations": [
            "Owner packets assign collection work; they do not satisfy missing external authority evidence by themselves.",
            "Source URIs marked TODO or placeholder must be replaced with authority-owned source exports before collection.",
            "Packet completion is proven only by verified source snapshots, intake receipts, rebuilt manifests, and readiness reports.",
        ],
    }
    return {**body, "owner_packet_bundle_id": content_hash(body)}


def verify_external_evidence_owner_packets(
    packet_bundle: dict[str, Any],
    work_package: dict[str, Any],
) -> ExternalEvidenceOwnerPacketVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if packet_bundle.get("schema") != EXTERNAL_EVIDENCE_OWNER_PACKET_SCHEMA:
        errors.append(f"unsupported external evidence owner packet schema: {packet_bundle.get('schema')}")
    if packet_bundle.get("owner_packet_bundle_id") != content_hash(without_keys(packet_bundle, "owner_packet_bundle_id")):
        errors.append("owner_packet_bundle_id does not match canonical owner packet bundle body")
    source = packet_bundle.get("source_work_package") if isinstance(packet_bundle.get("source_work_package"), dict) else {}
    if source.get("work_package_id") != work_package.get("work_package_id"):
        errors.append("owner packet bundle source work_package_id does not match supplied work package")
    if source.get("work_package_hash") != content_hash(work_package):
        errors.append("owner packet bundle source work_package_hash does not match supplied work package")
    try:
        expected = build_external_evidence_owner_packets(
            work_package,
            generated_at=str(packet_bundle.get("generated_at") or ""),
        )
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if without_keys(packet_bundle, "owner_packet_bundle_id") != without_keys(expected, "owner_packet_bundle_id"):
            errors.append("owner packet bundle body does not match supplied work package")
        summary = packet_bundle.get("summary", {}) if isinstance(packet_bundle.get("summary"), dict) else {}
        if summary.get("task_count") != summary.get("source_work_package_task_count"):
            warnings.append("owner packet task count does not match recorded source work package task count")
    return ExternalEvidenceOwnerPacketVerification(ok=not errors, errors=errors, warnings=warnings)


def _external_evidence_owner_packet_source_entries(source_map: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = source_map.get("entries", [])
    if not isinstance(entries, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for ref in (entry.get("unit_ref"), entry.get("task"), entry.get("task_ref"), entry.get("task_id")):
            if ref:
                result[str(ref)] = entry
    return result


def _external_evidence_owner_packet_intakes(intakes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_ref: dict[str, list[dict[str, Any]]] = {}
    for intake in intakes:
        if not isinstance(intake, dict):
            continue
        task = intake.get("task") if isinstance(intake.get("task"), dict) else {}
        for ref in (task.get("unit_ref"), task.get("task_ref"), task.get("task_id")):
            if ref:
                by_ref.setdefault(str(ref), []).append(intake)
    return by_ref


def _external_evidence_owner_packet_task_refs(task: dict[str, Any]) -> list[str]:
    return [str(ref) for ref in (task.get("unit_ref"), task.get("task_ref"), task.get("task_id")) if ref]


def _external_evidence_owner_packet_path(value: Any) -> str:
    return str(value or "").replace("\\", "/")


def _external_evidence_owner_packet_artifact_status(root: str | Path, evidence_item: dict[str, Any]) -> tuple[bool, str | None]:
    artifact_path = str(evidence_item.get("path") or "")
    if not artifact_path:
        return False, None
    try:
        resolved = _resolve_evidence_item_artifact_path(root, artifact_path)
    except ValueError:
        return False, None
    if not resolved.is_file():
        return False, None
    return True, file_sha256_ref(resolved)


def _external_evidence_owner_packet_task_status(
    task: dict[str, Any],
    *,
    source_entries: dict[str, dict[str, Any]],
    intakes_by_ref: dict[str, list[dict[str, Any]]],
    root: str | Path,
) -> dict[str, Any]:
    refs = _external_evidence_owner_packet_task_refs(task)
    source_entry = next((source_entries[ref] for ref in refs if ref in source_entries), None)
    intake = next((intakes_by_ref[ref][0] for ref in refs if ref in intakes_by_ref and intakes_by_ref[ref]), None)
    source_uri = source_entry.get("source_uri") if isinstance(source_entry, dict) else task.get("source_uri")
    snapshot_out = source_entry.get("snapshot_out") if isinstance(source_entry, dict) else task.get("snapshot_out")
    intake_out = source_entry.get("intake_out") if isinstance(source_entry, dict) else task.get("intake_out")
    source_uri_status = "placeholder" if _source_map_is_placeholder_uri(str(source_uri or "")) else "live"
    blocking_reasons: list[str] = []
    if source_entry is None:
        blocking_reasons.append("missing-source-map-entry")
    if source_uri_status != "live":
        blocking_reasons.append("placeholder-source-uri")
    intake_record: dict[str, Any] | None = None
    if intake is None:
        blocking_reasons.append("missing-intake")
    else:
        intake_hash = content_hash(intake)
        intake_id_ok = intake.get("intake_id") == content_hash(without_keys(intake, "intake_id"))
        if not intake_id_ok:
            blocking_reasons.append("invalid-intake-id")
        intake_task = intake.get("task") if isinstance(intake.get("task"), dict) else {}
        evidence_item = intake.get("evidence_item") if isinstance(intake.get("evidence_item"), dict) else {}
        for key in ("requirement_id", "authority_kind"):
            if str(intake_task.get(key) or evidence_item.get(key) or "") != str(task.get(key) or ""):
                blocking_reasons.append(f"intake-{key}-mismatch")
        if str(evidence_item.get("source_uri") or "") != str(source_uri or ""):
            blocking_reasons.append("intake-source-uri-mismatch")
        if _external_evidence_owner_packet_path(evidence_item.get("path")) != _external_evidence_owner_packet_path(snapshot_out):
            blocking_reasons.append("intake-artifact-path-mismatch")
        artifact_present, artifact_sha256 = _external_evidence_owner_packet_artifact_status(root, evidence_item)
        if not artifact_present:
            blocking_reasons.append("intake-artifact-missing")
        elif artifact_sha256 != evidence_item.get("sha256"):
            blocking_reasons.append("intake-artifact-hash-mismatch")
        intake_record = {
            "intake_id": intake.get("intake_id"),
            "intake_hash": intake_hash,
            "intake_id_ok": intake_id_ok,
            "artifact_path": evidence_item.get("path"),
            "artifact_present": artifact_present,
            "artifact_sha256": artifact_sha256,
        }
    closed = not blocking_reasons
    if closed:
        task_status = "closed"
    elif "placeholder-source-uri" in blocking_reasons or "missing-source-map-entry" in blocking_reasons:
        task_status = "blocked"
    else:
        task_status = "open"
    return {
        "unit_ref": task.get("unit_ref"),
        "task_ref": task.get("task_ref"),
        "requirement_id": task.get("requirement_id"),
        "authority_kind": task.get("authority_kind"),
        "owner_hint": task.get("owner_hint"),
        "source_uri": source_uri,
        "source_uri_status": source_uri_status,
        "snapshot_out": snapshot_out,
        "intake_out": intake_out,
        "task_status": task_status,
        "blocking_reasons": blocking_reasons,
        "intake": intake_record,
    }


def _external_evidence_owner_packet_status_counts(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        value = str(record.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return {name: counts[name] for name in sorted(counts)}


def build_external_evidence_owner_packet_status(
    packet_bundle: dict[str, Any],
    work_package: dict[str, Any],
    source_map: dict[str, Any],
    intakes: list[dict[str, Any]] | None = None,
    *,
    root: str | Path = ".",
    generated_at: str | None = None,
) -> dict[str, Any]:
    packet_result = verify_external_evidence_owner_packets(packet_bundle, work_package)
    if not packet_result.ok:
        raise ValueError("external evidence owner packets are not valid for status: " + "; ".join(packet_result.errors))
    if source_map.get("schema") != EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA:
        raise ValueError(f"unsupported external evidence source map schema: {source_map.get('schema')}")
    if source_map.get("source_map_id") != content_hash(without_keys(source_map, "source_map_id")):
        raise ValueError("source_map_id does not match canonical source map body")
    source_entries = _external_evidence_owner_packet_source_entries(source_map)
    supplied_intakes = [intake for intake in (intakes or []) if isinstance(intake, dict)]
    intakes_by_ref = _external_evidence_owner_packet_intakes(supplied_intakes)
    packet_statuses: list[dict[str, Any]] = []
    task_statuses: list[dict[str, Any]] = []
    for packet in packet_bundle.get("packets", []):
        if not isinstance(packet, dict):
            continue
        packet_tasks = packet.get("tasks", []) if isinstance(packet.get("tasks"), list) else []
        statuses = [
            _external_evidence_owner_packet_task_status(task, source_entries=source_entries, intakes_by_ref=intakes_by_ref, root=root)
            for task in packet_tasks
            if isinstance(task, dict)
        ]
        closed_count = sum(1 for status in statuses if status.get("task_status") == "closed")
        blocked_count = sum(1 for status in statuses if status.get("task_status") == "blocked")
        open_count = len(statuses) - closed_count - blocked_count
        if statuses and closed_count == len(statuses):
            packet_status = "closed"
        elif blocked_count:
            packet_status = "blocked"
        else:
            packet_status = "open"
        packet_statuses.append(
            {
                "packet_ref": packet.get("packet_ref"),
                "packet_id": packet.get("packet_id"),
                "owner_hint": packet.get("owner_hint"),
                "task_count": len(statuses),
                "closed_task_count": closed_count,
                "open_task_count": open_count,
                "blocked_task_count": blocked_count,
                "packet_status": packet_status,
            }
        )
        task_statuses.extend(statuses)
    closed_task_count = sum(1 for status in task_statuses if status.get("task_status") == "closed")
    blocked_task_count = sum(1 for status in task_statuses if status.get("task_status") == "blocked")
    open_task_count = len(task_statuses) - closed_task_count - blocked_task_count
    placeholder_source_uri_count = sum(1 for status in task_statuses if status.get("source_uri_status") == "placeholder")
    missing_intake_count = sum(1 for status in task_statuses if "missing-intake" in status.get("blocking_reasons", []))
    invalid_intake_count = sum(1 for status in task_statuses if any(str(reason).startswith("invalid-intake") for reason in status.get("blocking_reasons", [])))
    body = {
        "schema": EXTERNAL_EVIDENCE_OWNER_PACKET_STATUS_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "sources": {
            "owner_packet_bundle": {
                "owner_packet_bundle_id": packet_bundle.get("owner_packet_bundle_id"),
                "owner_packet_bundle_hash": content_hash(packet_bundle),
                "schema": packet_bundle.get("schema"),
                "generated_at": packet_bundle.get("generated_at"),
            },
            "work_package": {
                "work_package_id": work_package.get("work_package_id"),
                "work_package_hash": content_hash(work_package),
                "schema": work_package.get("schema"),
                "generated_at": work_package.get("generated_at"),
            },
            "source_map": {
                "source_map_id": source_map.get("source_map_id"),
                "source_map_hash": content_hash(source_map),
                "schema": source_map.get("schema"),
                "generated_at": source_map.get("generated_at"),
            },
            "intake_hashes": [content_hash(intake) for intake in supplied_intakes],
        },
        "summary": {
            "packet_count": len(packet_statuses),
            "task_count": len(task_statuses),
            "closed_packet_count": sum(1 for packet in packet_statuses if packet.get("packet_status") == "closed"),
            "open_packet_count": sum(1 for packet in packet_statuses if packet.get("packet_status") == "open"),
            "blocked_packet_count": sum(1 for packet in packet_statuses if packet.get("packet_status") == "blocked"),
            "closed_task_count": closed_task_count,
            "open_task_count": open_task_count,
            "blocked_task_count": blocked_task_count,
            "placeholder_source_uri_count": placeholder_source_uri_count,
            "live_source_uri_count": len(task_statuses) - placeholder_source_uri_count,
            "missing_intake_count": missing_intake_count,
            "invalid_intake_count": invalid_intake_count,
            "packet_status_counts": _external_evidence_owner_packet_status_counts(packet_statuses, "packet_status"),
            "task_status_counts": _external_evidence_owner_packet_status_counts(task_statuses, "task_status"),
        },
        "packets": packet_statuses,
        "tasks": task_statuses,
        "limitations": [
            "Owner packet status tracks collection progress only; it does not prove production readiness.",
            "A closed task still requires rebuilt manifest verification and readiness verification before external authority coverage is accepted.",
            "Placeholder source URIs keep tasks blocked even when a local intake artifact is present.",
        ],
    }
    return {**body, "owner_packet_status_id": content_hash(body)}


def verify_external_evidence_owner_packet_status(
    status_report: dict[str, Any],
    packet_bundle: dict[str, Any],
    work_package: dict[str, Any],
    source_map: dict[str, Any],
    intakes: list[dict[str, Any]] | None = None,
    *,
    root: str | Path = ".",
) -> ExternalEvidenceOwnerPacketStatusVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if status_report.get("schema") != EXTERNAL_EVIDENCE_OWNER_PACKET_STATUS_SCHEMA:
        errors.append(f"unsupported external evidence owner packet status schema: {status_report.get('schema')}")
    if status_report.get("owner_packet_status_id") != content_hash(without_keys(status_report, "owner_packet_status_id")):
        errors.append("owner_packet_status_id does not match canonical owner packet status body")
    try:
        expected = build_external_evidence_owner_packet_status(
            packet_bundle,
            work_package,
            source_map,
            intakes or [],
            root=root,
            generated_at=str(status_report.get("generated_at") or ""),
        )
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if without_keys(status_report, "owner_packet_status_id") != without_keys(expected, "owner_packet_status_id"):
            errors.append("owner packet status body does not match supplied packet bundle, work package, source map, and intakes")
        summary = status_report.get("summary", {}) if isinstance(status_report.get("summary"), dict) else {}
        if summary.get("placeholder_source_uri_count"):
            warnings.append(f"owner packet status contains {summary.get('placeholder_source_uri_count')} placeholder source_uri values")
        if summary.get("missing_intake_count"):
            warnings.append(f"owner packet status contains {summary.get('missing_intake_count')} tasks without intake receipts")
    return ExternalEvidenceOwnerPacketStatusVerification(ok=not errors, errors=errors, warnings=warnings)

def _external_evidence_owner_fulfillment_selected_tasks(
    status_report: dict[str, Any],
    *,
    owner_hint: str | None,
    include_closed: bool,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    tasks = status_report.get("tasks", [])
    if not isinstance(tasks, list):
        return selected
    for task in tasks:
        if not isinstance(task, dict):
            continue
        if owner_hint and str(task.get("owner_hint") or "") != owner_hint:
            continue
        if not include_closed and task.get("task_status") == "closed":
            continue
        selected.append(task)
    selected.sort(key=lambda item: (str(item.get("owner_hint") or ""), str(item.get("unit_ref") or item.get("task_ref") or "")))
    return selected


def _external_evidence_owner_fulfillment_description(task: dict[str, Any]) -> str:
    requirement_id = str(task.get("requirement_id") or "").strip()
    authority_kind = str(task.get("authority_kind") or "").strip()
    if requirement_id and authority_kind:
        return f"{authority_kind} evidence for {requirement_id}"
    return "External authority evidence"


def _external_evidence_owner_fulfillment_placeholder(task: dict[str, Any]) -> str:
    requirement_id = str(task.get("requirement_id") or "unknown-requirement").strip() or "unknown-requirement"
    authority_kind = str(task.get("authority_kind") or "unknown-authority").strip() or "unknown-authority"
    return f"TODO://authority/{requirement_id}/{authority_kind}"


def _external_evidence_owner_fulfillment_record(task: dict[str, Any]) -> dict[str, Any]:
    task_ref = str(task.get("unit_ref") or task.get("task_ref") or "").strip()
    if not task_ref:
        task_ref = _external_evidence_item_unit_ref(task)
    source_uri = str(task.get("source_uri") or "").strip() or _external_evidence_owner_fulfillment_placeholder(task)
    description = _external_evidence_owner_fulfillment_description(task)
    return {"task": task_ref, "source_uri": source_uri, "description": description}


def _external_evidence_owner_assignment_record(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task": str(task.get("unit_ref") or task.get("task_ref") or ""),
        "owner_hint": task.get("owner_hint"),
        "requirement_id": task.get("requirement_id"),
        "authority_kind": task.get("authority_kind"),
        "task_status": task.get("task_status"),
        "source_uri_status": task.get("source_uri_status"),
        "blocking_reasons": list(task.get("blocking_reasons") or []),
        "snapshot_out": task.get("snapshot_out"),
        "intake_out": task.get("intake_out"),
    }


def build_external_evidence_owner_fulfillment_template(
    status_report: dict[str, Any],
    *,
    owner_hint: str | None = None,
    include_closed: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if status_report.get("schema") != EXTERNAL_EVIDENCE_OWNER_PACKET_STATUS_SCHEMA:
        raise ValueError(f"unsupported external evidence owner packet status schema: {status_report.get('schema')}")
    if status_report.get("owner_packet_status_id") != content_hash(without_keys(status_report, "owner_packet_status_id")):
        raise ValueError("owner_packet_status_id does not match canonical owner packet status body")
    owner_filter = str(owner_hint).strip() if owner_hint else None
    selected_tasks = _external_evidence_owner_fulfillment_selected_tasks(
        status_report,
        owner_hint=owner_filter,
        include_closed=include_closed,
    )
    fulfillments = [_external_evidence_owner_fulfillment_record(task) for task in selected_tasks]
    assignments = [_external_evidence_owner_assignment_record(task) for task in selected_tasks]
    owner_hints = sorted({str(task.get("owner_hint") or "unknown") for task in selected_tasks})
    blocked_count = sum(1 for task in selected_tasks if task.get("task_status") == "blocked")
    open_count = sum(1 for task in selected_tasks if task.get("task_status") == "open")
    closed_count = sum(1 for task in selected_tasks if task.get("task_status") == "closed")
    placeholder_count = sum(1 for task in selected_tasks if task.get("source_uri_status") == "placeholder")
    missing_intake_count = sum(1 for task in selected_tasks if "missing-intake" in task.get("blocking_reasons", []))
    body = {
        "schema": EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_TEMPLATE_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "source_owner_packet_status": {
            "owner_packet_status_id": status_report.get("owner_packet_status_id"),
            "owner_packet_status_hash": content_hash(status_report),
            "schema": status_report.get("schema"),
            "generated_at": status_report.get("generated_at"),
        },
        "filters": {"owner_hint": owner_filter, "include_closed": include_closed},
        "summary": {
            "fulfillment_count": len(fulfillments),
            "assignment_count": len(assignments),
            "owner_count": len(owner_hints),
            "owners": owner_hints,
            "blocked_task_count": blocked_count,
            "open_task_count": open_count,
            "closed_task_count": closed_count,
            "placeholder_source_uri_count": placeholder_count,
            "live_source_uri_count": len(selected_tasks) - placeholder_count,
            "missing_intake_count": missing_intake_count,
        },
        "fulfillments": fulfillments,
        "assignments": assignments,
        "commands": {
            "fill_then_fulfill_source_map": "python -m trustai external-evidence-source-map-fulfill <source-map.json> <plan.json> --fulfillment-file <this-template.json> --require-live-source-uris --out <fulfilled-source-map.json>",
            "collect_after_fulfillment": "python -m trustai external-evidence-collect-batch <fulfilled-source-map.json> <manifest.json> <roadmap-audit.json> --root . --require-live-source-uris",
            "rebuild_manifest_after_intakes": "python -m trustai external-evidence-manifest-from-intakes <plan.json> <manifest.json> <roadmap-audit.json> --intake-dir <intake-dir> --require-live-source-uris --require-source-snapshot-artifacts",
        },
        "instructions": [
            "Replace every TODO or placeholder fulfillments[*].source_uri with an authority-owned live source URI.",
            "Keep fulfillments[*] restricted to fields accepted by external-evidence-source-map-fulfill; owner metadata is recorded under assignments.",
            "Collect source snapshots and intake receipts after the fulfilled source map verifies with --require-live-source-uris.",
        ],
        "limitations": [
            "This template is a handoff artifact; it does not satisfy missing external authority evidence by itself.",
            "Placeholder source URIs intentionally keep readiness blocked until owners replace them with live authority sources.",
        ],
    }
    return {**body, "owner_fulfillment_template_id": content_hash(body)}


def verify_external_evidence_owner_fulfillment_template(
    template: dict[str, Any],
    status_report: dict[str, Any],
) -> ExternalEvidenceOwnerFulfillmentTemplateVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if template.get("schema") != EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_TEMPLATE_SCHEMA:
        errors.append(f"unsupported external evidence owner fulfillment template schema: {template.get('schema')}")
    if template.get("owner_fulfillment_template_id") != content_hash(without_keys(template, "owner_fulfillment_template_id")):
        errors.append("owner_fulfillment_template_id does not match canonical owner fulfillment template body")
    source = template.get("source_owner_packet_status") if isinstance(template.get("source_owner_packet_status"), dict) else {}
    if source.get("owner_packet_status_id") != status_report.get("owner_packet_status_id"):
        errors.append("owner fulfillment template source owner_packet_status_id does not match supplied status report")
    if source.get("owner_packet_status_hash") != content_hash(status_report):
        errors.append("owner fulfillment template source owner_packet_status_hash does not match supplied status report")
    filters = template.get("filters") if isinstance(template.get("filters"), dict) else {}
    try:
        expected = build_external_evidence_owner_fulfillment_template(
            status_report,
            owner_hint=filters.get("owner_hint"),
            include_closed=bool(filters.get("include_closed")),
            generated_at=str(template.get("generated_at") or ""),
        )
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if without_keys(template, "owner_fulfillment_template_id") != without_keys(expected, "owner_fulfillment_template_id"):
            errors.append("owner fulfillment template body does not match supplied owner packet status report")
    summary = template.get("summary", {}) if isinstance(template.get("summary"), dict) else {}
    if summary.get("placeholder_source_uri_count"):
        warnings.append(f"owner fulfillment template contains {summary.get('placeholder_source_uri_count')} placeholder source_uri values")
    if summary.get("missing_intake_count"):
        warnings.append(f"owner fulfillment template contains {summary.get('missing_intake_count')} tasks without intake receipts")
    return ExternalEvidenceOwnerFulfillmentTemplateVerification(ok=not errors, errors=errors, warnings=warnings)


def _external_evidence_review_source_record(document: dict[str, Any], id_key: str, hash_key: str) -> dict[str, Any]:
    return {
        id_key: document.get(id_key),
        hash_key: content_hash(document),
        "schema": document.get("schema"),
        "generated_at": document.get("generated_at"),
    }


def _verify_external_evidence_owner_fulfillment_submission(
    template: dict[str, Any],
    status_report: dict[str, Any],
) -> ExternalEvidenceOwnerFulfillmentTemplateVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if template.get("schema") != EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_TEMPLATE_SCHEMA:
        errors.append(f"unsupported external evidence owner fulfillment template schema: {template.get('schema')}")
    if template.get("owner_fulfillment_template_id") != content_hash(without_keys(template, "owner_fulfillment_template_id")):
        warnings.append("owner fulfillment template id is stale after owner edits; review records the submitted content hash")
    source = template.get("source_owner_packet_status") if isinstance(template.get("source_owner_packet_status"), dict) else {}
    if source.get("owner_packet_status_id") != status_report.get("owner_packet_status_id"):
        errors.append("owner fulfillment template source owner_packet_status_id does not match supplied status report")
    if source.get("owner_packet_status_hash") != content_hash(status_report):
        errors.append("owner fulfillment template source owner_packet_status_hash does not match supplied status report")
    filters = template.get("filters") if isinstance(template.get("filters"), dict) else {}
    try:
        expected = build_external_evidence_owner_fulfillment_template(
            status_report,
            owner_hint=filters.get("owner_hint"),
            include_closed=bool(filters.get("include_closed")),
            generated_at=str(template.get("generated_at") or ""),
        )
    except ValueError as exc:
        errors.append(str(exc))
        expected = None
    if expected is not None:
        stable_keys = ("owner_fulfillment_template_id", "summary", "fulfillments")
        if without_keys(template, *stable_keys) != without_keys(expected, *stable_keys):
            errors.append("owner fulfillment submission metadata does not match supplied owner packet status report")
        expected_tasks = [str(item.get("task") or "") for item in expected.get("fulfillments", []) if isinstance(item, dict)]
        actual_tasks = [str(item.get("task") or "") for item in template.get("fulfillments", []) if isinstance(item, dict)]
        if sorted(actual_tasks) != sorted(expected_tasks):
            errors.append("owner fulfillment submission tasks do not match supplied owner packet status report")
    summary = template.get("summary", {}) if isinstance(template.get("summary"), dict) else {}
    if summary.get("placeholder_source_uri_count"):
        warnings.append(f"owner fulfillment template summary contains {summary.get('placeholder_source_uri_count')} placeholder source_uri values")
    if summary.get("missing_intake_count"):
        warnings.append(f"owner fulfillment template summary contains {summary.get('missing_intake_count')} tasks without intake receipts")
    return ExternalEvidenceOwnerFulfillmentTemplateVerification(ok=not errors, errors=errors, warnings=warnings)


def _external_evidence_owner_fulfillment_review_task_records(
    template: dict[str, Any],
    fulfilled_source_map: dict[str, Any],
) -> list[dict[str, Any]]:
    assignments = template.get("assignments", [])
    assignment_by_task: dict[str, dict[str, Any]] = {}
    if isinstance(assignments, list):
        for assignment in assignments:
            if isinstance(assignment, dict):
                task_ref = str(assignment.get("task") or "")
                if task_ref:
                    assignment_by_task[task_ref] = assignment

    defaults = fulfilled_source_map.get("defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    records: list[dict[str, Any]] = []
    entries = fulfilled_source_map.get("entries", [])
    if not isinstance(entries, list):
        return records
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        task_ref = str(entry.get("unit_ref") or entry.get("task") or "")
        assignment = assignment_by_task.get(task_ref) or assignment_by_task.get(str(entry.get("task") or "")) or {}
        source_uri = str(_source_map_effective_value(entry, defaults, "source_uri") or "")
        is_placeholder = _source_map_is_placeholder_uri(source_uri)
        blocking_reasons: list[str] = []
        if is_placeholder:
            blocking_reasons.append("placeholder-source-uri")
        records.append(
            {
                "task": task_ref,
                "owner_hint": assignment.get("owner_hint") or entry.get("owner_hint"),
                "requirement_id": entry.get("requirement_id"),
                "authority_kind": entry.get("authority_kind"),
                "source_uri": source_uri,
                "source_uri_status": "placeholder" if is_placeholder else "live",
                "review_status": "blocked" if blocking_reasons else "ready-to-collect",
                "blocking_reasons": blocking_reasons,
                "snapshot_out": entry.get("snapshot_out"),
                "intake_out": entry.get("intake_out"),
            }
        )
    return records


def _external_evidence_owner_fulfillment_review_blockers(
    template_result: ExternalEvidenceOwnerFulfillmentTemplateVerification,
    source_map_result: ExternalEvidenceSourceMapVerification,
    placeholder_count: int,
) -> list[str]:
    blockers: list[str] = []
    if not template_result.ok:
        blockers.extend(f"owner fulfillment template: {error}" for error in template_result.errors)
    if placeholder_count:
        blockers.append(f"owner fulfillment review contains {placeholder_count} placeholder source_uri values")
    if not source_map_result.ok:
        blockers.extend(f"fulfilled source map: {error}" for error in source_map_result.errors)
    return blockers


def _external_evidence_owner_fulfillment_review_next_actions(review_status: str, placeholder_count: int) -> list[str]:
    if placeholder_count:
        return [
            "Replace every placeholder source_uri in the owner fulfillment template with a live authority-owned URI.",
            "Regenerate this review with --require-live-source-uris before collecting source snapshots.",
            "After the fulfilled source map is ready, run external-evidence-collect-batch and rebuild the retained manifest from intake receipts.",
        ]
    if review_status == "ready-to-collect":
        return [
            "Run external-evidence-collect-batch with the reviewed fulfilled source map.",
            "Verify source snapshots and intake receipts, then rebuild the external evidence manifest from intakes.",
            "Regenerate external-evidence-readiness with --require-ready before claiming production authority coverage.",
        ]
    return [
        "Resolve the fulfilled source-map verification errors in this review.",
        "Regenerate this review after the owner fulfillment template and source map verify cleanly.",
    ]


def build_external_evidence_owner_fulfillment_review(
    template: dict[str, Any],
    status_report: dict[str, Any],
    source_map: dict[str, Any],
    plan: dict[str, Any],
    *,
    root: str | Path = ".",
    require_live_source_uris: bool = False,
    require_source_snapshots: bool = False,
    require_fresh_source_snapshots: bool = False,
    now: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    template_result = _verify_external_evidence_owner_fulfillment_submission(template, status_report)
    if not template_result.ok:
        raise ValueError("external evidence owner fulfillment submission is not valid for review: " + "; ".join(template_result.errors))
    fulfilled_source_map = fulfill_external_evidence_source_map(
        source_map,
        template.get("fulfillments", []),
        generated_at=generated_at,
    )
    source_map_result = verify_external_evidence_source_map_template(
        fulfilled_source_map,
        plan,
        root=root,
        require_live_source_uris=require_live_source_uris,
        require_source_snapshots=require_source_snapshots,
        require_fresh_source_snapshots=require_fresh_source_snapshots,
        now=now,
    )
    fulfilled_summary = fulfilled_source_map.get("summary", {}) if isinstance(fulfilled_source_map.get("summary"), dict) else {}
    template_summary = template.get("summary", {}) if isinstance(template.get("summary"), dict) else {}
    task_reviews = _external_evidence_owner_fulfillment_review_task_records(template, fulfilled_source_map)
    ready_task_count = sum(1 for task in task_reviews if task.get("review_status") == "ready-to-collect")
    blocked_task_count = sum(1 for task in task_reviews if task.get("review_status") == "blocked")
    placeholder_count = int(fulfilled_summary.get("placeholder_source_uri_count") or 0)
    review_status = "ready-to-collect" if source_map_result.ok and blocked_task_count == 0 and placeholder_count == 0 else "blocked"
    blockers = _external_evidence_owner_fulfillment_review_blockers(template_result, source_map_result, placeholder_count)
    body = {
        "schema": EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_REVIEW_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "verification_options": {
            "require_live_source_uris": require_live_source_uris,
            "require_source_snapshots": require_source_snapshots,
            "require_fresh_source_snapshots": require_fresh_source_snapshots,
            "now": now,
        },
        "sources": {
            "owner_fulfillment_template": _external_evidence_review_source_record(
                template,
                "owner_fulfillment_template_id",
                "owner_fulfillment_template_hash",
            ),
            "owner_packet_status": _external_evidence_review_source_record(
                status_report,
                "owner_packet_status_id",
                "owner_packet_status_hash",
            ),
            "source_map": _external_evidence_review_source_record(source_map, "source_map_id", "source_map_hash"),
            "collection_plan": _external_evidence_review_source_record(plan, "plan_id", "plan_hash"),
        },
        "summary": {
            "review_status": review_status,
            "fulfillment_count": int(template_summary.get("fulfillment_count") or len(template.get("fulfillments", []))),
            "owner_count": int(template_summary.get("owner_count") or 0),
            "ready_task_count": ready_task_count,
            "blocked_task_count": blocked_task_count,
            "placeholder_source_uri_count": placeholder_count,
            "live_source_uri_count": int(fulfilled_summary.get("live_source_uri_count") or 0),
            "source_map_entry_count": int(fulfilled_summary.get("entry_count") or len(task_reviews)),
            "template_verification_ok": template_result.ok,
            "fulfilled_source_map_verification_ok": source_map_result.ok,
            "error_count": len(source_map_result.errors),
            "warning_count": len(template_result.warnings) + len(source_map_result.warnings),
        },
        "fulfilled_source_map": fulfilled_source_map,
        "task_reviews": task_reviews,
        "verification": {
            "template_warnings": template_result.warnings,
            "fulfilled_source_map_errors": source_map_result.errors,
            "fulfilled_source_map_warnings": source_map_result.warnings,
        },
        "blockers": blockers,
        "next_actions": _external_evidence_owner_fulfillment_review_next_actions(review_status, placeholder_count),
        "commands": {
            "review_fulfillment": "python -m trustai external-evidence-owner-fulfillment-review <template.json> <status-report.json> <source-map.json> <plan.json> --require-live-source-uris --out <review.json> --fulfilled-source-map-out <fulfilled-source-map.json>",
            "collect_after_ready_review": "python -m trustai external-evidence-collect-batch <fulfilled-source-map.json> <manifest.json> <roadmap-audit.json> --root . --require-live-source-uris",
            "verify_ready_review": "python -m trustai external-evidence-owner-fulfillment-review-verify <review.json> <template.json> <status-report.json> <source-map.json> <plan.json> --require-ready",
        },
        "limitations": [
            "This review proves owner fulfillment readiness for collection only; it does not prove authority evidence has been collected.",
            "A ready review still requires source snapshot collection, intake verification, manifest rebuild, and production readiness verification.",
            "Placeholder source URIs intentionally keep the review blocked until owners supply live authority sources.",
        ],
    }
    return {**body, "owner_fulfillment_review_id": content_hash(body)}


def verify_external_evidence_owner_fulfillment_review(
    review: dict[str, Any],
    template: dict[str, Any],
    status_report: dict[str, Any],
    source_map: dict[str, Any],
    plan: dict[str, Any],
    *,
    root: str | Path = ".",
    require_live_source_uris: bool = False,
    require_source_snapshots: bool = False,
    require_fresh_source_snapshots: bool = False,
    now: str | None = None,
    require_ready: bool = False,
) -> ExternalEvidenceOwnerFulfillmentReviewVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if review.get("schema") != EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_REVIEW_SCHEMA:
        errors.append(f"unsupported external evidence owner fulfillment review schema: {review.get('schema')}")
    if review.get("owner_fulfillment_review_id") != content_hash(without_keys(review, "owner_fulfillment_review_id")):
        errors.append("owner_fulfillment_review_id does not match canonical owner fulfillment review body")
    expected_options = {
        "require_live_source_uris": require_live_source_uris,
        "require_source_snapshots": require_source_snapshots,
        "require_fresh_source_snapshots": require_fresh_source_snapshots,
        "now": now,
    }
    if review.get("verification_options") != expected_options:
        errors.append("verification_options do not match verifier options")
    try:
        expected = build_external_evidence_owner_fulfillment_review(
            template,
            status_report,
            source_map,
            plan,
            root=root,
            require_live_source_uris=require_live_source_uris,
            require_source_snapshots=require_source_snapshots,
            require_fresh_source_snapshots=require_fresh_source_snapshots,
            now=now,
            generated_at=str(review.get("generated_at") or ""),
        )
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if without_keys(review, "owner_fulfillment_review_id") != without_keys(expected, "owner_fulfillment_review_id"):
            errors.append("owner fulfillment review body does not match supplied template, status report, source map, and plan")
    summary = review.get("summary", {}) if isinstance(review.get("summary"), dict) else {}
    verification = review.get("verification", {}) if isinstance(review.get("verification"), dict) else {}
    warnings.extend(verification.get("template_warnings", []) if isinstance(verification.get("template_warnings"), list) else [])
    warnings.extend(verification.get("fulfilled_source_map_warnings", []) if isinstance(verification.get("fulfilled_source_map_warnings"), list) else [])
    if summary.get("placeholder_source_uri_count"):
        warnings.append(f"owner fulfillment review contains {summary.get('placeholder_source_uri_count')} placeholder source_uri values")
    if require_ready and summary.get("review_status") != "ready-to-collect":
        errors.append("owner fulfillment review is not ready to collect")
    return ExternalEvidenceOwnerFulfillmentReviewVerification(ok=not errors, errors=errors, warnings=warnings)


def _external_evidence_owner_fulfillment_closure_source_errors(
    review: dict[str, Any],
    status_report: dict[str, Any],
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if review.get("schema") != EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_REVIEW_SCHEMA:
        errors.append(f"unsupported external evidence owner fulfillment review schema: {review.get('schema')}")
    if review.get("owner_fulfillment_review_id") != content_hash(without_keys(review, "owner_fulfillment_review_id")):
        errors.append("owner_fulfillment_review_id does not match canonical owner fulfillment review body")
    if status_report.get("schema") != EXTERNAL_EVIDENCE_OWNER_PACKET_STATUS_SCHEMA:
        errors.append(f"unsupported external evidence owner packet status schema: {status_report.get('schema')}")
    if status_report.get("owner_packet_status_id") != content_hash(without_keys(status_report, "owner_packet_status_id")):
        errors.append("owner_packet_status_id does not match canonical owner packet status body")
    sources = review.get("sources") if isinstance(review.get("sources"), dict) else {}
    status_source = sources.get("owner_packet_status") if isinstance(sources.get("owner_packet_status"), dict) else {}
    if status_source.get("owner_packet_status_id") != status_report.get("owner_packet_status_id"):
        errors.append("owner fulfillment review source owner_packet_status_id does not match supplied status report")
    if status_source.get("owner_packet_status_hash") != content_hash(status_report):
        errors.append("owner fulfillment review source owner_packet_status_hash does not match supplied status report")
    summary = review.get("summary", {}) if isinstance(review.get("summary"), dict) else {}
    if summary.get("review_status") != "ready-to-collect":
        warnings.append("owner fulfillment review is not ready to collect")
    return errors, warnings


def _external_evidence_owner_fulfillment_closure_manifest_units(manifest: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    units: dict[tuple[str, str], list[dict[str, Any]]] = {}
    evidence = manifest.get("evidence", [])
    if not isinstance(evidence, list):
        return units
    for item in evidence:
        if isinstance(item, dict):
            key = _evidence_unit_key(item)
            if key[0] and key[1]:
                units.setdefault(key, []).append(item)
    return units


def _external_evidence_owner_fulfillment_closure_intake_records(
    intakes: list[dict[str, Any]],
    plan: dict[str, Any],
    source_manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    require_fresh: bool,
    require_live_source_uris: bool,
    require_source_snapshot_artifacts: bool,
    require_fresh_source_snapshot_artifacts: bool,
    now: str | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, intake in enumerate(intakes):
        result = verify_external_evidence_intake(
            intake,
            plan,
            source_manifest,
            roadmap_audit,
            root=root,
            require_fresh=require_fresh,
            require_live_source_uris=require_live_source_uris,
            require_source_snapshot_artifacts=require_source_snapshot_artifacts,
            require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
            now=now,
        )
        evidence_item = intake.get("evidence_item") if isinstance(intake, dict) and isinstance(intake.get("evidence_item"), dict) else {}
        task = intake.get("task") if isinstance(intake, dict) and isinstance(intake.get("task"), dict) else {}
        unit_key = _evidence_unit_key(evidence_item)
        records.append(
            {
                "intake_index": index,
                "intake_id": intake.get("intake_id") if isinstance(intake, dict) else None,
                "task": task.get("unit_ref") or task.get("task_ref") or task.get("task_id"),
                "unit_ref": f"{unit_key[0]}:{unit_key[1]}" if unit_key[0] and unit_key[1] else None,
                "requirement_id": unit_key[0] or None,
                "authority_kind": unit_key[1] or None,
                "evidence_hash": content_hash(evidence_item) if unit_key[0] and unit_key[1] else None,
                "verification_ok": result.ok,
                "errors": result.errors,
                "warnings": result.warnings,
            }
        )
    return records


def _external_evidence_owner_fulfillment_closure_task_status(blockers: list[str]) -> str:
    if not blockers:
        return "closed"
    if "missing-intake" in blockers:
        return "missing-intake"
    if "invalid-intake" in blockers:
        return "invalid-intake"
    if "missing-manifest-coverage" in blockers:
        return "missing-manifest-coverage"
    if "manifest-intake-mismatch" in blockers:
        return "manifest-intake-mismatch"
    return "blocked"


def _external_evidence_owner_fulfillment_closure_next_actions(summary: dict[str, Any]) -> list[str]:
    if summary.get("closure_status") == "closed":
        return [
            "Regenerate production readiness with the rebuilt manifest and require-ready gate.",
            "Append the complete external-evidence manifest to the roadmap evidence chain.",
        ]
    actions: list[str] = []
    if summary.get("placeholder_source_uri_count"):
        actions.append("Replace placeholder owner source URIs with live authority-owned source URIs and rerun the fulfillment review.")
    if summary.get("missing_intake_count") or summary.get("invalid_intake_task_count"):
        actions.append("Collect and verify source snapshots and intake receipts for every reviewed owner task.")
    if summary.get("missing_manifest_coverage_count") or summary.get("manifest_intake_mismatch_count"):
        actions.append("Rebuild the external-evidence manifest from the verified intake receipts and rerun closure verification.")
    if summary.get("source_error_count"):
        actions.append("Fix source artifact verification errors before accepting any owner fulfillment as closed.")
    if not actions:
        actions.append("Resolve the closure blockers and rerun this report before claiming external authority coverage.")
    return actions


def build_external_evidence_owner_fulfillment_closure(
    review: dict[str, Any],
    status_report: dict[str, Any],
    rebuilt_manifest: dict[str, Any],
    source_manifest: dict[str, Any],
    plan: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path = ".",
    intakes: list[dict[str, Any]] | None = None,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_source_snapshot_artifacts: bool = False,
    require_fresh_source_snapshot_artifacts: bool = False,
    now: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    intake_list = list(intakes or [])
    review_errors, review_warnings = _external_evidence_owner_fulfillment_closure_source_errors(review, status_report)
    roadmap_result = verify_roadmap_audit(roadmap_audit, root=root)
    source_manifest_result = verify_external_evidence_manifest(
        source_manifest,
        roadmap_audit,
        root=root,
        require_fresh=require_fresh,
        require_live_source_uris=require_live_source_uris,
        require_source_snapshot_artifacts=require_source_snapshot_artifacts,
        require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
        now=now,
    )
    plan_result = verify_external_evidence_collection_plan(plan, source_manifest, roadmap_audit, root=root)
    rebuilt_manifest_result = verify_external_evidence_manifest(
        rebuilt_manifest,
        roadmap_audit,
        root=root,
        require_fresh=require_fresh,
        require_live_source_uris=require_live_source_uris,
        require_source_snapshot_artifacts=require_source_snapshot_artifacts,
        require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
        now=now,
    )
    intake_records = _external_evidence_owner_fulfillment_closure_intake_records(
        intake_list,
        plan,
        source_manifest,
        roadmap_audit,
        root=root,
        require_fresh=require_fresh,
        require_live_source_uris=require_live_source_uris,
        require_source_snapshot_artifacts=require_source_snapshot_artifacts,
        require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
        now=now,
    )

    verification_errors: list[str] = []
    verification_warnings: list[str] = []
    verification_errors.extend(f"owner fulfillment review: {error}" for error in review_errors)
    verification_warnings.extend(f"owner fulfillment review: {warning}" for warning in review_warnings)
    for label, result in (
        ("roadmap audit", roadmap_result),
        ("source manifest", source_manifest_result),
        ("collection plan", plan_result),
        ("rebuilt manifest", rebuilt_manifest_result),
    ):
        verification_errors.extend(f"{label}: {error}" for error in result.errors)
        verification_warnings.extend(f"{label}: {warning}" for warning in result.warnings)

    valid_intakes_by_unit: dict[tuple[str, str], dict[str, Any]] = {}
    duplicate_valid_units: set[tuple[str, str]] = set()
    invalid_intakes_by_unit: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in intake_records:
        unit_key = (str(record.get("requirement_id") or ""), str(record.get("authority_kind") or ""))
        if not unit_key[0] or not unit_key[1]:
            continue
        if record.get("verification_ok"):
            if unit_key in valid_intakes_by_unit:
                duplicate_valid_units.add(unit_key)
            else:
                valid_intakes_by_unit[unit_key] = record
        else:
            invalid_intakes_by_unit.setdefault(unit_key, []).append(record)

    rebuilt_units = _external_evidence_owner_fulfillment_closure_manifest_units(rebuilt_manifest)
    reviewed_units: set[tuple[str, str]] = set()
    task_closures: list[dict[str, Any]] = []
    tasks = review.get("task_reviews", [])
    if not isinstance(tasks, list):
        tasks = []
    for task in tasks:
        if not isinstance(task, dict):
            continue
        unit_key = (str(task.get("requirement_id") or ""), str(task.get("authority_kind") or ""))
        if unit_key[0] and unit_key[1]:
            reviewed_units.add(unit_key)
        blockers: list[str] = []
        source_uri = str(task.get("source_uri") or "")
        if task.get("source_uri_status") != "live" or _source_map_is_placeholder_uri(source_uri):
            blockers.append("placeholder-source-uri")
        valid_intake = valid_intakes_by_unit.get(unit_key)
        if unit_key in duplicate_valid_units:
            blockers.append("duplicate-intake")
        if valid_intake is None:
            if invalid_intakes_by_unit.get(unit_key):
                blockers.append("invalid-intake")
            else:
                blockers.append("missing-intake")
        manifest_items = rebuilt_units.get(unit_key, [])
        if not manifest_items:
            blockers.append("missing-manifest-coverage")
        elif valid_intake is not None:
            intake_hash = valid_intake.get("evidence_hash")
            manifest_hashes = {content_hash(item) for item in manifest_items if isinstance(item, dict)}
            if intake_hash not in manifest_hashes:
                blockers.append("manifest-intake-mismatch")
        task_closures.append(
            {
                "task": task.get("task"),
                "owner_hint": task.get("owner_hint"),
                "requirement_id": unit_key[0] or None,
                "authority_kind": unit_key[1] or None,
                "source_uri": source_uri,
                "source_uri_status": "live" if task.get("source_uri_status") == "live" and not _source_map_is_placeholder_uri(source_uri) else "placeholder",
                "intake_id": valid_intake.get("intake_id") if valid_intake else None,
                "intake_evidence_hash": valid_intake.get("evidence_hash") if valid_intake else None,
                "manifest_evidence_count": len(manifest_items),
                "closure_status": _external_evidence_owner_fulfillment_closure_task_status(blockers),
                "blocking_reasons": blockers,
            }
        )

    unmatched_intakes: list[dict[str, Any]] = []
    for record in intake_records:
        unit_key = (str(record.get("requirement_id") or ""), str(record.get("authority_kind") or ""))
        if unit_key[0] and unit_key[1] and unit_key not in reviewed_units:
            unmatched_intakes.append(
                {
                    "intake_id": record.get("intake_id"),
                    "unit_ref": record.get("unit_ref"),
                    "verification_ok": record.get("verification_ok"),
                }
            )

    closed_task_count = sum(1 for task in task_closures if task.get("closure_status") == "closed")
    task_count = len(task_closures)
    placeholder_count = sum(1 for task in task_closures if "placeholder-source-uri" in task.get("blocking_reasons", []))
    missing_intake_count = sum(1 for task in task_closures if "missing-intake" in task.get("blocking_reasons", []))
    invalid_intake_task_count = sum(1 for task in task_closures if "invalid-intake" in task.get("blocking_reasons", []))
    duplicate_intake_task_count = sum(1 for task in task_closures if "duplicate-intake" in task.get("blocking_reasons", []))
    missing_manifest_count = sum(1 for task in task_closures if "missing-manifest-coverage" in task.get("blocking_reasons", []))
    manifest_mismatch_count = sum(1 for task in task_closures if "manifest-intake-mismatch" in task.get("blocking_reasons", []))
    invalid_intake_receipt_count = sum(1 for record in intake_records if not record.get("verification_ok"))
    source_error_count = len(verification_errors) + sum(len(record.get("errors", [])) for record in intake_records)
    if closed_task_count == task_count and source_error_count == 0:
        closure_status = "closed"
    elif closed_task_count:
        closure_status = "partial"
    else:
        closure_status = "blocked"

    summary = {
        "closure_status": closure_status,
        "task_count": task_count,
        "closed_task_count": closed_task_count,
        "blocked_task_count": task_count - closed_task_count,
        "placeholder_source_uri_count": placeholder_count,
        "live_source_uri_count": task_count - placeholder_count,
        "intake_receipt_count": len(intake_records),
        "valid_intake_receipt_count": len([record for record in intake_records if record.get("verification_ok")]),
        "invalid_intake_receipt_count": invalid_intake_receipt_count,
        "missing_intake_count": missing_intake_count,
        "invalid_intake_task_count": invalid_intake_task_count,
        "duplicate_intake_task_count": duplicate_intake_task_count,
        "missing_manifest_coverage_count": missing_manifest_count,
        "manifest_intake_mismatch_count": manifest_mismatch_count,
        "unmatched_intake_count": len(unmatched_intakes),
        "source_error_count": source_error_count,
        "source_warning_count": len(verification_warnings) + sum(len(record.get("warnings", [])) for record in intake_records),
    }
    blockers: list[str] = []
    if source_error_count:
        blockers.append("source artifacts or intake receipts do not verify")
    if placeholder_count:
        blockers.append(f"{placeholder_count} reviewed tasks still use placeholder source_uri values")
    if missing_intake_count:
        blockers.append(f"{missing_intake_count} reviewed tasks do not have intake receipts")
    if invalid_intake_task_count:
        blockers.append(f"{invalid_intake_task_count} reviewed tasks have invalid intake receipts")
    if duplicate_intake_task_count:
        blockers.append(f"{duplicate_intake_task_count} reviewed tasks have duplicate valid intake receipts")
    if missing_manifest_count:
        blockers.append(f"{missing_manifest_count} reviewed tasks are not covered by the rebuilt manifest")
    if manifest_mismatch_count:
        blockers.append(f"{manifest_mismatch_count} reviewed tasks have rebuilt manifest evidence that does not match the intake receipt")
    if unmatched_intakes:
        blockers.append(f"{len(unmatched_intakes)} intake receipts are outside the reviewed owner task set")

    body = {
        "schema": EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_CLOSURE_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "verification_options": {
            "require_fresh": require_fresh,
            "require_live_source_uris": require_live_source_uris,
            "require_source_snapshot_artifacts": require_source_snapshot_artifacts,
            "require_fresh_source_snapshot_artifacts": require_fresh_source_snapshot_artifacts,
            "now": now,
        },
        "sources": {
            "owner_fulfillment_review": _external_evidence_review_source_record(review, "owner_fulfillment_review_id", "owner_fulfillment_review_hash"),
            "owner_packet_status": _external_evidence_review_source_record(status_report, "owner_packet_status_id", "owner_packet_status_hash"),
            "rebuilt_manifest": _external_evidence_review_source_record(rebuilt_manifest, "manifest_id", "manifest_hash"),
            "source_manifest": _external_evidence_review_source_record(source_manifest, "manifest_id", "manifest_hash"),
            "collection_plan": _external_evidence_review_source_record(plan, "plan_id", "plan_hash"),
            "roadmap_audit": _external_evidence_review_source_record(roadmap_audit, "audit_id", "audit_hash"),
        },
        "summary": summary,
        "task_closures": task_closures,
        "intake_receipts": intake_records,
        "unmatched_intakes": unmatched_intakes,
        "verification": {
            "ok": source_error_count == 0,
            "errors": verification_errors,
            "warnings": verification_warnings,
            "error_count": len(verification_errors),
            "warning_count": len(verification_warnings),
        },
        "blockers": blockers,
        "next_actions": _external_evidence_owner_fulfillment_closure_next_actions(summary),
        "commands": {
            "collect_after_ready_review": "python -m trustai external-evidence-collect-batch <fulfilled-source-map.json> <manifest.json> <roadmap-audit.json> --root . --require-live-source-uris",
            "rebuild_manifest_after_intakes": "python -m trustai external-evidence-manifest-from-intakes <plan.json> <source-manifest.json> <roadmap-audit.json> --intake-dir <intake-dir> --require-live-source-uris --require-source-snapshot-artifacts --out <rebuilt-manifest.json>",
            "verify_closure": "python -m trustai external-evidence-owner-fulfillment-closure-verify <closure.json> <review.json> <status-report.json> <rebuilt-manifest.json> <source-manifest.json> <plan.json> <roadmap-audit.json> --require-closed",
        },
        "limitations": [
            "This closure report proves whether owner-reviewed evidence tasks are closed by verified intake receipts and rebuilt manifest coverage; it does not collect missing authority evidence by itself.",
            "A closed owner fulfillment still requires production readiness verification before external authority coverage can be claimed for the roadmap.",
            "Placeholder source URIs, missing intakes, invalid intakes, or missing rebuilt manifest coverage keep reviewed tasks blocked.",
        ],
    }
    return {**body, "owner_fulfillment_closure_id": content_hash(body)}


def verify_external_evidence_owner_fulfillment_closure(
    closure: dict[str, Any],
    review: dict[str, Any],
    status_report: dict[str, Any],
    rebuilt_manifest: dict[str, Any],
    source_manifest: dict[str, Any],
    plan: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path = ".",
    intakes: list[dict[str, Any]] | None = None,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_source_snapshot_artifacts: bool = False,
    require_fresh_source_snapshot_artifacts: bool = False,
    now: str | None = None,
    require_closed: bool = False,
) -> ExternalEvidenceOwnerFulfillmentClosureVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if closure.get("schema") != EXTERNAL_EVIDENCE_OWNER_FULFILLMENT_CLOSURE_SCHEMA:
        errors.append(f"unsupported external evidence owner fulfillment closure schema: {closure.get('schema')}")
    if closure.get("owner_fulfillment_closure_id") != content_hash(without_keys(closure, "owner_fulfillment_closure_id")):
        errors.append("owner_fulfillment_closure_id does not match canonical owner fulfillment closure body")
    expected_options = {
        "require_fresh": require_fresh,
        "require_live_source_uris": require_live_source_uris,
        "require_source_snapshot_artifacts": require_source_snapshot_artifacts,
        "require_fresh_source_snapshot_artifacts": require_fresh_source_snapshot_artifacts,
        "now": now,
    }
    if closure.get("verification_options") != expected_options:
        errors.append("verification_options do not match verifier options")
    expected = build_external_evidence_owner_fulfillment_closure(
        review,
        status_report,
        rebuilt_manifest,
        source_manifest,
        plan,
        roadmap_audit,
        root=root,
        intakes=intakes or [],
        require_fresh=require_fresh,
        require_live_source_uris=require_live_source_uris,
        require_source_snapshot_artifacts=require_source_snapshot_artifacts,
        require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
        now=now,
        generated_at=str(closure.get("generated_at") or ""),
    )
    if without_keys(closure, "owner_fulfillment_closure_id") != without_keys(expected, "owner_fulfillment_closure_id"):
        errors.append("owner fulfillment closure body does not match supplied review, status report, manifests, plan, roadmap audit, and intakes")
    expected_warnings = expected.get("verification", {}).get("warnings", [])
    if isinstance(expected_warnings, list):
        warnings.extend(str(warning) for warning in expected_warnings)
    for record in expected.get("intake_receipts", []):
        if isinstance(record, dict):
            record_warnings = record.get("warnings", [])
            if isinstance(record_warnings, list):
                warnings.extend(str(warning) for warning in record_warnings)
    summary = closure.get("summary", {}) if isinstance(closure.get("summary"), dict) else {}
    if summary.get("placeholder_source_uri_count"):
        warnings.append(f"owner fulfillment closure contains {summary.get('placeholder_source_uri_count')} placeholder source_uri values")
    if require_closed and summary.get("closure_status") != "closed":
        errors.append(
            "owner fulfillment is not closed: "
            f"closed_tasks={summary.get('closed_task_count', 0)}, "
            f"blocked_tasks={summary.get('blocked_task_count', 0)}, "
            f"missing_intakes={summary.get('missing_intake_count', 0)}, "
            f"missing_manifest_coverage={summary.get('missing_manifest_coverage_count', 0)}"
        )
    return ExternalEvidenceOwnerFulfillmentClosureVerification(ok=not errors, errors=errors, warnings=warnings)


def _external_evidence_readiness_check(check_id: str, ok: bool, summary: str) -> dict[str, Any]:
    return {"id": check_id, "status": "passed" if ok else "failed", "summary": summary}


def _external_evidence_readiness_count(summary: dict[str, Any], key: str) -> int:
    value = summary.get(key)
    return value if isinstance(value, int) else 0


def _external_evidence_item_unit_ref(item: dict[str, Any]) -> str:
    requirement_id = str(item.get("requirement_id") or "").strip()
    authority_kind = str(item.get("authority_kind") or "").strip()
    return f"{requirement_id}:{authority_kind}" if requirement_id and authority_kind else ""


def _external_evidence_decode_snapshot_body(document: dict[str, Any]) -> Any:
    if document.get("schema") != EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA:
        return None
    body_base64 = document.get("body_base64")
    if not isinstance(body_base64, str) or not body_base64:
        return None
    try:
        body_bytes = base64.b64decode(body_base64.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        return None
    try:
        return json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _external_evidence_non_production_reasons(document: Any) -> list[str]:
    try:
        serialized = json.dumps(document, sort_keys=True).lower()
    except (TypeError, ValueError):
        serialized = str(document).lower()
    markers = {
        "recorded-example": "recorded example",
        "not-live-run": "not a live run",
        "checked-in fixture": "checked-in fixture",
        "file-copy": "retained file-copy snapshot",
        "git-ls-remote": "retained git remote snapshot",
        "demonstrates manifest hashing only": "manifest-hashing fixture",
        "production evidence must replace": "requires production replacement",
        "passed-reference-export": "reference authority export",
        "accepted-for-reference": "reference authority export",
        "reference deployment": "reference deployment",
        "reference acceptance": "reference acceptance",
        "reference review": "reference review",
        "reference underwriting": "reference underwriting",
        "reference-template": "reference template review",
        "reference-customer-review": "reference customer review",
        "reference-ci-run": "reference CI run",
        "reference-kms-hsm-export": "reference KMS/HSM export",
        "trustai-reference": "reference environment",
        "customers.example": "example customer authority",
        "insurer.example": "example insurer authority",
        "regulator.example": "example regulator authority",
        "trustai.example": "example TrustAI service authority",
        "idp.example": "example identity-provider authority",
        "kms.example": "example KMS/HSM authority",
        "not a live customer": "not a live customer record",
        "no live customer": "no live customer deployment",
        "no live policy": "no live policy issuance",
        "no binding premium": "no binding premium discount",
        "not a named customer": "not a named customer record",
        "fresh tenant-specific authority exports are required": "requires fresh tenant authority exports",
        "fresh report and certificate references": "requires fresh certification references",
    }
    return [reason for marker, reason in markers.items() if marker in serialized]


def _external_evidence_item_production_reasons(item: dict[str, Any], *, root: str | Path) -> list[str]:
    artifact_path = str(item.get("path") or "").strip()
    if not artifact_path:
        return ["missing artifact path"]
    try:
        resolved = _resolve_evidence_item_artifact_path(root, artifact_path)
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"artifact not inspectable: {exc}"]
    reasons = _external_evidence_non_production_reasons(document)
    snapshot_body = _external_evidence_decode_snapshot_body(document) if isinstance(document, dict) else None
    if snapshot_body is not None:
        reasons.extend(_external_evidence_non_production_reasons(snapshot_body))
    return sorted(set(reasons))


def _external_evidence_production_usability(manifest: dict[str, Any], *, root: str | Path) -> dict[str, Any]:
    unit_items: dict[str, list[dict[str, Any]]] = {}
    for item in manifest.get("evidence", []):
        if isinstance(item, dict):
            unit_ref = _external_evidence_item_unit_ref(item)
            if unit_ref:
                unit_items.setdefault(unit_ref, []).append(item)

    non_production_units: list[dict[str, Any]] = []
    production_usable_units: list[str] = []
    for unit_ref, items in sorted(unit_items.items()):
        item_reasons = []
        for item in items:
            reasons = _external_evidence_item_production_reasons(item, root=root)
            if reasons:
                item_reasons.append({"evidence_id": item.get("evidence_id"), "path": item.get("path"), "reasons": reasons})
        if item_reasons and len(item_reasons) == len(items):
            non_production_units.append({"unit_ref": unit_ref, "items": item_reasons})
        else:
            production_usable_units.append(unit_ref)

    return {
        "covered_unit_count": len(unit_items),
        "production_usable_unit_refs": production_usable_units,
        "non_production_units": non_production_units,
        "production_usable_covered_authority_kind_count": len(production_usable_units),
        "non_production_covered_authority_kind_count": len(non_production_units),
    }


def build_external_evidence_readiness_report(
    gap_report: dict[str, Any],
    manifest: dict[str, Any],
    plan: dict[str, Any],
    source_map: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    work_package: dict[str, Any] | None = None,
    require_fresh: bool = False,
    now: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    manifest_result = verify_external_evidence_manifest(manifest, roadmap_audit, root=root, require_fresh=require_fresh, now=now)
    plan_result = verify_external_evidence_collection_plan(plan, manifest, roadmap_audit, root=root)
    source_map_result = verify_external_evidence_source_map_template(source_map, plan, root=root)
    gap_result = verify_external_evidence_gap_report(gap_report, manifest, plan, source_map, roadmap_audit, root=root, require_fresh=require_fresh, now=now)
    work_result = None
    if work_package is not None:
        work_result = verify_external_evidence_work_package(work_package, gap_report, manifest, plan, source_map, roadmap_audit, root=root)

    errors: list[str] = []
    warnings: list[str] = []
    for label, result in (("manifest", manifest_result), ("collection plan", plan_result), ("source map", source_map_result), ("gap report", gap_result)):
        errors.extend(f"{label}: {error}" for error in result.errors)
        warnings.extend(f"{label}: {warning}" for warning in result.warnings)
    if work_result is not None:
        errors.extend(f"work package: {error}" for error in work_result.errors)
        warnings.extend(f"work package: {warning}" for warning in work_result.warnings)

    manifest_summary = manifest.get("summary", {}) if isinstance(manifest.get("summary"), dict) else {}
    gap_summary = gap_report.get("summary", {}) if isinstance(gap_report.get("summary"), dict) else {}
    work_summary = work_package.get("summary", {}) if isinstance(work_package, dict) and isinstance(work_package.get("summary"), dict) else {}
    missing_authority = _external_evidence_readiness_count(gap_summary, "missing_authority_kind_count")
    remaining_tasks = _external_evidence_readiness_count(gap_summary, "remaining_task_count")
    placeholder_uris = _external_evidence_readiness_count(gap_summary, "placeholder_source_uri_count")
    work_tasks = _external_evidence_readiness_count(work_summary, "task_count")
    work_packages = _external_evidence_readiness_count(work_summary, "package_count")
    production_usability = _external_evidence_production_usability(manifest, root=root)
    non_production_covered = production_usability["non_production_covered_authority_kind_count"]

    blockers: list[str] = []
    if errors:
        blockers.append("underlying external-evidence artifacts do not verify")
    if non_production_covered:
        blockers.append(f"{non_production_covered} covered authority units use example or non-production evidence")
    if missing_authority:
        blockers.append(f"{missing_authority} authority units still lack accepted evidence")
    if remaining_tasks:
        blockers.append(f"{remaining_tasks} external evidence collection tasks remain open")
    if placeholder_uris:
        blockers.append(f"{placeholder_uris} source-map entries still use placeholder source URIs")
    if work_package is None and remaining_tasks:
        blockers.append("remaining tasks are not bound to a current work package")
    if work_package is not None and work_tasks != remaining_tasks:
        blockers.append("work package task count does not match gap report remaining task count")
    status = "ready" if not blockers else "not-ready"

    body = {
        "schema": EXTERNAL_EVIDENCE_READINESS_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "readiness_status": status,
        "sources": {
            "gap_report": _gap_report_source_record(gap_report, "gap_report_id", "gap_report_hash"),
            "manifest": _gap_report_source_record(manifest, "manifest_id", "manifest_hash"),
            "collection_plan": _gap_report_source_record(plan, "plan_id", "plan_hash"),
            "source_map": _gap_report_source_record(source_map, "source_map_id", "source_map_hash"),
            "roadmap_audit": _gap_report_source_record(roadmap_audit, "audit_id", "audit_hash"),
        },
        "summary": {
            "readiness_status": status,
            "required_requirement_count": _external_evidence_readiness_count(manifest_summary, "required_requirement_count"),
            "covered_requirement_count": _external_evidence_readiness_count(manifest_summary, "covered_requirement_count"),
            "missing_requirement_count": _external_evidence_readiness_count(gap_summary, "missing_requirement_count"),
            "required_authority_kind_count": _external_evidence_readiness_count(gap_summary, "required_authority_kind_count"),
            "covered_authority_kind_count": _external_evidence_readiness_count(gap_summary, "covered_authority_kind_count"),
            "production_usable_covered_authority_kind_count": production_usability["production_usable_covered_authority_kind_count"],
            "non_production_covered_authority_kind_count": non_production_covered,
            "missing_authority_kind_count": missing_authority,
            "remaining_task_count": remaining_tasks,
            "source_map_entry_count": _external_evidence_readiness_count(gap_summary, "source_map_entry_count"),
            "placeholder_source_uri_count": placeholder_uris,
            "live_source_uri_count": _external_evidence_readiness_count(gap_summary, "live_source_uri_count"),
            "work_package_count": work_packages,
            "work_package_task_count": work_tasks,
            "blocking_issue_count": len(blockers),
        },
        "checks": [
            _external_evidence_readiness_check("artifacts-verify", not errors, "All referenced external-evidence artifacts verify."),
            _external_evidence_readiness_check("covered-evidence-production-usable", non_production_covered == 0, "Covered authority units use production authority evidence rather than retained examples or fixtures."),
            _external_evidence_readiness_check("authority-coverage-complete", missing_authority == 0, "Every required authority unit has accepted evidence."),
            _external_evidence_readiness_check("collection-work-closed", remaining_tasks == 0, "No external-evidence collection tasks remain open."),
            _external_evidence_readiness_check("source-map-live", placeholder_uris == 0, "Every source-map entry has a live authority source URI."),
            _external_evidence_readiness_check("work-package-current", work_package is not None and work_tasks == remaining_tasks, "The work package covers the current remaining task set."),
        ],
        "blockers": blockers,
        "non_production_covered_authority_units": production_usability["non_production_units"],
        "next_actions": [
            "Replace retained/example authority evidence with production authority exports, assign owner work packages, replace TODO source URIs with authority-owned sources, collect snapshots and intake receipts, rebuild the manifest, and rerun readiness with --require-ready."
            if blockers else
            "Append the complete external-evidence manifest to the roadmap evidence chain and publish the proof bundle."
        ],
        "verification_options": {"require_fresh": require_fresh, "now": now},
        "verification": {"ok": not errors, "error_count": len(errors), "warning_count": len(warnings), "errors": errors, "warnings": warnings},
        "limitations": [
            "This readiness report proves production external-evidence completeness; it does not collect missing authority evidence by itself.",
            "A not-ready status is expected until every roadmap authority unit has live source evidence, source snapshots, intake receipts, and a rebuilt manifest.",
        ],
    }
    if work_package is not None:
        body["sources"]["work_package"] = _gap_report_source_record(work_package, "work_package_id", "work_package_hash")
    return {**body, "readiness_id": content_hash(body)}


def verify_external_evidence_readiness_report(
    report: dict[str, Any],
    gap_report: dict[str, Any],
    manifest: dict[str, Any],
    plan: dict[str, Any],
    source_map: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    work_package: dict[str, Any] | None = None,
    require_ready: bool = False,
) -> ExternalEvidenceReadinessVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if report.get("schema") != EXTERNAL_EVIDENCE_READINESS_SCHEMA:
        errors.append(f"unsupported external evidence readiness schema: {report.get('schema')}")
    if report.get("readiness_id") != content_hash(without_keys(report, "readiness_id")):
        errors.append("readiness_id does not match canonical readiness body")
    options = report.get("verification_options", {}) if isinstance(report.get("verification_options"), dict) else {}
    expected = build_external_evidence_readiness_report(
        gap_report,
        manifest,
        plan,
        source_map,
        roadmap_audit,
        root=root,
        work_package=work_package,
        require_fresh=bool(options.get("require_fresh")),
        now=options.get("now"),
        generated_at=str(report.get("generated_at") or ""),
    )
    if without_keys(report, "readiness_id") != without_keys(expected, "readiness_id"):
        errors.append("readiness report body does not match supplied external-evidence artifacts")
    expected_warnings = expected.get("verification", {}).get("warnings", [])
    if isinstance(expected_warnings, list):
        warnings.extend(str(warning) for warning in expected_warnings)
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    if require_ready and summary.get("readiness_status") != "ready":
        errors.append(
            "external evidence is not production-ready: "
            f"remaining_tasks={summary.get('remaining_task_count', 0)}, "
            f"missing_authority_units={summary.get('missing_authority_kind_count', 0)}, "
            f"placeholder_source_uris={summary.get('placeholder_source_uri_count', 0)}, "
            f"non_production_covered_authority_units={summary.get('non_production_covered_authority_kind_count', 0)}"
        )
    return ExternalEvidenceReadinessVerification(ok=not errors, errors=errors, warnings=warnings)


def _production_replacement_plan_task(
    readiness_unit: dict[str, Any],
    manifest_unit: dict[str, Any],
    evidence_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    unit_ref = str(readiness_unit.get("unit_ref") or manifest_unit.get("unit_ref") or "")
    if ":" in unit_ref:
        fallback_requirement_id, fallback_authority_kind = unit_ref.split(":", 1)
    else:
        fallback_requirement_id, fallback_authority_kind = "", "other"
    requirement_id = str(manifest_unit.get("requirement_id") or fallback_requirement_id)
    authority_kind = str(manifest_unit.get("authority_kind") or fallback_authority_kind)
    unit_id = str(manifest_unit.get("unit_id") or _authority_unit_id(requirement_id, authority_kind))
    base_task = _authority_collection_task(
        {
            "unit_id": unit_id,
            "unit_ref": unit_ref,
            "requirement_id": requirement_id,
            "phase": manifest_unit.get("phase"),
            "priority": manifest_unit.get("priority"),
            "title": manifest_unit.get("title"),
            "authority_kind": authority_kind,
            "coverage_status": "covered",
            "external_authority_required": manifest_unit.get("external_authority_required", []),
        }
    )
    items = readiness_unit.get("items", [])
    if not isinstance(items, list):
        items = []
    evidence_ids = sorted({str(item.get("evidence_id") or "") for item in items if isinstance(item, dict) and item.get("evidence_id")})
    retained_paths = sorted({str(item.get("path") or "") for item in items if isinstance(item, dict) and item.get("path")})
    reasons = sorted(
        {
            str(reason)
            for item in items
            if isinstance(item, dict)
            for reason in item.get("reasons", [])
            if str(reason)
        }
    )
    retained_source_uris = sorted(
        {
            str(evidence_by_id[evidence_id].get("source_uri") or "")
            for evidence_id in evidence_ids
            if evidence_id in evidence_by_id and evidence_by_id[evidence_id].get("source_uri")
        }
    )
    suggested_artifact_path = f"external-evidence/production/{requirement_id}/{authority_kind}.json"
    description = f"production {authority_kind} evidence for {requirement_id}"
    return {
        "task_id": content_hash({"task_kind": "external-authority-production-replacement", "unit_id": unit_id, "unit_ref": unit_ref}),
        "task_ref": f"external-evidence-production-replacement:{unit_ref}",
        "collection_task_ref": base_task.get("task_ref"),
        "unit_id": unit_id,
        "unit_ref": unit_ref,
        "requirement_id": requirement_id,
        "phase": manifest_unit.get("phase"),
        "priority": manifest_unit.get("priority"),
        "title": manifest_unit.get("title"),
        "authority_kind": authority_kind,
        "coverage_status": "non-production-covered",
        "replacement_status": "requires-production-authority",
        "owner_hint": base_task.get("owner_hint"),
        "suggested_artifact_path": suggested_artifact_path,
        "evidence_argument_template": (
            f"{requirement_id},{authority_kind},{suggested_artifact_path},{description}"
            ";issuer=<live-authority-issuer>;subject=<named-production-subject>;source_uri=<authority-owned-source-uri>;issued_at=<rfc3339>;expires_at=<rfc3339>"
        ),
        "suggested_evidence_sources": base_task.get("suggested_evidence_sources", []),
        "external_authority_required": manifest_unit.get("external_authority_required", []),
        "replaces_evidence_ids": evidence_ids,
        "replaces_artifacts": retained_paths,
        "retained_source_uris": retained_source_uris,
        "non_production_reasons": reasons,
        "acceptance_criteria": [
            "Replacement artifact must come from a live authority-owned source, not a retained fixture, checked-in example, or reference export.",
            f"Evidence item authority_kind must be {authority_kind} and accepted for {requirement_id}.",
            "Source snapshot and intake receipt must verify with freshness and source-snapshot artifact checks enabled.",
            "Rebuild the external evidence manifest and rerun external-evidence-readiness with --require-ready before claiming production authority coverage.",
        ],
        "next_actions": [
            "Collect a fresh source snapshot from the named external authority for this unit.",
            "Create and verify an intake receipt that maps the snapshot to the matching collection task.",
            "Replace the retained/reference evidence item in the manifest with the production authority artifact.",
            "Regenerate retained readiness and this replacement plan; this task closes only when it disappears from the plan.",
        ],
    }


def build_external_evidence_production_replacement_plan(
    readiness: dict[str, Any],
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    group_by: str = "owner_hint",
    generated_at: str | None = None,
) -> dict[str, Any]:
    if group_by not in EXTERNAL_EVIDENCE_WORK_PACKAGE_GROUP_BY:
        raise ValueError(f"unsupported external evidence production replacement group_by: {group_by}")
    if readiness.get("schema") != EXTERNAL_EVIDENCE_READINESS_SCHEMA:
        raise ValueError(f"unsupported external evidence readiness schema: {readiness.get('schema')}")
    if readiness.get("readiness_id") != content_hash(without_keys(readiness, "readiness_id")):
        raise ValueError("readiness_id does not match canonical readiness body")
    manifest_result = verify_external_evidence_manifest(manifest, roadmap_audit, root=root)
    if not manifest_result.ok:
        raise ValueError("invalid source external evidence manifest: " + "; ".join(manifest_result.errors))

    units = manifest.get("required_authority_evidence_units", [])
    if not isinstance(units, list):
        raise ValueError("required_authority_evidence_units must be a list")
    unit_by_ref = {
        str(unit.get("unit_ref") or ""): unit
        for unit in units
        if isinstance(unit, dict) and unit.get("unit_ref")
    }
    evidence_by_id = {
        str(item.get("evidence_id") or ""): item
        for item in manifest.get("evidence", [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    readiness_units = readiness.get("non_production_covered_authority_units", [])
    if not isinstance(readiness_units, list):
        raise ValueError("readiness non_production_covered_authority_units must be a list")

    tasks: list[dict[str, Any]] = []
    for index, readiness_unit in enumerate(readiness_units):
        if not isinstance(readiness_unit, dict):
            raise ValueError(f"readiness non-production unit {index} must be an object")
        unit_ref = str(readiness_unit.get("unit_ref") or "")
        manifest_unit = unit_by_ref.get(unit_ref)
        if manifest_unit is None:
            raise ValueError(f"readiness non-production unit is not present in manifest authority units: {unit_ref}")
        tasks.append(_production_replacement_plan_task(readiness_unit, manifest_unit, evidence_by_id))
    tasks.sort(key=_external_evidence_work_package_task_sort_key)

    grouped: dict[str, list[dict[str, Any]]] = {}
    for task in tasks:
        group_key = str(task.get(group_by) or "unknown")
        grouped.setdefault(group_key, []).append(task)

    packages = []
    for group_key in sorted(grouped):
        package_tasks = grouped[group_key]
        package_body = {
            "package_ref": f"{group_by}:{_source_map_path_segment(group_key)}",
            "group_by": group_by,
            "group_key": group_key,
            group_by: group_key,
            "task_count": len(package_tasks),
            "authority_kinds": _external_evidence_work_package_values(package_tasks, "authority_kind"),
            "requirement_ids": _external_evidence_work_package_values(package_tasks, "requirement_id"),
            "phases": _external_evidence_work_package_values(package_tasks, "phase"),
            "priorities": _external_evidence_work_package_values(package_tasks, "priority"),
            "tasks": package_tasks,
        }
        packages.append({**package_body, "package_id": content_hash(package_body)})

    readiness_summary = readiness.get("summary", {}) if isinstance(readiness.get("summary"), dict) else {}
    body = {
        "schema": EXTERNAL_EVIDENCE_PRODUCTION_REPLACEMENT_PLAN_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "group_by": group_by,
        "sources": {
            "readiness": _gap_report_source_record(readiness, "readiness_id", "readiness_hash"),
            "manifest": _gap_report_source_record(manifest, "manifest_id", "manifest_hash"),
            "roadmap_audit": _gap_report_source_record(roadmap_audit, "audit_id", "audit_hash"),
        },
        "summary": {
            "readiness_status": readiness_summary.get("readiness_status"),
            "required_authority_kind_count": readiness_summary.get("required_authority_kind_count", 0),
            "covered_authority_kind_count": readiness_summary.get("covered_authority_kind_count", 0),
            "production_usable_covered_authority_kind_count": readiness_summary.get("production_usable_covered_authority_kind_count", 0),
            "non_production_covered_authority_kind_count": readiness_summary.get("non_production_covered_authority_kind_count", 0),
            "replacement_status": "open" if tasks else "not-needed",
            "package_count": len(packages),
            "task_count": len(tasks),
            "replaced_artifact_count": len({path for task in tasks for path in task.get("replaces_artifacts", [])}),
            "task_count_by_owner_hint": _gap_report_group_counts(tasks, "owner_hint"),
            "task_count_by_authority_kind": _gap_report_group_counts(tasks, "authority_kind"),
            "task_count_by_phase": _gap_report_group_counts(tasks, "phase"),
            "task_count_by_priority": _gap_report_group_counts(tasks, "priority"),
            "task_count_by_requirement": _gap_report_group_counts(tasks, "requirement_id"),
            "task_count_by_package": {package["package_ref"]: package["task_count"] for package in packages},
        },
        "packages": packages,
        "tasks": tasks,
        "limitations": [
            "This plan identifies retained/reference authority evidence that must be replaced; it does not collect live authority evidence by itself.",
            "A replacement task closes only when the retained evidence item is replaced by a live authority source snapshot, intake receipt, rebuilt manifest entry, and ready readiness report.",
            "Keep retained examples for demo verification, but do not treat them as production authority evidence.",
        ],
    }
    return {**body, "replacement_plan_id": content_hash(body)}


def verify_external_evidence_production_replacement_plan(
    plan: dict[str, Any],
    readiness: dict[str, Any],
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
) -> ExternalEvidenceProductionReplacementPlanVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if plan.get("schema") != EXTERNAL_EVIDENCE_PRODUCTION_REPLACEMENT_PLAN_SCHEMA:
        errors.append(f"unsupported external evidence production replacement plan schema: {plan.get('schema')}")
    if plan.get("replacement_plan_id") != content_hash(without_keys(plan, "replacement_plan_id")):
        errors.append("replacement_plan_id does not match canonical production replacement plan body")
    group_by = str(plan.get("group_by") or "")
    if group_by not in EXTERNAL_EVIDENCE_WORK_PACKAGE_GROUP_BY:
        errors.append(f"unsupported external evidence production replacement plan group_by: {group_by}")
    try:
        expected = build_external_evidence_production_replacement_plan(
            readiness,
            manifest,
            roadmap_audit,
            root=root,
            group_by=group_by if group_by in EXTERNAL_EVIDENCE_WORK_PACKAGE_GROUP_BY else "owner_hint",
            generated_at=str(plan.get("generated_at") or ""),
        )
    except ValueError as exc:
        errors.append(str(exc))
    else:
        if without_keys(plan, "replacement_plan_id") != without_keys(expected, "replacement_plan_id"):
            errors.append("production replacement plan body does not match supplied readiness, manifest, and roadmap audit")
    summary = plan.get("summary", {}) if isinstance(plan.get("summary"), dict) else {}
    non_production_count = summary.get("non_production_covered_authority_kind_count")
    task_count = summary.get("task_count")
    if isinstance(non_production_count, int) and isinstance(task_count, int) and non_production_count != task_count:
        errors.append("production replacement plan task count must match non-production covered authority unit count")
    if summary.get("replacement_status") == "open":
        warnings.append(f"production replacement plan has {summary.get('task_count', 0)} open authority-evidence replacement tasks")
    return ExternalEvidenceProductionReplacementPlanVerification(ok=not errors, errors=errors, warnings=warnings)
def build_external_evidence_source_snapshot(
    *,
    source_uri: str,
    body: bytes | str,
    retrieval_method: str,
    issuer: str | None = None,
    subject: str | None = None,
    content_type: str | None = None,
    status_code: int | None = None,
    response_headers: dict[str, Any] | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not source_uri:
        raise ValueError("external evidence source_uri is required")
    if not retrieval_method:
        raise ValueError("external evidence retrieval_method is required")
    body_bytes = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    if not body_bytes:
        raise ValueError("external evidence source snapshot body is required")
    headers = {
        str(key).lower(): str(value)
        for key, value in sorted((response_headers or {}).items(), key=lambda item: str(item[0]).lower())
        if value is not None
    }
    body_record = {
        "schema": EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "source_uri": source_uri,
        "retrieval_method": retrieval_method,
        "issuer": issuer,
        "subject": subject,
        "content_type": content_type,
        "status_code": status_code,
        "response_headers": headers,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "body_sha256": "sha256:" + sha256(body_bytes).hexdigest(),
        "body_size_bytes": len(body_bytes),
        "body_base64": base64.b64encode(body_bytes).decode("ascii"),
        "limitations": [
            "This source snapshot preserves one collected authority response as a hashable artifact; it does not prove that the authority will return the same response later.",
            "Verifier checks cover snapshot integrity, body hash, optional HTTP metadata, and optional freshness metadata.",
            "Use this snapshot as the artifact supplied to external-evidence-intake for the matching collection-plan task.",
        ],
    }
    return {**body_record, "snapshot_id": content_hash(body_record)}


def verify_external_evidence_source_snapshot(
    snapshot: dict[str, Any],
    *,
    require_fresh: bool = False,
    now: str | None = None,
) -> ExternalEvidenceSourceSnapshotVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if snapshot.get("schema") != EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA:
        errors.append(f"unsupported external evidence source snapshot schema: {snapshot.get('schema')}")
    if snapshot.get("snapshot_id") != content_hash(without_keys(snapshot, "snapshot_id")):
        errors.append("snapshot_id does not match canonical source snapshot body")
    if not snapshot.get("source_uri"):
        errors.append("external evidence source snapshot source_uri is required")
    if not snapshot.get("retrieval_method"):
        errors.append("external evidence source snapshot retrieval_method is required")

    status_code = snapshot.get("status_code")
    if status_code is not None and (not isinstance(status_code, int) or status_code < 100 or status_code > 599):
        errors.append("external evidence source snapshot status_code must be an HTTP status code")
    headers = snapshot.get("response_headers")
    if not isinstance(headers, dict):
        errors.append("external evidence source snapshot response_headers must be an object")

    body_base64 = snapshot.get("body_base64")
    body_bytes = b""
    if not isinstance(body_base64, str) or not body_base64:
        errors.append("external evidence source snapshot body_base64 is required")
    else:
        try:
            body_bytes = base64.b64decode(body_base64.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError) as exc:
            errors.append(f"external evidence source snapshot body_base64 invalid: {exc}")
    if body_bytes:
        expected_hash = "sha256:" + sha256(body_bytes).hexdigest()
        if snapshot.get("body_sha256") != expected_hash:
            errors.append("external evidence source snapshot body_sha256 mismatch")
        if snapshot.get("body_size_bytes") != len(body_bytes):
            errors.append("external evidence source snapshot body_size_bytes mismatch")
    elif not errors:
        errors.append("external evidence source snapshot body is empty")

    freshness_now = _freshness_reference(snapshot, now, errors)
    issued_at = _parse_optional_timestamp(snapshot, "issued_at", errors)
    expires_at = _parse_optional_timestamp(snapshot, "expires_at", errors)
    missing_fields = [field for field in ("issued_at", "expires_at") if not snapshot.get(field)]
    if missing_fields:
        _freshness_problem(
            f"external evidence source snapshot freshness metadata missing: {', '.join(missing_fields)}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        errors.append("external evidence source snapshot expires_at must be after issued_at")
    if freshness_now is not None and issued_at is not None and issued_at > freshness_now:
        _freshness_problem(
            f"external evidence source snapshot is not yet issued: {snapshot.get('issued_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if freshness_now is not None and expires_at is not None and expires_at <= freshness_now:
        _freshness_problem(
            f"external evidence source snapshot expired: {snapshot.get('expires_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )

    return ExternalEvidenceSourceSnapshotVerification(ok=not errors, errors=errors, warnings=warnings)

def build_external_evidence_intake(
    plan: dict[str, Any],
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    task_ref: str,
    artifact_path: str,
    description: str,
    issuer: str | None = None,
    subject: str | None = None,
    source_uri: str | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    plan_result = verify_external_evidence_collection_plan(plan, manifest, roadmap_audit, root=root)
    if not plan_result.ok:
        raise ValueError("invalid external evidence collection plan: " + "; ".join(plan_result.errors))
    task = _find_collection_task(plan, task_ref)
    if task is None:
        raise ValueError(f"external evidence collection task not found: {task_ref}")
    if ";" in description:
        raise ValueError("external evidence intake description cannot contain ';' because it is rendered into a CLI evidence argument")

    requirements = _reference_attested_requirements(roadmap_audit)
    required_ids = [requirement["id"] for requirement in requirements]
    required_authority_kinds = {
        requirement["id"]: _allowed_authority_kinds_for_requirement(requirement)
        for requirement in requirements
    }
    evidence_input = {
        "requirement_id": task.get("requirement_id"),
        "authority_kind": task.get("authority_kind"),
        "path": artifact_path,
        "description": description,
        "issuer": issuer,
        "subject": subject,
        "source_uri": source_uri,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    evidence_item = _build_evidence_item(Path(root), evidence_input, required_ids, required_authority_kinds)
    body = {
        "schema": EXTERNAL_EVIDENCE_INTAKE_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "source_plan": _collection_plan_source_record(plan),
        "source_manifest": _collection_intake_manifest_record(manifest),
        "source_roadmap_audit": manifest.get("source_roadmap_audit"),
        "task": _intake_task_record(task),
        "evidence_item": evidence_item,
        "evidence_argument": _evidence_argument(evidence_item),
        "limitations": [
            "This intake receipt hashes and maps one collected artifact to a collection-plan task; it does not itself satisfy roadmap completion.",
            "Coverage is updated only after rebuilding and verifying an external evidence manifest with the emitted evidence argument.",
            "Issuer authority and freshness remain bounded by the collected artifact and manifest verification options.",
        ],
    }
    return {**body, "intake_id": content_hash(body)}


def verify_external_evidence_intake(
    intake: dict[str, Any],
    plan: dict[str, Any],
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_source_snapshot_artifacts: bool = False,
    require_fresh_source_snapshot_artifacts: bool = False,
    now: str | None = None,
) -> ExternalEvidenceIntakeVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if require_fresh_source_snapshot_artifacts and not require_source_snapshot_artifacts:
        errors.append("source snapshot artifact freshness requires source snapshot artifact verification")

    if intake.get("schema") != EXTERNAL_EVIDENCE_INTAKE_SCHEMA:
        errors.append(f"unsupported external evidence intake schema: {intake.get('schema')}")
    if intake.get("intake_id") != content_hash(without_keys(intake, "intake_id")):
        errors.append("intake_id does not match canonical intake body")

    plan_result = verify_external_evidence_collection_plan(plan, manifest, roadmap_audit, root=root)
    warnings.extend(plan_result.warnings)
    if not plan_result.ok:
        errors.extend(f"source plan: {error}" for error in plan_result.errors)

    if intake.get("source_plan") != _collection_plan_source_record(plan):
        errors.append("source_plan does not match supplied collection plan")
    if intake.get("source_manifest") != _collection_intake_manifest_record(manifest):
        errors.append("source_manifest does not match supplied external evidence manifest")
    if intake.get("source_roadmap_audit") != manifest.get("source_roadmap_audit"):
        errors.append("source_roadmap_audit does not match supplied manifest")

    task_record = intake.get("task")
    if not isinstance(task_record, dict):
        errors.append("intake task must be an object")
        task_record = {}
    task = _find_collection_task(plan, str(task_record.get("task_id") or task_record.get("task_ref") or task_record.get("unit_ref") or ""))
    if task is None:
        errors.append("intake task is not present in supplied collection plan")
    else:
        expected_task = _intake_task_record(task)
        if task_record != expected_task:
            errors.append("intake task does not match supplied collection plan")

    evidence_item = intake.get("evidence_item")
    if not isinstance(evidence_item, dict):
        errors.append("intake evidence_item must be an object")
        evidence_item = {}
    if task is not None:
        if evidence_item.get("requirement_id") != task.get("requirement_id"):
            errors.append("intake evidence requirement_id does not match task")
        if evidence_item.get("authority_kind") != task.get("authority_kind"):
            errors.append("intake evidence authority_kind does not match task")

    requirements = _reference_attested_requirements(roadmap_audit)
    required_authority_kinds = {
        requirement["id"]: _allowed_authority_kinds_for_requirement(requirement)
        for requirement in requirements
    }
    freshness_now = _freshness_reference(intake, now, errors)
    _verify_evidence_item(
        Path(root),
        evidence_item,
        errors,
        warnings,
        now=freshness_now,
        require_fresh=require_fresh,
        require_live_source_uris=require_live_source_uris,
        allowed_authority_kinds=required_authority_kinds.get(str(evidence_item.get("requirement_id") or ""), []),
    )
    if require_source_snapshot_artifacts:
        _verify_evidence_item_source_snapshot_artifact(
            Path(root),
            evidence_item,
            errors,
            warnings,
            require_fresh=require_fresh_source_snapshot_artifacts,
            now=now,
        )
    try:
        expected_evidence_argument = _evidence_argument(evidence_item)
    except ValueError as exc:
        expected_evidence_argument = None
        errors.append(str(exc))
    if expected_evidence_argument is not None and intake.get("evidence_argument") != expected_evidence_argument:
        errors.append("evidence_argument does not match intake evidence item")

    return ExternalEvidenceIntakeVerification(ok=not errors, errors=errors, warnings=warnings)


def verify_external_evidence_collection_run(
    collection_run: dict[str, Any],
    plan: dict[str, Any],
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    source_map: dict[str, Any] | None = None,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_fresh_source_snapshot_artifacts: bool = False,
    now: str | None = None,
) -> ExternalEvidenceCollectionRunVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if collection_run.get("schema") != EXTERNAL_EVIDENCE_COLLECTION_RUN_SCHEMA:
        errors.append(f"unsupported external evidence collection run schema: {collection_run.get('schema')}")
    if collection_run.get("run_id") != content_hash(without_keys(collection_run, "run_id")):
        errors.append("run_id does not match canonical collection run body")

    plan_result = verify_external_evidence_collection_plan(plan, manifest, roadmap_audit, root=root_path)
    warnings.extend(plan_result.warnings)
    if not plan_result.ok:
        errors.extend(f"source plan: {error}" for error in plan_result.errors)

    source_map_record = collection_run.get("source_map")
    if not isinstance(source_map_record, dict):
        errors.append("collection run source_map must be an object")
        source_map_record = {}
    elif source_map is not None and source_map_record.get("source_map_hash") != content_hash(source_map):
        errors.append("collection run source_map_hash does not match supplied source map")

    source_map_tasks = _collection_run_source_map_tasks(source_map, errors) if source_map is not None else None

    summary = collection_run.get("summary")
    if not isinstance(summary, dict):
        errors.append("collection run summary must be an object")
        summary = {}

    collected = collection_run.get("collected")
    if not isinstance(collected, list):
        errors.append("collection run collected must be a list")
        collected = []

    seen_tasks: set[str] = set()
    for index, item in enumerate(collected):
        label = f"collection run item {index}"
        if not isinstance(item, dict):
            errors.append(f"{label} must be an object")
            continue

        task = item.get("task")
        if not isinstance(task, str) or not task:
            errors.append(f"{label} task is required")
            task = ""
        elif task in seen_tasks:
            errors.append(f"duplicate collection run task: {task}")
        else:
            seen_tasks.add(task)

        source_uri = item.get("source_uri")
        if not isinstance(source_uri, str) or not source_uri:
            errors.append(f"{label} source_uri is required")
            source_uri = ""

        warnings_value = item.get("warnings", [])
        if not isinstance(warnings_value, list) or any(not isinstance(value, str) for value in warnings_value):
            errors.append(f"{label} warnings must be a list of strings")

        snapshot_artifact_path = item.get("snapshot_artifact_path")
        snapshot_path: Path | None = None
        snapshot: dict[str, Any] = {}
        if not isinstance(snapshot_artifact_path, str) or not snapshot_artifact_path:
            errors.append(f"{label} snapshot_artifact_path is required")
        else:
            try:
                snapshot_path = _resolve_evidence_item_artifact_path(root_path, snapshot_artifact_path)
            except ValueError as exc:
                errors.append(f"{label} snapshot_artifact_path {exc}")
            else:
                if not snapshot_path.is_file():
                    errors.append(f"{label} source snapshot artifact does not exist: {snapshot_artifact_path}")
                else:
                    try:
                        snapshot = load_external_evidence_source_snapshot(snapshot_path)
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                        errors.append(f"{label} source snapshot artifact is not readable: {exc}")
                    else:
                        snapshot_result = verify_external_evidence_source_snapshot(
                            snapshot,
                            require_fresh=require_fresh_source_snapshot_artifacts,
                            now=now,
                        )
                        warnings.extend(f"{label} source snapshot: {warning}" for warning in snapshot_result.warnings)
                        if not snapshot_result.ok:
                            errors.extend(f"{label} source snapshot: {error}" for error in snapshot_result.errors)
                        if item.get("snapshot_id") != snapshot.get("snapshot_id"):
                            errors.append(f"{label} snapshot_id does not match source snapshot artifact")
                        if source_uri and snapshot.get("source_uri") != source_uri:
                            errors.append(f"{label} source snapshot source_uri does not match run source_uri")

        if item.get("snapshot_path"):
            try:
                reported_snapshot_path = _resolve_collection_run_file_path(root_path, item.get("snapshot_path"), f"{label} snapshot_path")
            except ValueError as exc:
                errors.append(str(exc))
            else:
                if snapshot_path is not None and reported_snapshot_path != snapshot_path.resolve():
                    errors.append(f"{label} snapshot_path does not match snapshot_artifact_path")

        intake_path: Path | None = None
        intake: dict[str, Any] = {}
        intake_evidence_item: dict[str, Any] = {}
        try:
            intake_path = _resolve_collection_run_file_path(root_path, item.get("intake_path"), f"{label} intake_path")
        except ValueError as exc:
            errors.append(str(exc))
        else:
            if not intake_path.is_file():
                errors.append(f"{label} intake receipt does not exist: {item.get('intake_path')}")
            else:
                try:
                    intake = load_external_evidence_intake(intake_path)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    errors.append(f"{label} intake receipt is not readable: {exc}")
                else:
                    intake_result = verify_external_evidence_intake(
                        intake,
                        plan,
                        manifest,
                        roadmap_audit,
                        root=root_path,
                        require_fresh=require_fresh,
                        require_live_source_uris=require_live_source_uris,
                        require_source_snapshot_artifacts=True,
                        require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
                        now=now,
                    )
                    warnings.extend(f"{label} intake: {warning}" for warning in intake_result.warnings)
                    if not intake_result.ok:
                        errors.extend(f"{label} intake: {error}" for error in intake_result.errors)
                    if item.get("intake_id") != intake.get("intake_id"):
                        errors.append(f"{label} intake_id does not match intake receipt")
                    if item.get("evidence_argument") != intake.get("evidence_argument"):
                        errors.append(f"{label} evidence_argument does not match intake receipt")
                    evidence_item = intake.get("evidence_item") if isinstance(intake.get("evidence_item"), dict) else {}
                    intake_evidence_item = evidence_item
                    if snapshot_artifact_path and evidence_item.get("path") != snapshot_artifact_path:
                        errors.append(f"{label} intake evidence path does not match snapshot_artifact_path")
                    if source_uri and evidence_item.get("source_uri") != source_uri:
                        errors.append(f"{label} intake source_uri does not match run source_uri")
                    task_record = intake.get("task") if isinstance(intake.get("task"), dict) else {}
                    task_refs = {
                        str(task_record.get("task_id") or ""),
                        str(task_record.get("task_ref") or ""),
                        str(task_record.get("unit_id") or ""),
                        str(task_record.get("unit_ref") or ""),
                    }
                    if task and task not in task_refs:
                        errors.append(f"{label} intake task does not match run task")

        if source_map_tasks is not None and task:
            source_entry = source_map_tasks.get(task)
            if source_entry is None:
                errors.append(f"{label} task is not present in supplied source map: {task}")
            else:
                expected_source_uri = source_entry.get("source_uri")
                if expected_source_uri and source_uri != str(expected_source_uri):
                    errors.append(f"{label} source_uri does not match supplied source map")
                expected_description = source_entry.get("description")
                if expected_description and intake_evidence_item and intake_evidence_item.get("description") != str(expected_description):
                    errors.append(f"{label} intake description does not match supplied source map")
                expected_snapshot_out = source_entry.get("snapshot_out")
                if expected_snapshot_out and snapshot_path is not None:
                    try:
                        expected_snapshot_path = _resolve_source_map_snapshot_path(root_path, str(expected_snapshot_out))
                    except ValueError as exc:
                        errors.append(f"{label} source map snapshot_out {exc}")
                    else:
                        if expected_snapshot_path != snapshot_path.resolve():
                            errors.append(f"{label} snapshot_artifact_path does not match supplied source map snapshot_out")
                expected_intake_out = source_entry.get("intake_out")
                if expected_intake_out and intake_path is not None:
                    try:
                        expected_intake_path = _resolve_collection_run_file_path(root_path, str(expected_intake_out), f"{label} source map intake_out")
                    except ValueError as exc:
                        errors.append(str(exc))
                    else:
                        if expected_intake_path != intake_path.resolve():
                            errors.append(f"{label} intake_path does not match supplied source map intake_out")

    if summary.get("collected_count") != len(collected):
        errors.append("collection run summary collected_count does not match collected items")
    if summary.get("task_count") != len(seen_tasks):
        errors.append("collection run summary task_count does not match unique collected tasks")
    if not isinstance(summary.get("require_fresh"), bool):
        errors.append("collection run summary require_fresh must be a boolean")

    if source_map_tasks is not None:
        source_tasks = set(source_map_tasks)
        missing_tasks = sorted(source_tasks - seen_tasks)
        extra_tasks = sorted(seen_tasks - source_tasks)
        if missing_tasks:
            errors.append("collection run missing supplied source map tasks: " + ", ".join(missing_tasks))
        if extra_tasks:
            errors.append("collection run contains tasks outside supplied source map: " + ", ".join(extra_tasks))

    return ExternalEvidenceCollectionRunVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        collected_count=len(collected),
    )


def build_external_evidence_manifest_from_intakes(
    plan: dict[str, Any],
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    intakes: list[dict[str, Any]],
    manifest_ref: str | None = None,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_source_snapshot_artifacts: bool = False,
    require_fresh_source_snapshot_artifacts: bool = False,
    now: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    manifest_result = verify_external_evidence_manifest(manifest, roadmap_audit, root=root, require_live_source_uris=require_live_source_uris)
    if not manifest_result.ok:
        raise ValueError("invalid source external evidence manifest: " + "; ".join(manifest_result.errors))
    plan_result = verify_external_evidence_collection_plan(plan, manifest, roadmap_audit, root=root)
    if not plan_result.ok:
        raise ValueError("invalid external evidence collection plan: " + "; ".join(plan_result.errors))

    evidence_by_unit: dict[tuple[str, str], dict[str, Any]] = {}
    evidence = manifest.get("evidence", [])
    if not isinstance(evidence, list):
        raise ValueError("source manifest evidence must be a list")
    for item in evidence:
        if not isinstance(item, dict):
            raise ValueError("source manifest evidence item must be an object")
        unit_key = _evidence_unit_key(item)
        if unit_key in evidence_by_unit:
            raise ValueError(f"source manifest has duplicate evidence for authority unit: {unit_key[0]}:{unit_key[1]}")
        evidence_by_unit[unit_key] = item

    seen_intake_units: set[tuple[str, str]] = set()
    for intake in intakes:
        if not isinstance(intake, dict):
            raise ValueError("external evidence intake must be an object")
        intake_result = verify_external_evidence_intake(
            intake,
            plan,
            manifest,
            roadmap_audit,
            root=root,
            require_fresh=require_fresh,
            require_live_source_uris=require_live_source_uris,
            require_source_snapshot_artifacts=require_source_snapshot_artifacts,
            require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
            now=now,
        )
        if not intake_result.ok:
            intake_label = intake.get("intake_id") or intake.get("task", {}).get("unit_ref") or "unknown"
            raise ValueError(f"invalid external evidence intake {intake_label}: " + "; ".join(intake_result.errors))
        evidence_item = intake.get("evidence_item")
        if not isinstance(evidence_item, dict):
            raise ValueError("external evidence intake evidence_item must be an object")
        unit_key = _evidence_unit_key(evidence_item)
        if unit_key in seen_intake_units:
            raise ValueError(f"duplicate intake receipt for authority unit: {unit_key[0]}:{unit_key[1]}")
        seen_intake_units.add(unit_key)
        evidence_by_unit[unit_key] = evidence_item

    requirements = _reference_attested_requirements(roadmap_audit)
    requirement_order = {requirement["id"]: index for index, requirement in enumerate(requirements)}
    authority_order = {authority_kind: index for index, authority_kind in enumerate(AUTHORITY_KIND_ORDER)}
    ordered_evidence = sorted(
        evidence_by_unit.values(),
        key=lambda item: (
            requirement_order.get(str(item.get("requirement_id") or ""), len(requirement_order)),
            authority_order.get(str(item.get("authority_kind") or ""), len(authority_order)),
            str(item.get("path") or ""),
        ),
    )
    rebuilt_manifest = build_external_evidence_manifest(
        roadmap_audit,
        root=root,
        evidence=ordered_evidence,
        manifest_ref=manifest_ref or str(manifest.get("manifest_ref") or "production-external-evidence"),
        generated_at=generated_at,
    )
    rebuilt_result = verify_external_evidence_manifest(
        rebuilt_manifest,
        roadmap_audit,
        root=root,
        require_fresh=require_fresh,
        require_live_source_uris=require_live_source_uris,
        require_source_snapshot_artifacts=require_source_snapshot_artifacts,
        require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
        now=now,
    )
    if not rebuilt_result.ok:
        raise ValueError("invalid rebuilt external evidence manifest: " + "; ".join(rebuilt_result.errors))
    return rebuilt_manifest

def verify_roadmap_evidence_chain(
    chain: EvidenceChain,
    *,
    key: str | None = None,
    require_external: bool = False,
    require_complete: bool = False,
    require_fresh: bool = False,
) -> RoadmapEvidenceChainVerification:
    errors: list[str] = []
    warnings: list[str] = []

    chain_result = chain.verify_all(key=key)
    if not chain_result.ok:
        errors.extend(f"chain: {error}" for error in chain_result.errors)

    audit_entries: list[dict[str, Any]] = []
    audit_by_source: dict[tuple[Any, Any], dict[str, Any]] = {}
    external_entries: list[dict[str, Any]] = []
    collection_run_entries: list[dict[str, Any]] = []
    complete_external_count = 0
    fresh_external_count = 0

    for entry in chain.entries:
        entry_type = entry.get("entry_type")
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            errors.append(f"entry {entry.get('index')} payload must be an object")
            continue
        if entry_type == ROADMAP_AUDIT_ENTRY_TYPE:
            audit_entries.append(entry)
            audit_id = payload.get("audit_id")
            audit_hash = payload.get("audit_hash")
            if not audit_id:
                errors.append(f"roadmap audit entry {entry.get('index')} missing audit_id")
            if not audit_hash:
                errors.append(f"roadmap audit entry {entry.get('index')} missing audit_hash")
            if audit_id and audit_hash:
                audit_by_source[(audit_id, audit_hash)] = entry
        elif entry_type == EXTERNAL_EVIDENCE_ENTRY_TYPE:
            external_entries.append(entry)
        elif entry_type == EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE:
            collection_run_entries.append(entry)

    if not audit_entries:
        errors.append("roadmap evidence chain has no roadmap audit entry")
    if require_external and not external_entries:
        errors.append("roadmap evidence chain has no external evidence entry")

    for entry in external_entries:
        payload = entry.get("payload", {})
        source = payload.get("source_roadmap_audit")
        if not isinstance(source, dict):
            errors.append(f"external evidence entry {entry.get('index')} missing source_roadmap_audit")
            continue
        source_key = (source.get("audit_id"), source.get("audit_hash"))
        audit_entry = audit_by_source.get(source_key)
        if audit_entry is None:
            errors.append(f"external evidence entry {entry.get('index')} source roadmap audit is not chained")
            continue
        if audit_entry.get("index", -1) >= entry.get("index", -1):
            errors.append(f"external evidence entry {entry.get('index')} does not follow its source roadmap audit entry")

        proof = payload.get("source_roadmap_audit_inclusion_proof")
        if not isinstance(proof, dict):
            errors.append(f"external evidence entry {entry.get('index')} missing source roadmap audit inclusion proof")
        else:
            _verify_source_roadmap_audit_inclusion_proof(chain, audit_entry, entry, proof, errors)

        _verify_external_evidence_entry_summary(
            entry,
            errors,
            warnings,
            require_complete=require_complete,
            require_fresh=require_fresh,
        )
        if (
            payload.get("status") == "complete"
            and payload.get("missing_requirement_count") == 0
            and payload.get("missing_authority_kind_count") == 0
        ):
            complete_external_count += 1
        if (
            payload.get("require_fresh") is True
            and payload.get("stale_evidence_count") == 0
            and payload.get("missing_freshness_count") == 0
        ):
            fresh_external_count += 1

    for entry in collection_run_entries:
        payload = entry.get("payload", {})
        source = payload.get("source_roadmap_audit")
        if not isinstance(source, dict):
            errors.append(f"external evidence collection run entry {entry.get('index')} missing source_roadmap_audit")
            continue
        source_key = (source.get("audit_id"), source.get("audit_hash"))
        audit_entry = audit_by_source.get(source_key)
        if audit_entry is None:
            errors.append(f"external evidence collection run entry {entry.get('index')} source roadmap audit is not chained")
            continue
        if audit_entry.get("index", -1) >= entry.get("index", -1):
            errors.append(f"external evidence collection run entry {entry.get('index')} does not follow its source roadmap audit entry")
        proof = payload.get("source_roadmap_audit_inclusion_proof")
        if not isinstance(proof, dict):
            errors.append(f"external evidence collection run entry {entry.get('index')} missing source roadmap audit inclusion proof")
        else:
            _verify_source_roadmap_audit_inclusion_proof(
                chain,
                audit_entry,
                entry,
                proof,
                errors,
                label="external evidence collection run entry",
            )
        _verify_external_evidence_collection_run_entry_summary(entry, errors)

    return RoadmapEvidenceChainVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        audit_entry_count=len(audit_entries),
        external_evidence_entry_count=len(external_entries),
        external_evidence_collection_run_entry_count=len(collection_run_entries),
        complete_external_evidence_entry_count=complete_external_count,
        fresh_external_evidence_entry_count=fresh_external_count,
    )


def build_roadmap_evidence_report(
    chain: EvidenceChain,
    *,
    key: str | None = None,
    require_external: bool = False,
    require_complete: bool = False,
    require_fresh: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    result = verify_roadmap_evidence_chain(
        chain,
        key=key,
        require_external=require_external or require_complete,
        require_complete=require_complete,
        require_fresh=require_fresh,
    )
    body = {
        "schema": ROADMAP_EVIDENCE_REPORT_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "verification_options": {
            "require_external": require_external or require_complete,
            "require_complete": require_complete,
            "require_fresh": require_fresh,
        },
        "chain": _roadmap_evidence_chain_record(chain),
        "summary": _roadmap_evidence_summary(chain, result),
        "verification": _roadmap_evidence_verification_record(result),
        "roadmap_audit_entries": _roadmap_audit_entry_records(chain),
        "external_evidence_entries": _external_evidence_entry_records(chain),
        "external_evidence_collection_run_entries": _external_evidence_collection_run_entry_records(chain),
        "limitations": [
            "This report verifies evidence-chain integrity and roadmap evidence relationships only.",
            "It does not fetch live provider APIs, KMS/HSM systems, TSAs, cloud object-lock stores, regulators, insurers, or standards bodies.",
            "External evidence quality depends on the issuer and artifacts supplied to the chain.",
        ],
    }
    return {**body, "report_id": content_hash(body)}


def verify_roadmap_evidence_report(
    report: dict[str, Any],
    chain: EvidenceChain,
    *,
    key: str | None = None,
    require_external: bool = False,
    require_complete: bool = False,
    require_fresh: bool = False,
) -> RoadmapEvidenceReportVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if report.get("schema") != ROADMAP_EVIDENCE_REPORT_SCHEMA:
        errors.append(f"unsupported roadmap evidence report schema: {report.get('schema')}")
    if report.get("report_id") != content_hash(without_keys(report, "report_id")):
        errors.append("report_id does not match canonical report body")

    expected_options = {
        "require_external": require_external or require_complete,
        "require_complete": require_complete,
        "require_fresh": require_fresh,
    }
    if report.get("verification_options") != expected_options:
        errors.append("verification_options do not match verifier options")

    expected_chain = _roadmap_evidence_chain_record(chain)
    if report.get("chain") != expected_chain:
        errors.append("chain summary does not match supplied evidence chain")

    result = verify_roadmap_evidence_chain(
        chain,
        key=key,
        require_external=require_external or require_complete,
        require_complete=require_complete,
        require_fresh=require_fresh,
    )
    expected_summary = _roadmap_evidence_summary(chain, result)
    if report.get("summary") != expected_summary:
        errors.append("report summary does not match supplied evidence chain")
    expected_verification = _roadmap_evidence_verification_record(result)
    if report.get("verification") != expected_verification:
        errors.append("report verification block does not match supplied evidence chain")
    if report.get("roadmap_audit_entries") != _roadmap_audit_entry_records(chain):
        errors.append("roadmap audit entries do not match supplied evidence chain")
    if report.get("external_evidence_entries") != _external_evidence_entry_records(chain):
        errors.append("external evidence entries do not match supplied evidence chain")
    if report.get("external_evidence_collection_run_entries") != _external_evidence_collection_run_entry_records(chain):
        errors.append("external evidence collection run entries do not match supplied evidence chain")

    warnings.extend(result.warnings)
    if not result.ok:
        errors.extend(f"roadmap evidence chain: {error}" for error in result.errors)

    return RoadmapEvidenceReportVerification(ok=not errors, errors=errors, warnings=warnings)


def build_roadmap_evidence_bundle(
    chain: EvidenceChain,
    *,
    key: str | None = None,
    require_external: bool = False,
    require_complete: bool = False,
    require_fresh: bool = False,
    generated_at: str | None = None,
    report: dict[str, Any] | None = None,
    root: str | Path = ".",
    source_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or utc_now()
    if report is None:
        report = build_roadmap_evidence_report(
            chain,
            key=key,
            require_external=require_external or require_complete,
            require_complete=require_complete,
            require_fresh=require_fresh,
            generated_at=timestamp,
        )
    else:
        report = json.loads(json.dumps(report, sort_keys=True))
    embedded_source_artifacts = _build_bundle_source_artifacts(Path(root), source_artifacts or [])
    body = {
        "schema": ROADMAP_EVIDENCE_BUNDLE_SCHEMA,
        "generated_at": timestamp,
        "verification_options": {
            "require_external": require_external or require_complete,
            "require_complete": require_complete,
            "require_fresh": require_fresh,
        },
        "chain": _roadmap_evidence_chain_document(chain),
        "report": report,
        "source_artifacts": embedded_source_artifacts,
        "summary": _roadmap_evidence_bundle_summary(chain, report, embedded_source_artifacts),
        "limitations": [
            "This bundle is self-contained for offline chain and roadmap evidence verification when all required source artifacts are embedded.",
            "It does not include live provider API, KMS/HSM, TSA, cloud object-lock, regulator, insurer, or standards-body fetches.",
            "External authority claims remain bounded by the evidence entries and artifacts already committed to the bundled chain.",
        ],
    }
    return {**body, "bundle_id": content_hash(body)}


def verify_roadmap_evidence_bundle(
    bundle: dict[str, Any],
    *,
    key: str | None = None,
    require_external: bool = False,
    require_complete: bool = False,
    require_fresh: bool = False,
    require_source_artifacts: bool = False,
) -> RoadmapEvidenceBundleVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if bundle.get("schema") != ROADMAP_EVIDENCE_BUNDLE_SCHEMA:
        errors.append(f"unsupported roadmap evidence bundle schema: {bundle.get('schema')}")
    if bundle.get("bundle_id") != content_hash(without_keys(bundle, "bundle_id")):
        errors.append("bundle_id does not match canonical bundle body")

    expected_options = {
        "require_external": require_external or require_complete,
        "require_complete": require_complete,
        "require_fresh": require_fresh,
    }
    if bundle.get("verification_options") != expected_options:
        errors.append("verification_options do not match verifier options")

    chain = _roadmap_evidence_chain_from_document(bundle.get("chain"), errors)
    report = bundle.get("report")
    if not isinstance(report, dict):
        errors.append("bundle report must be an object")
        report = {}

    if chain is not None:
        report_result = verify_roadmap_evidence_report(
            report,
            chain,
            key=key,
            require_external=require_external or require_complete,
            require_complete=require_complete,
            require_fresh=require_fresh,
        )
        if not report_result.ok:
            errors.extend(f"report: {error}" for error in report_result.errors)
        warnings.extend(report_result.warnings)
        source_artifacts = bundle.get("source_artifacts", [])
        _verify_bundle_source_artifacts(
            chain,
            source_artifacts,
            errors,
            warnings,
            require_source_artifacts=require_source_artifacts,
        )
        expected_summary = _roadmap_evidence_bundle_summary(chain, report, source_artifacts if isinstance(source_artifacts, list) else [])
        if bundle.get("summary") != expected_summary:
            errors.append("bundle summary does not match bundled chain and report")

    return RoadmapEvidenceBundleVerification(ok=not errors, errors=errors, warnings=warnings)


def extract_roadmap_evidence_bundle_sources(
    bundle: dict[str, Any],
    out_dir: str | Path,
    *,
    key: str | None = None,
    require_external: bool = False,
    require_complete: bool = False,
    require_fresh: bool = False,
    require_source_artifacts: bool = False,
    overwrite: bool = False,
) -> list[dict[str, Any]]:
    result = verify_roadmap_evidence_bundle(
        bundle,
        key=key,
        require_external=require_external or require_complete,
        require_complete=require_complete,
        require_fresh=require_fresh,
        require_source_artifacts=require_source_artifacts,
    )
    if not result.ok:
        raise ValueError("invalid roadmap evidence bundle: " + "; ".join(result.errors))

    source_artifacts = bundle.get("source_artifacts", [])
    if not isinstance(source_artifacts, list):
        raise ValueError("bundle source_artifacts must be a list")

    output_root = Path(out_dir)
    extracted: list[dict[str, Any]] = []
    for artifact in source_artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("bundle source artifact must be an object")
        path = artifact.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("bundle source artifact path is required")
        if not _is_safe_relative_path(path):
            raise ValueError(f"bundle source artifact path must be repository-relative: {path}")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"bundle source artifact content_b64 invalid: {path}") from exc
        actual_sha = "sha256:" + sha256(data).hexdigest()
        if artifact.get("sha256") != actual_sha:
            raise ValueError(f"bundle source artifact hash mismatch: {path}")

        target = output_root / Path(path)
        if target.exists():
            if target.is_dir():
                raise ValueError(f"bundle source artifact output path is a directory: {target}")
            if not overwrite:
                raise ValueError(f"bundle source artifact output already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append(
            {
                "kind": artifact.get("kind"),
                "path": path,
                "sha256": actual_sha,
                "bytes": len(data),
                "artifact_id": artifact.get("artifact_id"),
                "extracted_to": str(target),
            }
        )
    return extracted


def append_external_evidence_collection_run(
    chain: EvidenceChain,
    collection_run: dict[str, Any],
    plan: dict[str, Any],
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    source_map: dict[str, Any],
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_fresh_source_snapshot_artifacts: bool = False,
    now: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_external_evidence_collection_run(
        collection_run,
        plan,
        manifest,
        roadmap_audit,
        root=root,
        source_map=source_map,
        require_fresh=require_fresh,
        require_live_source_uris=require_live_source_uris,
        require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid external evidence collection run: " + "; ".join(result.errors))
    source_audit = manifest.get("source_roadmap_audit")
    source_audit_proof = _source_roadmap_audit_proof(chain, source_audit)
    if source_audit_proof is None:
        raise ValueError("source roadmap audit must be appended before collection run")

    summary = collection_run.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    collected = collection_run.get("collected", [])
    if not isinstance(collected, list):
        collected = []
    collected_items = [item for item in collected if isinstance(item, dict)]

    payload = {
        "run_id": collection_run["run_id"],
        "run_hash": content_hash(collection_run),
        "source_map": collection_run.get("source_map"),
        "source_map_hash": content_hash(source_map),
        "source_plan": _collection_plan_source_record(plan),
        "source_manifest": _collection_intake_manifest_record(manifest),
        "source_roadmap_audit": source_audit,
        "source_roadmap_audit_inclusion_proof": source_audit_proof,
        "require_fresh": require_fresh,
        "require_live_source_uris": require_live_source_uris,
        "require_source_snapshot_artifacts": True,
        "require_fresh_source_snapshot_artifacts": require_fresh_source_snapshot_artifacts,
        "freshness_checked_at": now or collection_run.get("generated_at"),
        "collected_count": summary.get("collected_count"),
        "task_count": summary.get("task_count"),
        "collected_tasks": [item.get("task") for item in collected_items],
        "snapshot_ids": [item.get("snapshot_id") for item in collected_items],
        "intake_ids": [item.get("intake_id") for item in collected_items],
        "limitations": [
            "This entry attests that a collection-run report and its retained source snapshots/intake receipts verified offline before append.",
            "It records collection provenance only; final external authority coverage still requires a verified external-evidence manifest entry.",
        ],
    }
    return chain.append(
        EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE,
        payload,
        key=key,
        timestamp=collection_run.get("generated_at"),
    )


def append_external_evidence_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    require_complete: bool = False,
    require_fresh: bool = False,
    require_live_source_uris: bool = False,
    require_source_snapshot_artifacts: bool = False,
    require_fresh_source_snapshot_artifacts: bool = False,
    now: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_external_evidence_manifest(
        manifest,
        roadmap_audit,
        root=root,
        require_complete=require_complete,
        require_fresh=require_fresh,
        require_live_source_uris=require_live_source_uris,
        require_source_snapshot_artifacts=require_source_snapshot_artifacts,
        require_fresh_source_snapshot_artifacts=require_fresh_source_snapshot_artifacts,
        now=now,
    )
    if not result.ok:
        raise ValueError("invalid external evidence manifest: " + "; ".join(result.errors))
    summary = manifest.get("summary", {})
    source_audit_proof = _source_roadmap_audit_proof(chain, manifest.get("source_roadmap_audit"))
    payload = {
        "manifest_id": manifest["manifest_id"],
        "manifest_hash": content_hash(manifest),
        "manifest_ref": manifest.get("manifest_ref"),
        "source_roadmap_audit": manifest.get("source_roadmap_audit"),
        "source_roadmap_audit_inclusion_proof": source_audit_proof,
        "status": summary.get("status"),
        "require_complete": require_complete,
        "require_fresh": require_fresh,
        "require_live_source_uris": require_live_source_uris,
        "require_source_snapshot_artifacts": require_source_snapshot_artifacts,
        "require_fresh_source_snapshot_artifacts": require_fresh_source_snapshot_artifacts,
        "freshness_checked_at": now or manifest.get("generated_at"),
        "required_requirement_count": summary.get("required_requirement_count"),
        "covered_requirement_count": summary.get("covered_requirement_count"),
        "missing_requirement_count": summary.get("missing_requirement_count"),
        "required_authority_kind_count": summary.get("required_authority_kind_count"),
        "covered_authority_kind_count": summary.get("covered_authority_kind_count"),
        "missing_authority_kind_count": summary.get("missing_authority_kind_count"),
        "evidence_count": summary.get("evidence_count"),
        "issued_at_count": summary.get("issued_at_count"),
        "expires_at_count": summary.get("expires_at_count"),
        "freshness_window_count": summary.get("freshness_window_count"),
        "fresh_evidence_count": result.fresh_evidence_count,
        "stale_evidence_count": result.stale_evidence_count,
        "missing_freshness_count": result.missing_freshness_count,
        "covered_requirement_ids": summary.get("covered_requirement_ids", []),
        "missing_requirement_ids": summary.get("missing_requirement_ids", []),
        "covered_authority_kinds_by_requirement": summary.get("covered_authority_kinds_by_requirement", {}),
        "missing_authority_kinds_by_requirement": summary.get("missing_authority_kinds_by_requirement", {}),
        "limitations": manifest.get("limitations", []),
    }
    return chain.append(EXTERNAL_EVIDENCE_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("generated_at"))

def parse_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 3)
    if len(parts) != 4:
        raise ValueError("evidence must be requirement_id,authority_kind,path,description[;key=value...]")
    requirement_id, authority_kind, path, description = [part.strip() for part in parts]
    metadata: dict[str, Any] = {}
    description_parts = [part.strip() for part in description.split(";")]
    description = description_parts[0]
    allowed_metadata = {"issuer", "subject", "source_uri", "issued_at", "expires_at"}
    for token in description_parts[1:]:
        if not token:
            continue
        if "=" not in token:
            raise ValueError("evidence metadata must be key=value")
        key, metadata_value = [part.strip() for part in token.split("=", 1)]
        if key not in allowed_metadata:
            raise ValueError(f"unsupported evidence metadata key: {key}")
        metadata[key] = metadata_value
    return {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "path": path,
        "description": description,
        **metadata,
    }


def parse_bundle_source_artifact_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 2)
    if len(parts) != 3:
        raise ValueError("source artifact must be kind,path,description")
    kind, path, description = [part.strip() for part in parts]
    return {"kind": kind, "path": path, "description": description}

def write_external_evidence_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def write_external_evidence_collection_plan(path: str | Path, plan: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_collection_plan(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_external_evidence_source_map(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def load_external_evidence_collection_run(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_source_snapshot(path: str | Path, snapshot: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_source_snapshot(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def write_external_evidence_intake(path: str | Path, intake: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(intake, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_intake(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def discover_external_evidence_intake_paths(
    paths: list[str | Path] | None = None,
    directories: list[str | Path] | None = None,
) -> list[Path]:
    discovered: list[Path] = []
    seen: set[str] = set()

    def add_path(path: Path) -> None:
        key = str(path)
        if key not in seen:
            seen.add(key)
            discovered.append(path)

    for value in paths or []:
        add_path(Path(value))

    for value in directories or []:
        directory = Path(value)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"external evidence intake directory is missing: {directory}")
        for path in sorted(directory.rglob("*.json"), key=lambda item: item.as_posix()):
            try:
                candidate = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"external evidence intake directory contains invalid JSON: {path}: {exc}") from exc
            if isinstance(candidate, dict) and candidate.get("schema") == EXTERNAL_EVIDENCE_INTAKE_SCHEMA:
                add_path(path)

    return discovered


def load_external_evidence_intakes(
    paths: list[str | Path] | None = None,
    directories: list[str | Path] | None = None,
) -> list[dict[str, Any]]:
    intake_paths = discover_external_evidence_intake_paths(paths, directories)
    if not intake_paths:
        raise ValueError("at least one external evidence intake receipt is required")
    return [load_external_evidence_intake(path) for path in intake_paths]

def write_external_evidence_gap_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_gap_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_gap_report_markdown(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_gap_report_markdown(report), encoding="utf-8")


def write_external_evidence_work_package(path: str | Path, work_package: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(work_package, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_work_package(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_work_package_markdown(path: str | Path, work_package: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_work_package_markdown(work_package), encoding="utf-8")


def write_external_evidence_owner_packets(path: str | Path, packet_bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(packet_bundle, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_owner_packets(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_owner_packets_markdown(path: str | Path, packet_bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_owner_packets_markdown(packet_bundle), encoding="utf-8")


def write_external_evidence_owner_packet_status(path: str | Path, status_report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(status_report, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_owner_packet_status(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_owner_packet_status_markdown(path: str | Path, status_report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_owner_packet_status_markdown(status_report), encoding="utf-8")

def write_external_evidence_owner_fulfillment_template(path: str | Path, template: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(template, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_owner_fulfillment_template(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_owner_fulfillment_template_markdown(path: str | Path, template: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_owner_fulfillment_template_markdown(template), encoding="utf-8")


def write_external_evidence_owner_fulfillment_review(path: str | Path, review: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(review, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_owner_fulfillment_review(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_owner_fulfillment_review_markdown(path: str | Path, review: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_owner_fulfillment_review_markdown(review), encoding="utf-8")


def write_external_evidence_owner_fulfillment_closure(path: str | Path, closure: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(closure, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_owner_fulfillment_closure(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_owner_fulfillment_closure_markdown(path: str | Path, closure: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_owner_fulfillment_closure_markdown(closure), encoding="utf-8")


def write_external_evidence_readiness_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_readiness_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_readiness_markdown(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_readiness_markdown(report), encoding="utf-8")

def write_external_evidence_production_replacement_plan(path: str | Path, plan: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_production_replacement_plan(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_production_replacement_plan_markdown(path: str | Path, plan: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_production_replacement_plan_markdown(plan), encoding="utf-8")
def write_roadmap_evidence_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def load_roadmap_evidence_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_roadmap_evidence_bundle(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def load_roadmap_evidence_bundle(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def write_external_evidence_markdown(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_markdown(manifest), encoding="utf-8")

def write_external_evidence_collection_plan_markdown(path: str | Path, plan: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_collection_plan_markdown(plan), encoding="utf-8")


def write_roadmap_evidence_markdown(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_roadmap_evidence_markdown(report), encoding="utf-8")


def write_roadmap_evidence_bundle_markdown(path: str | Path, bundle: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_roadmap_evidence_bundle_markdown(bundle), encoding="utf-8")

def _markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")


def _markdown_code_list(values: Any) -> str:
    if not isinstance(values, list):
        return ""
    return ", ".join(f"`{_markdown_cell(value)}`" for value in values if str(value))


def _markdown_text_list(values: Any) -> str:
    if not isinstance(values, list):
        return ""
    return "<br>".join(_markdown_cell(value) for value in values if str(value))


def _external_evidence_freshness_cell(item: dict[str, Any]) -> str:
    issued_at = str(item.get("issued_at") or "")
    expires_at = str(item.get("expires_at") or "")
    if issued_at or expires_at:
        return _markdown_cell(f"{issued_at or 'missing issued_at'} to {expires_at or 'missing expires_at'}")
    return "missing"


def render_external_evidence_work_package_markdown(work_package: dict[str, Any]) -> str:
    summary = work_package.get("summary", {}) if isinstance(work_package.get("summary"), dict) else {}
    lines = [
        "# External Evidence Work Packages",
        "",
        f"- Work package ID: `{work_package.get('work_package_id')}`",
        f"- Generated at: `{work_package.get('generated_at')}`",
        f"- Grouped by: `{work_package.get('group_by')}`",
        f"- Packages: {summary.get('package_count', 0)}",
        f"- Tasks: {summary.get('task_count', 0)}",
        f"- Missing tasks: {summary.get('missing_task_count', 0)}",
        f"- Placeholder source URIs: {summary.get('placeholder_source_uri_count', 0)}",
        f"- Live source URIs: {summary.get('live_source_uri_count', 0)}",
        "",
        "## Tasks By Owner",
        "",
    ]
    by_owner = summary.get("task_count_by_owner_hint", {})
    if isinstance(by_owner, dict) and by_owner:
        for owner, count in by_owner.items():
            lines.append(f"- {owner}: {count}")
    else:
        lines.append("- None")
    lines.extend(["", "## Packages", ""])
    packages = work_package.get("packages", [])
    if isinstance(packages, list) and packages:
        for package in packages:
            if not isinstance(package, dict):
                continue
            lines.append(f"### {package.get('group_key')}")
            lines.append("")
            lines.append(f"- Package ref: `{package.get('package_ref')}`")
            lines.append(f"- Package ID: `{package.get('package_id')}`")
            group_by = package.get("group_by")
            if isinstance(group_by, str) and group_by:
                label = group_by.replace("_", " ").title()
                lines.append(f"- {label}: `{_markdown_cell(package.get(group_by))}`")
            lines.append(f"- Tasks: {package.get('task_count', 0)}")
            lines.append(f"- Authority kinds: {_markdown_code_list(package.get('authority_kinds', []))}")
            lines.append(f"- Requirements: {_markdown_code_list(package.get('requirement_ids', []))}")
            commands = package.get("commands", {}) if isinstance(package.get("commands"), dict) else {}
            if commands.get("collect_batch_command"):
                lines.append(f"- Batch collect command: `{_markdown_cell(commands.get('collect_batch_command'))}`")
            if commands.get("rebuild_manifest_command"):
                lines.append(f"- Rebuild manifest command: `{_markdown_cell(commands.get('rebuild_manifest_command'))}`")
            lines.extend(["", "| Task | Phase | Priority | Authority | Source URI Status | Intake |", "|---|---|---|---|---|---|"])
            tasks = package.get("tasks", [])
            if isinstance(tasks, list):
                for task in tasks:
                    if not isinstance(task, dict):
                        continue
                    lines.append(
                        "| "
                        + " | ".join(
                            [
                                f"`{_markdown_cell(task.get('unit_ref'))}`",
                                _markdown_cell(task.get("phase")),
                                _markdown_cell(task.get("priority")),
                                f"`{_markdown_cell(task.get('authority_kind'))}`",
                                _markdown_cell(task.get("source_uri_status")),
                                f"`{_markdown_cell(task.get('intake_out'))}`",
                            ]
                        )
                        + " |"
                    )
            lines.append("")
            lines.extend(["#### Task Commands", ""])
            if isinstance(tasks, list):
                for task in tasks:
                    if not isinstance(task, dict):
                        continue
                    task_commands = task.get("commands", {}) if isinstance(task.get("commands"), dict) else {}
                    lines.append(f"- `{_markdown_cell(task.get('unit_ref'))}` collect: `{_markdown_cell(task_commands.get('collect_command'))}`")
                    lines.append(f"- `{_markdown_cell(task.get('unit_ref'))}` verify intake: `{_markdown_cell(task_commands.get('verify_intake_command'))}`")
            lines.append("")
    else:
        lines.append("No work packages.")
    return "\n".join(lines).rstrip() + "\n"



def render_external_evidence_owner_packets_markdown(packet_bundle: dict[str, Any]) -> str:
    summary = packet_bundle.get("summary", {}) if isinstance(packet_bundle.get("summary"), dict) else {}
    source = packet_bundle.get("source_work_package", {}) if isinstance(packet_bundle.get("source_work_package"), dict) else {}
    lines = [
        "# External Evidence Owner Packets",
        "",
        f"- Owner packet bundle ID: `{packet_bundle.get('owner_packet_bundle_id')}`",
        f"- Generated at: `{packet_bundle.get('generated_at')}`",
        f"- Source work package ID: `{source.get('work_package_id')}`",
        f"- Source work package hash: `{source.get('work_package_hash')}`",
        f"- Packets: {summary.get('packet_count', 0)}",
        f"- Tasks: {summary.get('task_count', 0)}",
        f"- Missing tasks: {summary.get('missing_task_count', 0)}",
        f"- Placeholder source URIs: {summary.get('placeholder_source_uri_count', 0)}",
        "",
        "## Packets",
        "",
    ]
    packets = packet_bundle.get("packets", [])
    if isinstance(packets, list) and packets:
        for packet in packets:
            if not isinstance(packet, dict):
                continue
            lines.append(f"### {_markdown_cell(packet.get('owner_hint'))}")
            lines.append("")
            lines.append(f"- Packet ref: `{_markdown_cell(packet.get('packet_ref'))}`")
            lines.append(f"- Packet ID: `{_markdown_cell(packet.get('packet_id'))}`")
            lines.append(f"- Package ref: `{_markdown_cell(packet.get('package_ref'))}`")
            lines.append(f"- Tasks: {packet.get('task_count', 0)}")
            lines.append(f"- Missing tasks: {packet.get('missing_task_count', 0)}")
            lines.append(f"- Authority kinds: {_markdown_code_list(packet.get('authority_kinds', []))}")
            lines.append(f"- Requirements: {_markdown_code_list(packet.get('requirement_ids', []))}")
            handoff = packet.get("handoff", {}) if isinstance(packet.get("handoff"), dict) else {}
            if handoff.get("collect_batch_command"):
                lines.append(f"- Batch collect command: `{_markdown_cell(handoff.get('collect_batch_command'))}`")
            if handoff.get("rebuild_manifest_command"):
                lines.append(f"- Rebuild manifest command: `{_markdown_cell(handoff.get('rebuild_manifest_command'))}`")
            if handoff.get("completion_gate"):
                lines.append(f"- Completion gate: {_markdown_cell(handoff.get('completion_gate'))}")
            lines.extend(["", "| Task | Phase | Priority | Authority | Source URI Status | Intake |", "|---|---|---|---|---|---|"])
            tasks = packet.get("tasks", [])
            if isinstance(tasks, list):
                for task in tasks:
                    if not isinstance(task, dict):
                        continue
                    lines.append(
                        "| "
                        + " | ".join(
                            [
                                f"`{_markdown_cell(task.get('unit_ref'))}`",
                                _markdown_cell(task.get("phase")),
                                _markdown_cell(task.get("priority")),
                                f"`{_markdown_cell(task.get('authority_kind'))}`",
                                _markdown_cell(task.get("source_uri_status")),
                                f"`{_markdown_cell(task.get('intake_out'))}`",
                            ]
                        )
                        + " |"
                    )
            lines.extend(["", "#### Task Commands", ""])
            if isinstance(tasks, list):
                for task in tasks:
                    if not isinstance(task, dict):
                        continue
                    commands = task.get("commands", {}) if isinstance(task.get("commands"), dict) else {}
                    lines.append(f"- `{_markdown_cell(task.get('unit_ref'))}` collect: `{_markdown_cell(commands.get('collect_command'))}`")
                    lines.append(f"- `{_markdown_cell(task.get('unit_ref'))}` verify intake: `{_markdown_cell(commands.get('verify_intake_command'))}`")
            lines.append("")
    else:
        lines.append("No owner packets.")
    limitations = packet_bundle.get("limitations", [])
    lines.extend(["", "## Limitations", ""])
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {_markdown_cell(item)}" for item in limitations)
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"


def render_external_evidence_owner_packet_status_markdown(status_report: dict[str, Any]) -> str:
    summary = status_report.get("summary", {}) if isinstance(status_report.get("summary"), dict) else {}
    lines = [
        "# External Evidence Owner Packet Status",
        "",
        f"- Status ID: `{status_report.get('owner_packet_status_id')}`",
        f"- Generated at: `{status_report.get('generated_at')}`",
        f"- Packets: {summary.get('packet_count', 0)}",
        f"- Tasks: {summary.get('task_count', 0)}",
        f"- Closed tasks: {summary.get('closed_task_count', 0)}",
        f"- Open tasks: {summary.get('open_task_count', 0)}",
        f"- Blocked tasks: {summary.get('blocked_task_count', 0)}",
        f"- Placeholder source URIs: {summary.get('placeholder_source_uri_count', 0)}",
        f"- Missing intakes: {summary.get('missing_intake_count', 0)}",
        "",
        "## Packets",
        "",
        "| Owner | Packet | Status | Tasks | Closed | Open | Blocked |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    packets = status_report.get("packets", [])
    if isinstance(packets, list):
        for packet in packets:
            if not isinstance(packet, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(packet.get("owner_hint")),
                        f"`{_markdown_cell(packet.get('packet_ref'))}`",
                        _markdown_cell(packet.get("packet_status")),
                        str(packet.get("task_count", 0)),
                        str(packet.get("closed_task_count", 0)),
                        str(packet.get("open_task_count", 0)),
                        str(packet.get("blocked_task_count", 0)),
                    ]
                )
                + " |"
            )
    lines.extend(["", "## Open And Blocked Tasks", "", "| Task | Owner | Status | Source URI | Blocking Reasons |", "|---|---|---|---|---|"])
    tasks = status_report.get("tasks", [])
    if isinstance(tasks, list):
        for task in tasks:
            if not isinstance(task, dict) or task.get("task_status") == "closed":
                continue
            reasons = task.get("blocking_reasons", []) if isinstance(task.get("blocking_reasons"), list) else []
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_markdown_cell(task.get('unit_ref'))}`",
                        _markdown_cell(task.get("owner_hint")),
                        _markdown_cell(task.get("task_status")),
                        _markdown_cell(task.get("source_uri_status")),
                        _markdown_code_list(reasons),
                    ]
                )
                + " |"
            )
    limitations = status_report.get("limitations", [])
    lines.extend(["", "## Limitations", ""])
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {_markdown_cell(item)}" for item in limitations)
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"

def render_external_evidence_owner_fulfillment_template_markdown(template: dict[str, Any]) -> str:
    summary = template.get("summary", {}) if isinstance(template.get("summary"), dict) else {}
    lines = [
        "# External Evidence Owner Fulfillment Template",
        "",
        f"- Template ID: `{template.get('owner_fulfillment_template_id')}`",
        f"- Generated at: `{template.get('generated_at')}`",
        f"- Fulfillments: {summary.get('fulfillment_count', 0)}",
        f"- Owners: {summary.get('owner_count', 0)}",
        f"- Blocked tasks: {summary.get('blocked_task_count', 0)}",
        f"- Open tasks: {summary.get('open_task_count', 0)}",
        f"- Closed tasks: {summary.get('closed_task_count', 0)}",
        f"- Placeholder source URIs: {summary.get('placeholder_source_uri_count', 0)}",
        f"- Missing intakes: {summary.get('missing_intake_count', 0)}",
        "",
        "## Fulfillments",
        "",
        "| Task | Source URI | Description |",
        "|---|---|---|",
    ]
    fulfillments = template.get("fulfillments", [])
    if isinstance(fulfillments, list):
        for item in fulfillments:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_markdown_cell(item.get('task'))}`",
                        _markdown_cell(item.get("source_uri")),
                        _markdown_cell(item.get("description")),
                    ]
                )
                + " |"
            )
    lines.extend(["", "## Assignments", "", "| Task | Owner | Status | Blocking Reasons | Snapshot | Intake |", "|---|---|---|---|---|---|"])
    assignments = template.get("assignments", [])
    if isinstance(assignments, list):
        for item in assignments:
            if not isinstance(item, dict):
                continue
            reasons = item.get("blocking_reasons", []) if isinstance(item.get("blocking_reasons"), list) else []
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_markdown_cell(item.get('task'))}`",
                        _markdown_cell(item.get("owner_hint")),
                        _markdown_cell(item.get("task_status")),
                        _markdown_code_list(reasons),
                        _markdown_cell(item.get("snapshot_out")),
                        _markdown_cell(item.get("intake_out")),
                    ]
                )
                + " |"
            )
    commands = template.get("commands", {}) if isinstance(template.get("commands"), dict) else {}
    lines.extend(["", "## Commands", ""])
    if commands:
        for key, command in commands.items():
            lines.append(f"- {key}: `{_markdown_cell(command)}`")
    else:
        lines.append("- None")
    limitations = template.get("limitations", [])
    lines.extend(["", "## Limitations", ""])
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {_markdown_cell(item)}" for item in limitations)
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"


def render_external_evidence_owner_fulfillment_review_markdown(review: dict[str, Any]) -> str:
    summary = review.get("summary", {}) if isinstance(review.get("summary"), dict) else {}
    lines = [
        "# External Evidence Owner Fulfillment Review",
        "",
        f"- Review ID: `{review.get('owner_fulfillment_review_id')}`",
        f"- Generated at: `{review.get('generated_at')}`",
        f"- Status: `{summary.get('review_status')}`",
        f"- Fulfillments: {summary.get('fulfillment_count', 0)}",
        f"- Owners: {summary.get('owner_count', 0)}",
        f"- Ready tasks: {summary.get('ready_task_count', 0)}",
        f"- Blocked tasks: {summary.get('blocked_task_count', 0)}",
        f"- Placeholder source URIs: {summary.get('placeholder_source_uri_count', 0)}",
        f"- Live source URIs: {summary.get('live_source_uri_count', 0)}",
        "",
        "## Task Review",
        "",
        "| Task | Owner | Status | Source URI | Blocking Reasons |",
        "|---|---|---|---|---|",
    ]
    tasks = review.get("task_reviews", [])
    if isinstance(tasks, list):
        for task in tasks:
            if not isinstance(task, dict):
                continue
            reasons = task.get("blocking_reasons", []) if isinstance(task.get("blocking_reasons"), list) else []
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_markdown_cell(task.get('task'))}`",
                        _markdown_cell(task.get("owner_hint")),
                        _markdown_cell(task.get("review_status")),
                        _markdown_cell(task.get("source_uri")),
                        _markdown_code_list(reasons),
                    ]
                )
                + " |"
            )
    verification = review.get("verification", {}) if isinstance(review.get("verification"), dict) else {}
    lines.extend(["", "## Verification", ""])
    errors = verification.get("fulfilled_source_map_errors", []) if isinstance(verification.get("fulfilled_source_map_errors"), list) else []
    warnings = verification.get("fulfilled_source_map_warnings", []) if isinstance(verification.get("fulfilled_source_map_warnings"), list) else []
    lines.append(f"- Fulfilled source map errors: {len(errors)}")
    lines.append(f"- Fulfilled source map warnings: {len(warnings)}")
    if errors:
        lines.extend(f"  - {_markdown_cell(error)}" for error in errors)
    blockers = review.get("blockers", [])
    lines.extend(["", "## Blockers", ""])
    if isinstance(blockers, list) and blockers:
        lines.extend(f"- {_markdown_cell(blocker)}" for blocker in blockers)
    else:
        lines.append("- None")
    next_actions = review.get("next_actions", [])
    lines.extend(["", "## Next Actions", ""])
    if isinstance(next_actions, list) and next_actions:
        lines.extend(f"- {_markdown_cell(action)}" for action in next_actions)
    else:
        lines.append("- None")
    commands = review.get("commands", {}) if isinstance(review.get("commands"), dict) else {}
    lines.extend(["", "## Commands", ""])
    if commands:
        for key, command in commands.items():
            lines.append(f"- {key}: `{_markdown_cell(command)}`")
    else:
        lines.append("- None")
    limitations = review.get("limitations", [])
    lines.extend(["", "## Limitations", ""])
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {_markdown_cell(item)}" for item in limitations)
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"


def render_external_evidence_owner_fulfillment_closure_markdown(closure: dict[str, Any]) -> str:
    summary = closure.get("summary", {}) if isinstance(closure.get("summary"), dict) else {}
    lines = [
        "# External Evidence Owner Fulfillment Closure",
        "",
        f"- Closure ID: `{closure.get('owner_fulfillment_closure_id')}`",
        f"- Generated at: `{closure.get('generated_at')}`",
        f"- Status: `{summary.get('closure_status')}`",
        f"- Closed tasks: {summary.get('closed_task_count', 0)}/{summary.get('task_count', 0)}",
        f"- Missing intakes: {summary.get('missing_intake_count', 0)}",
        f"- Invalid intake tasks: {summary.get('invalid_intake_task_count', 0)}",
        f"- Missing manifest coverage: {summary.get('missing_manifest_coverage_count', 0)}",
        f"- Placeholder source URIs: {summary.get('placeholder_source_uri_count', 0)}",
        "",
        "## Task Closure",
        "",
        "| Task | Owner | Status | Intake | Manifest Evidence | Blocking Reasons |",
        "|---|---|---|---|---|---|",
    ]
    tasks = closure.get("task_closures", [])
    if isinstance(tasks, list):
        for task in tasks:
            if not isinstance(task, dict):
                continue
            reasons = task.get("blocking_reasons", []) if isinstance(task.get("blocking_reasons"), list) else []
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_markdown_cell(task.get('task'))}`",
                        _markdown_cell(task.get("owner_hint")),
                        _markdown_cell(task.get("closure_status")),
                        _markdown_cell(task.get("intake_id")),
                        str(task.get("manifest_evidence_count", 0)),
                        _markdown_code_list(reasons),
                    ]
                )
                + " |"
            )
    blockers = closure.get("blockers", [])
    lines.extend(["", "## Blockers", ""])
    if isinstance(blockers, list) and blockers:
        lines.extend(f"- {_markdown_cell(blocker)}" for blocker in blockers)
    else:
        lines.append("- None")
    next_actions = closure.get("next_actions", [])
    lines.extend(["", "## Next Actions", ""])
    if isinstance(next_actions, list) and next_actions:
        lines.extend(f"- {_markdown_cell(action)}" for action in next_actions)
    else:
        lines.append("- None")
    verification = closure.get("verification", {}) if isinstance(closure.get("verification"), dict) else {}
    lines.extend(["", "## Verification", ""])
    lines.append(f"- Source errors: {verification.get('error_count', 0)}")
    lines.append(f"- Source warnings: {verification.get('warning_count', 0)}")
    unmatched = closure.get("unmatched_intakes", [])
    lines.append(f"- Unmatched intakes: {len(unmatched) if isinstance(unmatched, list) else 0}")
    limitations = closure.get("limitations", [])
    lines.extend(["", "## Limitations", ""])
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {_markdown_cell(item)}" for item in limitations)
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"


def render_external_evidence_readiness_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    lines = [
        "# External Evidence Production Readiness",
        "",
        f"- Readiness ID: `{report.get('readiness_id')}`",
        f"- Generated at: `{report.get('generated_at')}`",
        f"- Status: `{summary.get('readiness_status')}`",
        f"- Covered authority units: {summary.get('covered_authority_kind_count', 0)}/{summary.get('required_authority_kind_count', 0)}",
        f"- Production-usable covered authority units: {summary.get('production_usable_covered_authority_kind_count', 0)}",
        f"- Non-production covered authority units: {summary.get('non_production_covered_authority_kind_count', 0)}",
        f"- Missing authority units: {summary.get('missing_authority_kind_count', 0)}",
        f"- Remaining collection tasks: {summary.get('remaining_task_count', 0)}",
        f"- Placeholder source URIs: {summary.get('placeholder_source_uri_count', 0)}",
        f"- Work packages: {summary.get('work_package_count', 0)}",
        "",
        "## Checks",
        "",
        "| Check | Status | Summary |",
        "|---|---|---|",
    ]
    checks = report.get("checks", [])
    if isinstance(checks, list):
        for check in checks:
            if isinstance(check, dict):
                lines.append(f"| `{_markdown_cell(check.get('id'))}` | `{_markdown_cell(check.get('status'))}` | {_markdown_cell(check.get('summary'))} |")
    blockers = report.get("blockers", [])
    lines.extend(["", "## Blockers", ""])
    if isinstance(blockers, list) and blockers:
        lines.extend(f"- {_markdown_cell(blocker)}" for blocker in blockers)
    else:
        lines.append("- None")
    next_actions = report.get("next_actions", [])
    lines.extend(["", "## Next Actions", ""])
    if isinstance(next_actions, list) and next_actions:
        lines.extend(f"- {_markdown_cell(action)}" for action in next_actions)
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"

def render_external_evidence_production_replacement_plan_markdown(plan: dict[str, Any]) -> str:
    summary = plan.get("summary", {}) if isinstance(plan.get("summary"), dict) else {}
    lines = [
        "# External Evidence Production Replacement Plan",
        "",
        f"- Replacement plan ID: `{plan.get('replacement_plan_id')}`",
        f"- Generated at: `{plan.get('generated_at')}`",
        f"- Status: `{summary.get('replacement_status')}`",
        f"- Open replacement tasks: {summary.get('task_count', 0)}",
        f"- Non-production covered authority units: {summary.get('non_production_covered_authority_kind_count', 0)}",
        f"- Production-usable covered authority units: {summary.get('production_usable_covered_authority_kind_count', 0)}",
        f"- Packages: {summary.get('package_count', 0)}",
        "",
        "## Packages",
        "",
        "| Package | Tasks | Authority Kinds | Requirements |",
        "|---|---:|---|---|",
    ]
    packages = plan.get("packages", [])
    if isinstance(packages, list):
        for package in packages:
            if isinstance(package, dict):
                lines.append(
                    f"| `{_markdown_cell(package.get('package_ref'))}` | {package.get('task_count', 0)} | "
                    f"{_markdown_code_list(package.get('authority_kinds'))} | {_markdown_code_list(package.get('requirement_ids'))} |"
                )
    tasks = plan.get("tasks", [])
    lines.extend(["", "## Replacement Tasks", "", "| Unit | Owner | Authority | Replaces | Reasons |", "|---|---|---|---|---|"])
    if isinstance(tasks, list):
        for task in tasks:
            if isinstance(task, dict):
                lines.append(
                    f"| `{_markdown_cell(task.get('unit_ref'))}` | {_markdown_cell(task.get('owner_hint'))} | "
                    f"`{_markdown_cell(task.get('authority_kind'))}` | {_markdown_code_list(task.get('replaces_artifacts'))} | "
                    f"{_markdown_text_list(task.get('non_production_reasons'))} |"
                )
    limitations = plan.get("limitations", [])
    lines.extend(["", "## Limitations", ""])
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {_markdown_cell(item)}" for item in limitations)
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"
def render_external_evidence_gap_report_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    lines = [
        "# External Evidence Gap Report",
        "",
        f"- Gap report ID: `{report.get('gap_report_id')}`",
        f"- Generated at: `{report.get('generated_at')}`",
        f"- Status: `{summary.get('status')}`",
        f"- Covered authority kinds: {summary.get('covered_authority_kind_count', 0)}/{summary.get('required_authority_kind_count', 0)}",
        f"- Missing authority kinds: {summary.get('missing_authority_kind_count', 0)}",
        f"- Remaining collection tasks: {summary.get('remaining_task_count', 0)}",
        f"- Source-map entries: {summary.get('source_map_entry_count', 0)}",
        f"- Placeholder source URIs: {summary.get('placeholder_source_uri_count', 0)}",
        f"- Live source URIs: {summary.get('live_source_uri_count', 0)}",
        "",
        "## Gaps By Authority Kind",
        "",
    ]
    by_authority = summary.get("gap_count_by_authority_kind", {})
    if isinstance(by_authority, dict) and by_authority:
        for authority, count in by_authority.items():
            lines.append(f"- `{authority}`: {count}")
    else:
        lines.append("- None")
    lines.extend(["", "## Gaps By Requirement", ""])
    by_requirement = summary.get("gap_count_by_requirement", {})
    if isinstance(by_requirement, dict) and by_requirement:
        for requirement, count in by_requirement.items():
            lines.append(f"- `{requirement}`: {count}")
    else:
        lines.append("- None")
    lines.extend(["", "## Collection Worklist", ""])
    gaps = report.get("gaps", [])
    if isinstance(gaps, list) and gaps:
        for gap in gaps:
            if not isinstance(gap, dict):
                continue
            lines.append(f"### {gap.get('unit_ref')}")
            lines.append("")
            lines.append(f"- Title: {gap.get('title')}")
            lines.append(f"- Authority kind: `{gap.get('authority_kind')}`")
            lines.append(f"- Owner hint: {gap.get('owner_hint')}")
            lines.append(f"- Description: {gap.get('description')}")
            lines.append(f"- Source URI: `{gap.get('source_uri')}`")
            if gap.get("source_file"):
                lines.append(f"- Source file: `{gap.get('source_file')}`")
            if gap.get("retrieval_method"):
                lines.append(f"- Retrieval method: `{gap.get('retrieval_method')}`")
            if gap.get("content_type"):
                lines.append(f"- Content type: `{gap.get('content_type')}`")
            if gap.get("issuer") or gap.get("subject"):
                lines.append(f"- Issuer/subject: {gap.get('issuer') or 'missing issuer'} / {gap.get('subject') or 'missing subject'}")
            if gap.get("issued_at") or gap.get("expires_at"):
                lines.append(f"- Freshness: `{gap.get('issued_at') or 'missing issued_at'} to {gap.get('expires_at') or 'missing expires_at'}`")
            if gap.get("timeout_seconds"):
                lines.append(f"- Timeout seconds: `{gap.get('timeout_seconds')}`")
            lines.append(f"- Snapshot output: `{gap.get('snapshot_out')}`")
            lines.append(f"- Intake output: `{gap.get('intake_out')}`")
            suggestions = gap.get("suggested_evidence_sources", [])
            if suggestions:
                lines.append("- Suggested evidence sources: " + "; ".join(str(item) for item in suggestions))
            lines.append("")
    else:
        lines.append("No remaining external evidence gaps.")
        lines.append("")
    lines.extend(["## Limitations", ""])
    for limitation in report.get("limitations", []):
        lines.append(f"- {limitation}")
    return "\n".join(lines).rstrip() + "\n"

def render_external_evidence_markdown(manifest: dict[str, Any]) -> str:
    summary = manifest.get("summary", {})
    covered_ids = set(summary.get("covered_requirement_ids", []))
    covered_authorities = summary.get("covered_authority_kinds_by_requirement", {})
    missing_authorities = summary.get("missing_authority_kinds_by_requirement", {})
    if not isinstance(covered_authorities, dict):
        covered_authorities = {}
    if not isinstance(missing_authorities, dict):
        missing_authorities = {}
    requirement_rows = "\n".join(
        "| `{requirement}` | {phase} | {priority} | {coverage} | {accepted} | {covered_authorities} | {missing_authorities} | {authority} |".format(
            requirement=_markdown_cell(item.get("id", "")),
            phase=_markdown_cell(item.get("phase", "")),
            priority=_markdown_cell(item.get("priority", "")),
            coverage="covered" if item.get("id") in covered_ids and not missing_authorities.get(item.get("id")) else "missing",
            accepted=_markdown_code_list(item.get("allowed_authority_kinds", [])),
            covered_authorities=_markdown_code_list(covered_authorities.get(item.get("id"), [])),
            missing_authorities=_markdown_code_list(missing_authorities.get(item.get("id"), [])),
            authority=_markdown_text_list(item.get("external_authority_required", [])),
        )
        for item in manifest.get("required_external_requirements", [])
    )
    unit_rows = "\n".join(
        "| `{unit_id}` | `{unit_ref}` | `{requirement}` | {authority} | {status} | {title} |".format(
            unit_id=_markdown_cell(item.get("unit_id", "")),
            unit_ref=_markdown_cell(item.get("unit_ref", "")),
            requirement=_markdown_cell(item.get("requirement_id", "")),
            authority=_markdown_cell(item.get("authority_kind", "")),
            status=_markdown_cell(item.get("coverage_status", "")),
            title=_markdown_cell(item.get("title", "")),
        )
        for item in manifest.get("required_authority_evidence_units", [])
    )
    evidence_rows = "\n".join(
        "| `{requirement}` | {kind} | {accepted} | `{path}` | {freshness} | {description} |".format(
            requirement=_markdown_cell(item.get("requirement_id", "")),
            kind=_markdown_cell(item.get("authority_kind", "")),
            accepted=_markdown_code_list(item.get("accepted_authority_kinds", [])),
            path=_markdown_cell(item.get("path", "")),
            freshness=_external_evidence_freshness_cell(item),
            description=_markdown_cell(item.get("description", "")),
        )
        for item in manifest.get("evidence", [])
    )
    missing = summary.get("missing_requirement_ids", [])
    missing_lines = "\n".join(f"- `{_markdown_cell(requirement_id)}`" for requirement_id in missing)
    return f"""# TrustAI External Evidence Manifest

Manifest ID: `{manifest.get('manifest_id', '')}`

Status: {summary.get('status', '')}

## Coverage

- Required external requirements: {summary.get('required_requirement_count', 0)}
- Covered requirements: {summary.get('covered_requirement_count', 0)}
- Required authority kinds: {summary.get('required_authority_kind_count', 0)}
- Covered authority kinds: {summary.get('covered_authority_kind_count', 0)}
- Missing authority kinds: {summary.get('missing_authority_kind_count', 0)}
- Evidence items: {summary.get('evidence_count', 0)}
- Evidence with issued_at: {summary.get('issued_at_count', 0)}
- Evidence with expires_at: {summary.get('expires_at_count', 0)}
- Evidence with freshness windows: {summary.get('freshness_window_count', 0)}

## Required External Evidence

| Requirement | Phase | Priority | Coverage | Accepted Authorities | Covered Authorities | Missing Authorities | Authority Evidence Needed |
|---|---|---|---|---|---|---|---|
{requirement_rows or "| - | - | - | - | - | - | - | - |"}

## Authority Coverage Units

| Unit ID | Unit Ref | Requirement | Authority | Status | Title |
|---|---|---|---|---|---|
{unit_rows or "| - | - | - | - | - | - |"}

## Evidence

| Requirement | Authority | Accepted Authorities | Artifact | Freshness Window | Description |
|---|---|---|---|---|---|
{evidence_rows or "| - | - | - | - | - | - |"}

## Missing Requirements

{missing_lines or "- None"}
"""


def render_external_evidence_collection_plan_markdown(plan: dict[str, Any]) -> str:
    summary = plan.get("summary", {})
    source = plan.get("source_manifest", {})
    task_rows = "\n".join(
        "| `{task_id}` | `{unit_ref}` | `{requirement}` | {authority} | {status} | {owner} | `{artifact}` | `{evidence_arg}` |".format(
            task_id=_markdown_cell(item.get("task_id", "")),
            unit_ref=_markdown_cell(item.get("unit_ref", "")),
            requirement=_markdown_cell(item.get("requirement_id", "")),
            authority=_markdown_cell(item.get("authority_kind", "")),
            status=_markdown_cell(item.get("coverage_status", "")),
            owner=_markdown_cell(item.get("owner_hint", "")),
            artifact=_markdown_cell(item.get("suggested_artifact_path", "")),
            evidence_arg=_markdown_cell(item.get("evidence_argument_template", "")),
        )
        for item in plan.get("tasks", [])
    )
    return f"""# TrustAI External Evidence Collection Plan

Plan ID: `{plan.get('plan_id', '')}`

Source manifest: `{source.get('manifest_id', '')}`

Status filter: {plan.get('status_filter', '')}

## Summary

- Source manifest status: {summary.get('source_manifest_status', '')}
- Total authority units: {summary.get('total_authority_unit_count', 0)}
- Selected tasks: {summary.get('selected_task_count', 0)}
- Selected missing tasks: {summary.get('selected_missing_task_count', 0)}
- Selected covered tasks: {summary.get('selected_covered_task_count', 0)}
- Missing authority kinds overall: {summary.get('missing_authority_kind_count', 0)}

## Collection Tasks

| Task ID | Unit Ref | Requirement | Authority | Status | Owner Hint | Suggested Artifact | Evidence Argument Template |
|---|---|---|---|---|---|---|---|
{task_rows or "| - | - | - | - | - | - | - | - |"}
"""

def render_roadmap_evidence_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    chain = report.get("chain", {})
    verification = report.get("verification", {})
    audit_rows = "\n".join(
        "| {index} | `{entry_id}` | `{audit_id}` | {implemented}/{reference}/{missing} |".format(
            index=entry.get("index", ""),
            entry_id=entry.get("entry_id", ""),
            audit_id=entry.get("audit_id", ""),
            implemented=entry.get("implemented_local_count", 0),
            reference=entry.get("reference_attested_count", 0),
            missing=entry.get("missing_local_evidence_count", 0),
        )
        for entry in report.get("roadmap_audit_entries", [])
    )
    external_rows = "\n".join(
        "| {index} | `{entry_id}` | `{manifest_id}` | {status} | {covered}/{required} | {authority_covered}/{authority_required} | {missing} | {missing_authority} |".format(
            index=entry.get("index", ""),
            entry_id=entry.get("entry_id", ""),
            manifest_id=entry.get("manifest_id", ""),
            status=entry.get("status", ""),
            covered=entry.get("covered_requirement_count", 0),
            required=entry.get("required_requirement_count", 0),
            authority_covered=entry.get("covered_authority_kind_count", 0),
            authority_required=entry.get("required_authority_kind_count", 0),
            missing=entry.get("missing_requirement_count", 0),
            missing_authority=entry.get("missing_authority_kind_count", 0),
        )
        for entry in report.get("external_evidence_entries", [])
    )
    errors = "\n".join(f"- {error}" for error in verification.get("errors", []))
    warnings = "\n".join(f"- {warning}" for warning in verification.get("warnings", []))
    limitations = "\n".join(f"- {limitation}" for limitation in report.get("limitations", []))
    return f"""# TrustAI Roadmap Evidence Report

Report ID: `{report.get('report_id', '')}`

Semantic verification: {"passed" if verification.get("ok") else "failed"}

## Chain

- Tenant: `{chain.get('tenant_id', '')}`
- Entries: {chain.get('entry_count', 0)}
- Tree root: `{chain.get('tree', {}).get('root', '')}`

## Summary

- Roadmap audit entries: {summary.get('roadmap_audit_entry_count', 0)}
- External evidence entries: {summary.get('external_evidence_entry_count', 0)}
- External evidence collection run entries: {summary.get('external_evidence_collection_run_entry_count', 0)}
- Complete external evidence entries: {summary.get('complete_external_evidence_entry_count', 0)}
- Fresh external evidence entries: {summary.get('fresh_external_evidence_entry_count', 0)}

## Roadmap Audit Entries

| Index | Entry ID | Audit ID | Implemented / Reference / Missing |
|---|---|---|---|
{audit_rows or "| - | - | - | - |"}

## External Evidence Entries

| Index | Entry ID | Manifest ID | Status | Requirements Covered / Required | Authority Kinds Covered / Required | Missing Requirements | Missing Authority Kinds |
|---|---|---|---|---|---|---|---|
{external_rows or "| - | - | - | - | - | - | - | - |"}

## Errors

{errors or "- None"}

## Warnings

{warnings or "- None"}

## Limitations

{limitations or "- None"}
"""


def render_roadmap_evidence_bundle_markdown(bundle: dict[str, Any]) -> str:
    summary = bundle.get("summary", {})
    report = bundle.get("report", {})
    report_verification = report.get("verification", {}) if isinstance(report, dict) else {}
    chain = bundle.get("chain", {})
    tree = chain.get("tree", {}) if isinstance(chain, dict) else {}
    limitations = "\n".join(f"- {limitation}" for limitation in bundle.get("limitations", []))
    return f"""# TrustAI Roadmap Evidence Bundle

Bundle ID: `{bundle.get('bundle_id', '')}`

Report ID: `{summary.get('report_id', '')}`

Semantic verification: {"passed" if report_verification.get("ok") else "failed"}

## Chain Snapshot

- Tenant: `{chain.get('tenant_id', '') if isinstance(chain, dict) else ''}`
- Entries: {summary.get('chain_entry_count', 0)}
- Tree root: `{tree.get('root', '')}`

## Roadmap Evidence

- Roadmap audit entries: {summary.get('roadmap_audit_entry_count', 0)}
- External evidence entries: {summary.get('external_evidence_entry_count', 0)}
- External evidence collection run entries: {summary.get('external_evidence_collection_run_entry_count', 0)}
- Complete external evidence entries: {summary.get('complete_external_evidence_entry_count', 0)}
- Fresh external evidence entries: {summary.get('fresh_external_evidence_entry_count', 0)}
- Embedded source artifacts: {summary.get('source_artifact_count', 0)}

## Limitations

{limitations or "- None"}
"""


def _roadmap_evidence_chain_record(chain: EvidenceChain) -> dict[str, Any]:
    return {
        "tenant_id": chain.tenant_id,
        "entry_count": len(chain.entries),
        "tree": chain.tree(),
    }


def _roadmap_evidence_chain_document(chain: EvidenceChain) -> dict[str, Any]:
    entries = json.loads(json.dumps(chain.entries, sort_keys=True))
    return {
        "spec_version": CHAIN_SPEC_VERSION,
        "tenant_id": chain.tenant_id,
        "tree": chain.tree(),
        "entries": entries,
    }


def _roadmap_evidence_chain_from_document(document: Any, errors: list[str]) -> EvidenceChain | None:
    if not isinstance(document, dict):
        errors.append("bundle chain must be an object")
        return None
    if document.get("spec_version") != CHAIN_SPEC_VERSION:
        errors.append(f"unsupported bundled chain spec version: {document.get('spec_version')}")
    tenant_id = document.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        errors.append("bundled chain tenant_id is required")
        tenant_id = "bundle"
    entries = document.get("entries")
    if not isinstance(entries, list):
        errors.append("bundled chain entries must be a list")
        entries = []
    chain = EvidenceChain(Path("<roadmap-evidence-bundle>"), tenant_id, json.loads(json.dumps(entries, sort_keys=True)))
    if document.get("tree") != chain.tree():
        errors.append("bundled chain tree does not match entries")
    return chain


def _build_bundle_source_artifacts(root: Path, source_artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for item in source_artifacts:
        kind = str(item.get("kind") or "")
        path = str(item.get("path") or "")
        if kind not in BUNDLE_SOURCE_ARTIFACT_KINDS:
            raise ValueError(f"unsupported bundle source artifact kind: {kind}")
        if not path:
            raise ValueError("bundle source artifact path is required")
        if not _is_safe_relative_path(path):
            raise ValueError(f"bundle source artifact path must be repository-relative: {path}")
        target = root / path
        if not target.exists() or not target.is_file():
            raise ValueError(f"bundle source artifact file is missing: {path}")
        data = canonical_file_bytes(target)
        body = {
            "kind": kind,
            "path": Path(path).as_posix(),
            "sha256": "sha256:" + sha256(data).hexdigest(),
            "content_b64": base64.b64encode(data).decode("ascii"),
            "description": str(item.get("description") or ""),
        }
        artifacts.append({**body, "artifact_id": content_hash(body)})
    return artifacts


def _verify_bundle_source_artifacts(
    chain: EvidenceChain,
    source_artifacts: Any,
    errors: list[str],
    warnings: list[str],
    *,
    require_source_artifacts: bool = False,
) -> None:
    if not isinstance(source_artifacts, list):
        errors.append("bundle source_artifacts must be a list")
        return
    if require_source_artifacts and not source_artifacts:
        errors.append("bundle source_artifacts are required")
    manifest_evidence_refs: set[tuple[str, str]] = set()
    embedded_external_file_refs: set[tuple[str, str]] = set()
    collection_run_source_map_hashes: set[str] = set()
    collection_run_source_snapshot_refs: set[tuple[str, str]] = set()
    collection_run_intake_refs: set[tuple[str, str]] = set()
    embedded_roadmap_audit_hashes: set[str] = set()
    embedded_external_manifest_hashes: set[str] = set()
    embedded_collection_run_hashes: set[str] = set()
    embedded_source_map_hashes: set[str] = set()
    embedded_source_snapshot_refs: set[tuple[str, str]] = set()
    embedded_intake_refs: set[tuple[str, str]] = set()
    decoded_artifacts: list[tuple[dict[str, Any], bytes]] = []
    for artifact in source_artifacts:
        if not isinstance(artifact, dict):
            errors.append("bundle source artifact must be an object")
            continue
        body = without_keys(artifact, "artifact_id")
        if artifact.get("artifact_id") != content_hash(body):
            errors.append(f"bundle source artifact id mismatch: {artifact.get('path')}")
        kind = artifact.get("kind")
        if kind not in BUNDLE_SOURCE_ARTIFACT_KINDS:
            errors.append(f"unsupported bundle source artifact kind: {kind}")
        path = artifact.get("path")
        normalized_path = str(path or "")
        if not isinstance(path, str) or not path:
            errors.append("bundle source artifact path is required")
        elif not _is_safe_relative_path(path):
            errors.append(f"bundle source artifact path must be repository-relative: {path}")
        else:
            normalized_path = Path(path).as_posix()
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (binascii.Error, ValueError):
            errors.append(f"bundle source artifact content_b64 invalid: {path}")
            continue
        actual_sha = "sha256:" + sha256(data).hexdigest()
        if artifact.get("sha256") != actual_sha:
            errors.append(f"bundle source artifact hash mismatch: {path}")
        if kind == "external-evidence-file":
            embedded_external_file_refs.add((normalized_path, actual_sha))
        decoded_artifacts.append((artifact, data))

        if kind == "external-evidence-manifest":
            manifest = _json_source_artifact(artifact, data, errors)
            if isinstance(manifest, dict):
                for evidence in manifest.get("evidence", []):
                    if isinstance(evidence, dict) and evidence.get("path") and evidence.get("sha256"):
                        manifest_evidence_refs.add((Path(str(evidence.get("path"))).as_posix(), str(evidence.get("sha256"))))
                manifest_hash = content_hash(manifest)
                embedded_external_manifest_hashes.add(manifest_hash)
                if not _chain_has_external_manifest(chain, manifest_hash):
                    errors.append(f"external evidence manifest artifact is not committed to bundled chain: {path}")
        elif kind == "external-evidence-collection-run":
            collection_run = _json_source_artifact(artifact, data, errors)
            if isinstance(collection_run, dict):
                _verify_bundle_collection_run_artifact(collection_run, normalized_path, chain, errors)
                embedded_collection_run_hashes.add(content_hash(collection_run))
                source_map = collection_run.get("source_map", {})
                if isinstance(source_map, dict) and isinstance(source_map.get("source_map_hash"), str):
                    collection_run_source_map_hashes.add(source_map["source_map_hash"])
                for item in collection_run.get("collected", []):
                    if not isinstance(item, dict):
                        continue
                    snapshot_path = item.get("snapshot_artifact_path") or item.get("snapshot_path")
                    snapshot_id = item.get("snapshot_id")
                    if isinstance(snapshot_path, str) and isinstance(snapshot_id, str):
                        collection_run_source_snapshot_refs.add((Path(snapshot_path).as_posix(), snapshot_id))
                    intake_path = item.get("intake_path")
                    intake_id = item.get("intake_id")
                    if isinstance(intake_path, str) and isinstance(intake_id, str):
                        collection_run_intake_refs.add((Path(intake_path).as_posix(), intake_id))
        elif kind == "external-evidence-source-map":
            source_map = _json_source_artifact(artifact, data, errors)
            if isinstance(source_map, dict):
                if source_map.get("schema") != EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA:
                    errors.append(f"unsupported external evidence source map artifact schema: {path}: {source_map.get('schema')}")
                if source_map.get("source_map_id") != content_hash(without_keys(source_map, "source_map_id")):
                    errors.append(f"external evidence source map artifact id mismatch: {path}")
                embedded_source_map_hashes.add(content_hash(source_map))
        elif kind == "external-evidence-source-snapshot":
            snapshot = _json_source_artifact(artifact, data, errors)
            if isinstance(snapshot, dict):
                snapshot_result = verify_external_evidence_source_snapshot(snapshot)
                warnings.extend(f"bundle source snapshot artifact {path}: {warning}" for warning in snapshot_result.warnings)
                if not snapshot_result.ok:
                    errors.extend(f"bundle source snapshot artifact {path}: {error}" for error in snapshot_result.errors)
                snapshot_id = snapshot.get("snapshot_id")
                if isinstance(snapshot_id, str):
                    embedded_source_snapshot_refs.add((normalized_path, snapshot_id))
        elif kind == "external-evidence-intake":
            intake = _json_source_artifact(artifact, data, errors)
            if isinstance(intake, dict):
                if intake.get("schema") != EXTERNAL_EVIDENCE_INTAKE_SCHEMA:
                    errors.append(f"unsupported external evidence intake artifact schema: {path}: {intake.get('schema')}")
                if intake.get("intake_id") != content_hash(without_keys(intake, "intake_id")):
                    errors.append(f"external evidence intake artifact id mismatch: {path}")
                intake_id = intake.get("intake_id")
                if isinstance(intake_id, str):
                    embedded_intake_refs.add((normalized_path, intake_id))
        elif kind == "roadmap-audit":
            audit = _json_source_artifact(artifact, data, errors)
            if isinstance(audit, dict):
                audit_hash = content_hash(audit)
                embedded_roadmap_audit_hashes.add(audit_hash)
                if not _chain_has_roadmap_audit(chain, audit_hash):
                    errors.append(f"roadmap audit artifact is not committed to bundled chain: {path}")
    _verify_required_bundle_source_artifacts(
        chain,
        embedded_roadmap_audit_hashes,
        embedded_external_manifest_hashes,
        embedded_collection_run_hashes,
        embedded_source_map_hashes,
        errors,
        require_source_artifacts=require_source_artifacts,
    )
    for path, _sha in sorted(manifest_evidence_refs - embedded_external_file_refs):
        message = f"external evidence file referenced by embedded manifest is not embedded: {path}"
        if require_source_artifacts:
            errors.append(message)
        else:
            warnings.append(message)
    for source_map_hash in sorted(collection_run_source_map_hashes - embedded_source_map_hashes):
        message = f"external evidence source map referenced by embedded collection run is not embedded: {source_map_hash}"
        if require_source_artifacts:
            errors.append(message)
        else:
            warnings.append(message)
    for path, snapshot_id in sorted(collection_run_source_snapshot_refs - embedded_source_snapshot_refs):
        message = f"external evidence source snapshot referenced by embedded collection run is not embedded: {path}"
        if require_source_artifacts:
            errors.append(message)
        else:
            warnings.append(message)
    for path, intake_id in sorted(collection_run_intake_refs - embedded_intake_refs):
        message = f"external evidence intake referenced by embedded collection run is not embedded: {path}"
        if require_source_artifacts:
            errors.append(message)
        else:
            warnings.append(message)
    for artifact, _data in decoded_artifacts:
        kind = artifact.get("kind")
        if kind == "external-evidence-file":
            ref = (str(artifact.get("path")), str(artifact.get("sha256")))
            if ref not in manifest_evidence_refs:
                warnings.append(f"external evidence file artifact is not referenced by an embedded manifest: {artifact.get('path')}")
        elif kind == "external-evidence-source-map":
            source_map_hash = ""
            try:
                source_map_hash = content_hash(json.loads(_data.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            if source_map_hash and source_map_hash not in collection_run_source_map_hashes:
                warnings.append(f"external evidence source map artifact is not referenced by an embedded collection run: {artifact.get('path')}")
        elif kind == "external-evidence-source-snapshot":
            snapshot_id = _bundle_json_id(_data, "snapshot_id")
            ref = (str(artifact.get("path")), snapshot_id)
            if snapshot_id and ref not in collection_run_source_snapshot_refs:
                warnings.append(f"external evidence source snapshot artifact is not referenced by an embedded collection run: {artifact.get('path')}")
        elif kind == "external-evidence-intake":
            intake_id = _bundle_json_id(_data, "intake_id")
            ref = (str(artifact.get("path")), intake_id)
            if intake_id and ref not in collection_run_intake_refs:
                warnings.append(f"external evidence intake artifact is not referenced by an embedded collection run: {artifact.get('path')}")


def _verify_required_bundle_source_artifacts(
    chain: EvidenceChain,
    embedded_roadmap_audit_hashes: set[str],
    embedded_external_manifest_hashes: set[str],
    embedded_collection_run_hashes: set[str],
    embedded_source_map_hashes: set[str],
    errors: list[str],
    *,
    require_source_artifacts: bool,
) -> None:
    if not require_source_artifacts:
        return
    for entry in chain.entries:
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            continue
        if entry.get("entry_type") == ROADMAP_AUDIT_ENTRY_TYPE:
            audit_hash = payload.get("audit_hash")
            if isinstance(audit_hash, str) and audit_hash not in embedded_roadmap_audit_hashes:
                errors.append(f"roadmap audit chain entry {entry.get('index')} is missing an embedded source artifact")
        elif entry.get("entry_type") == EXTERNAL_EVIDENCE_ENTRY_TYPE:
            manifest_hash = payload.get("manifest_hash")
            if isinstance(manifest_hash, str) and manifest_hash not in embedded_external_manifest_hashes:
                errors.append(f"external evidence chain entry {entry.get('index')} is missing an embedded manifest source artifact")
        elif entry.get("entry_type") == EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE:
            run_hash = payload.get("run_hash")
            if isinstance(run_hash, str) and run_hash not in embedded_collection_run_hashes:
                errors.append(f"external evidence collection run chain entry {entry.get('index')} is missing an embedded collection-run source artifact")
            source_map_hash = payload.get("source_map_hash")
            if isinstance(source_map_hash, str) and source_map_hash not in embedded_source_map_hashes:
                errors.append(f"external evidence collection run chain entry {entry.get('index')} is missing an embedded source-map source artifact")


def _verify_bundle_collection_run_artifact(collection_run: dict[str, Any], path: str, chain: EvidenceChain, errors: list[str]) -> None:
    if collection_run.get("schema") != EXTERNAL_EVIDENCE_COLLECTION_RUN_SCHEMA:
        errors.append(f"unsupported external evidence collection run artifact schema: {path}: {collection_run.get('schema')}")
    if collection_run.get("run_id") != content_hash(without_keys(collection_run, "run_id")):
        errors.append(f"external evidence collection run artifact id mismatch: {path}")
    run_hash = content_hash(collection_run)
    if not _chain_has_external_collection_run(chain, run_hash):
        errors.append(f"external evidence collection run artifact is not committed to bundled chain: {path}")


def _bundle_json_id(data: bytes, field: str) -> str:
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    value = parsed.get(field)
    return value if isinstance(value, str) else ""


def _json_source_artifact(artifact: dict[str, Any], data: bytes, errors: list[str]) -> dict[str, Any] | None:
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"bundle source artifact JSON invalid: {artifact.get('path')}: {exc}")
        return None
    if not isinstance(parsed, dict):
        errors.append(f"bundle source artifact JSON must be an object: {artifact.get('path')}")
        return None
    return parsed


def _chain_has_roadmap_audit(chain: EvidenceChain, audit_hash: str) -> bool:
    for entry in chain.entries:
        payload = entry.get("payload", {})
        if entry.get("entry_type") == ROADMAP_AUDIT_ENTRY_TYPE and isinstance(payload, dict):
            if payload.get("audit_hash") == audit_hash:
                return True
    return False


def _chain_has_external_manifest(chain: EvidenceChain, manifest_hash: str) -> bool:
    for entry in chain.entries:
        payload = entry.get("payload", {})
        if entry.get("entry_type") == EXTERNAL_EVIDENCE_ENTRY_TYPE and isinstance(payload, dict):
            if payload.get("manifest_hash") == manifest_hash:
                return True
    return False

def _chain_has_external_collection_run(chain: EvidenceChain, run_hash: str) -> bool:
    for entry in chain.entries:
        payload = entry.get("payload", {})
        if entry.get("entry_type") == EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE and isinstance(payload, dict):
            if payload.get("run_hash") == run_hash:
                return True
    return False

def _roadmap_evidence_bundle_summary(chain: EvidenceChain, report: dict[str, Any], source_artifacts: list[Any] | None = None) -> dict[str, Any]:
    report_summary = report.get("summary", {}) if isinstance(report, dict) else {}
    return {
        "report_id": report.get("report_id") if isinstance(report, dict) else None,
        "report_hash": content_hash(report),
        "chain_tree": chain.tree(),
        "chain_entry_count": len(chain.entries),
        "roadmap_audit_entry_count": report_summary.get("roadmap_audit_entry_count"),
        "external_evidence_entry_count": report_summary.get("external_evidence_entry_count"),
        "external_evidence_collection_run_entry_count": report_summary.get("external_evidence_collection_run_entry_count"),
        "complete_external_evidence_entry_count": report_summary.get("complete_external_evidence_entry_count"),
        "fresh_external_evidence_entry_count": report_summary.get("fresh_external_evidence_entry_count"),
        "source_artifact_count": len(source_artifacts or []),
        "semantic_ok": report_summary.get("semantic_ok"),
    }


def _roadmap_evidence_summary(
    chain: EvidenceChain,
    result: RoadmapEvidenceChainVerification,
) -> dict[str, Any]:
    return {
        "semantic_ok": result.ok,
        "chain_entry_count": len(chain.entries),
        "roadmap_audit_entry_count": result.audit_entry_count,
        "external_evidence_entry_count": result.external_evidence_entry_count,
        "external_evidence_collection_run_entry_count": result.external_evidence_collection_run_entry_count,
        "complete_external_evidence_entry_count": result.complete_external_evidence_entry_count,
        "fresh_external_evidence_entry_count": result.fresh_external_evidence_entry_count,
        "has_external_evidence": result.external_evidence_entry_count > 0,
        "has_external_evidence_collection_runs": result.external_evidence_collection_run_entry_count > 0,
        "has_complete_external_evidence": result.complete_external_evidence_entry_count > 0,
        "has_fresh_external_evidence": result.fresh_external_evidence_entry_count > 0,
    }


def _roadmap_evidence_verification_record(result: RoadmapEvidenceChainVerification) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "errors": result.errors,
        "warnings": result.warnings,
        "audit_entry_count": result.audit_entry_count,
        "external_evidence_entry_count": result.external_evidence_entry_count,
        "external_evidence_collection_run_entry_count": result.external_evidence_collection_run_entry_count,
        "complete_external_evidence_entry_count": result.complete_external_evidence_entry_count,
        "fresh_external_evidence_entry_count": result.fresh_external_evidence_entry_count,
    }


def _roadmap_audit_entry_records(chain: EvidenceChain) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for entry in chain.entries:
        if entry.get("entry_type") != ROADMAP_AUDIT_ENTRY_TYPE:
            continue
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}
        records.append(
            {
                "index": entry.get("index"),
                "entry_id": entry.get("entry_id"),
                "timestamp": entry.get("timestamp"),
                "audit_id": payload.get("audit_id"),
                "audit_hash": payload.get("audit_hash"),
                "completion_position": payload.get("completion_position"),
                "requirement_count": payload.get("requirement_count"),
                "implemented_local_count": payload.get("implemented_local_count"),
                "reference_attested_count": payload.get("reference_attested_count"),
                "missing_local_evidence_count": payload.get("missing_local_evidence_count"),
                "deferred_external_count": payload.get("deferred_external_count"),
            }
        )
    return records


def _external_evidence_entry_records(chain: EvidenceChain) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for entry in chain.entries:
        if entry.get("entry_type") != EXTERNAL_EVIDENCE_ENTRY_TYPE:
            continue
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}
        proof = payload.get("source_roadmap_audit_inclusion_proof")
        proof_record = None
        if isinstance(proof, dict):
            proof_record = {
                "entry_id": proof.get("entry_id"),
                "index": proof.get("index"),
                "tree_size": proof.get("tree_size"),
                "tree_root": proof.get("tree_root"),
            }
        records.append(
            {
                "index": entry.get("index"),
                "entry_id": entry.get("entry_id"),
                "timestamp": entry.get("timestamp"),
                "manifest_id": payload.get("manifest_id"),
                "manifest_hash": payload.get("manifest_hash"),
                "manifest_ref": payload.get("manifest_ref"),
                "source_roadmap_audit": payload.get("source_roadmap_audit"),
                "source_roadmap_audit_inclusion_proof": proof_record,
                "status": payload.get("status"),
                "require_complete": payload.get("require_complete"),
                "require_fresh": payload.get("require_fresh"),
                "require_live_source_uris": payload.get("require_live_source_uris"),
                "require_source_snapshot_artifacts": payload.get("require_source_snapshot_artifacts"),
                "require_fresh_source_snapshot_artifacts": payload.get("require_fresh_source_snapshot_artifacts"),
                "freshness_checked_at": payload.get("freshness_checked_at"),
                "required_requirement_count": payload.get("required_requirement_count"),
                "covered_requirement_count": payload.get("covered_requirement_count"),
                "missing_requirement_count": payload.get("missing_requirement_count"),
                "required_authority_kind_count": payload.get("required_authority_kind_count"),
                "covered_authority_kind_count": payload.get("covered_authority_kind_count"),
                "missing_authority_kind_count": payload.get("missing_authority_kind_count"),
                "evidence_count": payload.get("evidence_count"),
                "issued_at_count": payload.get("issued_at_count"),
                "expires_at_count": payload.get("expires_at_count"),
                "freshness_window_count": payload.get("freshness_window_count"),
                "fresh_evidence_count": payload.get("fresh_evidence_count"),
                "stale_evidence_count": payload.get("stale_evidence_count"),
                "missing_freshness_count": payload.get("missing_freshness_count"),
                "covered_requirement_ids": payload.get("covered_requirement_ids", []),
                "missing_requirement_ids": payload.get("missing_requirement_ids", []),
                "covered_authority_kinds_by_requirement": payload.get("covered_authority_kinds_by_requirement", {}),
                "missing_authority_kinds_by_requirement": payload.get("missing_authority_kinds_by_requirement", {}),
            }
        )
    return records


def _external_evidence_collection_run_entry_records(chain: EvidenceChain) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for entry in chain.entries:
        if entry.get("entry_type") != EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE:
            continue
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}
        proof = payload.get("source_roadmap_audit_inclusion_proof")
        proof_record = None
        if isinstance(proof, dict):
            proof_record = {
                "entry_id": proof.get("entry_id"),
                "index": proof.get("index"),
                "tree_size": proof.get("tree_size"),
                "tree_root": proof.get("tree_root"),
            }
        records.append(
            {
                "index": entry.get("index"),
                "entry_id": entry.get("entry_id"),
                "timestamp": entry.get("timestamp"),
                "run_id": payload.get("run_id"),
                "run_hash": payload.get("run_hash"),
                "source_map": payload.get("source_map"),
                "source_map_hash": payload.get("source_map_hash"),
                "source_plan": payload.get("source_plan"),
                "source_manifest": payload.get("source_manifest"),
                "source_roadmap_audit": payload.get("source_roadmap_audit"),
                "source_roadmap_audit_inclusion_proof": proof_record,
                "require_fresh": payload.get("require_fresh"),
                "require_live_source_uris": payload.get("require_live_source_uris"),
                "require_source_snapshot_artifacts": payload.get("require_source_snapshot_artifacts"),
                "require_fresh_source_snapshot_artifacts": payload.get("require_fresh_source_snapshot_artifacts"),
                "freshness_checked_at": payload.get("freshness_checked_at"),
                "collected_count": payload.get("collected_count"),
                "task_count": payload.get("task_count"),
                "collected_tasks": payload.get("collected_tasks", []),
                "snapshot_ids": payload.get("snapshot_ids", []),
                "intake_ids": payload.get("intake_ids", []),
            }
        )
    return records


def _verify_source_roadmap_audit_inclusion_proof(
    chain: EvidenceChain,
    audit_entry: dict[str, Any],
    external_entry: dict[str, Any],
    proof: dict[str, Any],
    errors: list[str],
    *,
    label: str = "external evidence entry",
) -> None:
    if proof.get("entry_id") != audit_entry.get("entry_id"):
        errors.append(f"{label} {external_entry.get('index')} source audit proof entry_id mismatch")
    if proof.get("index") != audit_entry.get("index"):
        errors.append(f"{label} {external_entry.get('index')} source audit proof index mismatch")

    tree_size = proof.get("tree_size")
    if not isinstance(tree_size, int):
        errors.append(f"{label} {external_entry.get('index')} source audit proof tree_size invalid")
        return
    audit_index = int(audit_entry.get("index", -1))
    external_index = int(external_entry.get("index", -1))
    if tree_size <= audit_index:
        errors.append(f"{label} {external_entry.get('index')} source audit proof tree_size excludes audit entry")
        return
    if tree_size > external_index:
        errors.append(f"{label} {external_entry.get('index')} source audit proof was not recorded before append")
        return

    prefix_ids = chain.entry_ids()[:tree_size]
    expected_root = merkle_root(prefix_ids)
    if proof.get("tree_root") != expected_root:
        errors.append(f"{label} {external_entry.get('index')} source audit proof tree_root mismatch")
    audit_path = proof.get("audit_path")
    if not isinstance(audit_path, list):
        errors.append(f"{label} {external_entry.get('index')} source audit proof audit_path invalid")
        return
    if not verify_inclusion(str(audit_entry.get("entry_id")), audit_path, str(proof.get("tree_root") or "")):
        errors.append(f"{label} {external_entry.get('index')} source audit proof inclusion failed")


def _verify_external_evidence_entry_summary(
    entry: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    require_complete: bool,
    require_fresh: bool,
) -> None:
    payload = entry.get("payload", {})
    required = payload.get("required_requirement_count")
    covered = payload.get("covered_requirement_count")
    missing = payload.get("missing_requirement_count")
    status = payload.get("status")
    if all(isinstance(value, int) for value in (required, covered, missing)) and covered + missing != required:
        errors.append(f"external evidence entry {entry.get('index')} coverage counts do not add up")
    missing_authority = payload.get("missing_authority_kind_count")
    covered_authority = payload.get("covered_authority_kind_count")
    required_authority = payload.get("required_authority_kind_count")
    has_authority_counts = all(isinstance(value, int) for value in (required_authority, covered_authority, missing_authority))
    if has_authority_counts and covered_authority + missing_authority != required_authority:
        errors.append(f"external evidence entry {entry.get('index')} authority-kind coverage counts do not add up")
    if status == "complete" and missing != 0:
        errors.append(f"external evidence entry {entry.get('index')} is complete but has missing requirements")
    if status == "complete" and not has_authority_counts:
        errors.append(f"external evidence entry {entry.get('index')} is complete but missing authority-kind coverage metadata")
    if status == "complete" and has_authority_counts and missing_authority != 0:
        errors.append(f"external evidence entry {entry.get('index')} is complete but has missing authority kinds")
    if status != "complete":
        message = f"external evidence entry {entry.get('index')} is partial"
        if require_complete:
            errors.append(message)
        else:
            warnings.append(message)
    stale = payload.get("stale_evidence_count")
    missing_freshness = payload.get("missing_freshness_count")
    if require_fresh:
        if payload.get("require_fresh") is not True:
            errors.append(f"external evidence entry {entry.get('index')} was not appended with freshness required")
        if stale != 0:
            errors.append(f"external evidence entry {entry.get('index')} has stale evidence")
        if missing_freshness != 0:
            errors.append(f"external evidence entry {entry.get('index')} has evidence without freshness metadata")
    elif stale:
        warnings.append(f"external evidence entry {entry.get('index')} has stale evidence")
    elif missing_freshness:
        warnings.append(f"external evidence entry {entry.get('index')} has evidence without freshness metadata")


def _verify_external_evidence_collection_run_entry_summary(entry: dict[str, Any], errors: list[str]) -> None:
    payload = entry.get("payload", {})
    if not isinstance(payload, dict):
        errors.append(f"external evidence collection run entry {entry.get('index')} payload must be an object")
        return
    for field in ("run_id", "run_hash", "source_map_hash"):
        if not isinstance(payload.get(field), str) or not payload.get(field):
            errors.append(f"external evidence collection run entry {entry.get('index')} missing {field}")
    source_map = payload.get("source_map")
    if not isinstance(source_map, dict):
        errors.append(f"external evidence collection run entry {entry.get('index')} source_map must be an object")
    elif source_map.get("source_map_hash") != payload.get("source_map_hash"):
        errors.append(f"external evidence collection run entry {entry.get('index')} source_map hash mismatch")
    collected_count = payload.get("collected_count")
    task_count = payload.get("task_count")
    collected_tasks = payload.get("collected_tasks")
    snapshot_ids = payload.get("snapshot_ids")
    intake_ids = payload.get("intake_ids")
    if not isinstance(collected_tasks, list) or any(not isinstance(value, str) for value in collected_tasks):
        errors.append(f"external evidence collection run entry {entry.get('index')} collected_tasks must be a list of strings")
        collected_tasks = []
    if not isinstance(snapshot_ids, list) or any(not isinstance(value, str) for value in snapshot_ids):
        errors.append(f"external evidence collection run entry {entry.get('index')} snapshot_ids must be a list of strings")
        snapshot_ids = []
    if not isinstance(intake_ids, list) or any(not isinstance(value, str) for value in intake_ids):
        errors.append(f"external evidence collection run entry {entry.get('index')} intake_ids must be a list of strings")
        intake_ids = []
    if isinstance(collected_count, int):
        if len(collected_tasks) != collected_count:
            errors.append(f"external evidence collection run entry {entry.get('index')} collected_count does not match collected_tasks")
        if len(snapshot_ids) != collected_count:
            errors.append(f"external evidence collection run entry {entry.get('index')} collected_count does not match snapshot_ids")
        if len(intake_ids) != collected_count:
            errors.append(f"external evidence collection run entry {entry.get('index')} collected_count does not match intake_ids")
    else:
        errors.append(f"external evidence collection run entry {entry.get('index')} collected_count must be an integer")
    if isinstance(task_count, int):
        if len(set(collected_tasks)) != task_count:
            errors.append(f"external evidence collection run entry {entry.get('index')} task_count does not match unique collected tasks")
    else:
        errors.append(f"external evidence collection run entry {entry.get('index')} task_count must be an integer")
    if payload.get("require_source_snapshot_artifacts") is not True:
        errors.append(f"external evidence collection run entry {entry.get('index')} was not appended with source snapshot artifact verification")


def _source_roadmap_audit_proof(chain: EvidenceChain, source_roadmap_audit: Any) -> dict[str, Any] | None:
    if not isinstance(source_roadmap_audit, dict):
        return None
    audit_id = source_roadmap_audit.get("audit_id")
    audit_hash = source_roadmap_audit.get("audit_hash")
    for entry in chain.entries:
        payload = entry.get("payload", {})
        if (
            entry.get("entry_type") == ROADMAP_AUDIT_ENTRY_TYPE
            and payload.get("audit_id") == audit_id
            and payload.get("audit_hash") == audit_hash
        ):
            return chain.proof_for(entry)
    return None

def _reference_attested_requirements(roadmap_audit: dict[str, Any]) -> list[dict[str, Any]]:
    requirements = roadmap_audit.get("requirements", [])
    if not isinstance(requirements, list):
        return []
    return [
        requirement
        for requirement in requirements
        if isinstance(requirement, dict) and requirement.get("status") == STATUS_REFERENCE_ATTESTED
    ]


def _build_evidence_item(
    root: Path,
    item: dict[str, Any],
    required_ids: list[str],
    required_authority_kinds: dict[str, list[str]],
) -> dict[str, Any]:
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    path = str(item.get("path") or "")
    if requirement_id not in required_ids:
        raise ValueError(f"unknown or non-external roadmap requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    allowed_authority_kinds = required_authority_kinds.get(requirement_id, ["other"])
    if authority_kind not in allowed_authority_kinds:
        raise ValueError(
            f"authority kind {authority_kind} is not accepted for requirement {requirement_id}; "
            f"expected one of {', '.join(allowed_authority_kinds)}"
        )
    if not path:
        raise ValueError("external evidence path is required")
    file_ref = _file_ref(root, path)
    if not file_ref["present"]:
        raise ValueError(f"external evidence file is missing: {path}")
    body = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "accepted_authority_kinds": allowed_authority_kinds,
        "path": file_ref["path"],
        "sha256": file_ref["sha256"],
        "description": str(item.get("description") or ""),
        "issuer": item.get("issuer"),
        "subject": item.get("subject"),
        "source_uri": item.get("source_uri"),
        "issued_at": item.get("issued_at"),
        "expires_at": item.get("expires_at"),
    }
    return {**body, "evidence_id": content_hash(body)}


def _freshness_reference(manifest: dict[str, Any], now: str | None, errors: list[str]):
    reference = now or manifest.get("generated_at")
    if not reference:
        return None
    try:
        return parse_rfc3339(str(reference))
    except ValueError as exc:
        label = "now" if now else "generated_at"
        errors.append(f"external evidence freshness {label} invalid: {exc}")
        return None


def _parse_optional_timestamp(item: dict[str, Any], field: str, errors: list[str]):
    value = item.get(field)
    if not value:
        return None
    try:
        return parse_rfc3339(str(value))
    except ValueError as exc:
        errors.append(f"external evidence {field} invalid: {exc}")
        return None


def _freshness_problem(message: str, errors: list[str], warnings: list[str], *, require_fresh: bool) -> None:
    if require_fresh:
        errors.append(message)
    else:
        warnings.append(message)


def _verify_evidence_item(
    root: Path,
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    now,
    require_fresh: bool,
    require_live_source_uris: bool,
    allowed_authority_kinds: list[str],
) -> str:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"evidence_id does not match evidence body: {item.get('requirement_id')}")
    authority_kind = item.get("authority_kind")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    elif allowed_authority_kinds and authority_kind not in allowed_authority_kinds:
        errors.append(
            f"authority kind {authority_kind} is not accepted for requirement {item.get('requirement_id')}; "
            f"expected one of {', '.join(allowed_authority_kinds)}"
        )
    if item.get("accepted_authority_kinds") != allowed_authority_kinds:
        errors.append(f"accepted_authority_kinds do not match requirement policy: {item.get('requirement_id')}")
    if not item.get("description"):
        errors.append(f"external evidence description is required: {item.get('requirement_id')}")
    source_uri = str(item.get("source_uri") or "")
    if _source_map_is_placeholder_uri(source_uri):
        source_uri_message = (
            "external evidence source_uri is placeholder or missing for "
            f"{item.get('requirement_id')}:{item.get('authority_kind')}"
        )
        if require_live_source_uris:
            errors.append(source_uri_message)
        else:
            warnings.append(source_uri_message)

    issued_at = _parse_optional_timestamp(item, "issued_at", errors)
    expires_at = _parse_optional_timestamp(item, "expires_at", errors)
    freshness_status = "fresh"
    missing_fields = [field for field in ("issued_at", "expires_at") if not item.get(field)]
    if missing_fields:
        freshness_status = "missing"
        _freshness_problem(
            f"external evidence freshness metadata missing for {item.get('requirement_id')}: {', '.join(missing_fields)}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        freshness_status = "stale"
        errors.append(f"external evidence expires_at must be after issued_at: {item.get('requirement_id')}")
    if now is not None and issued_at is not None and issued_at > now:
        freshness_status = "stale"
        _freshness_problem(
            f"external evidence is not yet issued for {item.get('requirement_id')}: {item.get('issued_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    if now is not None and expires_at is not None and expires_at <= now:
        freshness_status = "stale"
        _freshness_problem(
            f"external evidence expired for {item.get('requirement_id')}: {item.get('expires_at')}",
            errors,
            warnings,
            require_fresh=require_fresh,
        )
    _verify_file_ref(root, item, errors)
    return freshness_status


def _verify_evidence_item_source_snapshot_artifact(
    root: Path,
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    *,
    require_fresh: bool,
    now: str | None,
    label: str = "intake",
) -> None:
    artifact_path_value = item.get("path")
    if not isinstance(artifact_path_value, str):
        artifact_path_value = ""
    try:
        artifact_path = _resolve_evidence_item_artifact_path(root, artifact_path_value)
    except ValueError as exc:
        errors.append(f"{label} source snapshot artifact {exc}")
        return
    if not artifact_path.is_file():
        errors.append(f"{label} source snapshot artifact does not exist: {artifact_path_value}")
        return
    try:
        snapshot = load_external_evidence_source_snapshot(artifact_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"{label} source snapshot artifact is not a readable source snapshot: {exc}")
        return
    snapshot_result = verify_external_evidence_source_snapshot(
        snapshot,
        require_fresh=require_fresh,
        now=now,
    )
    warnings.extend(f"{label} source snapshot artifact: {warning}" for warning in snapshot_result.warnings)
    if not snapshot_result.ok:
        errors.extend(f"{label} source snapshot artifact: {error}" for error in snapshot_result.errors)
    if str(snapshot.get("source_uri") or "") != str(item.get("source_uri") or ""):
        errors.append(f"{label} source snapshot artifact source_uri does not match evidence source_uri")
    status_code = snapshot.get("status_code")
    if isinstance(status_code, int) and (status_code < 200 or status_code >= 400):
        errors.append(f"{label} source snapshot artifact status_code is not successful: {status_code}")


def _collection_run_source_map_tasks(source_map: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    if source_map.get("schema") != EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA:
        errors.append(f"unsupported external evidence source map schema: {source_map.get('schema')}")
    defaults = source_map.get("defaults", {})
    if not isinstance(defaults, dict):
        errors.append("external evidence source map defaults must be an object")
        defaults = {}
    entries = source_map.get("entries", [])
    if not isinstance(entries, list):
        errors.append("external evidence source map entries must be a list")
        entries = []

    tasks: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"external evidence source map entry {index} must be an object")
            continue
        task_value = None
        for key in SOURCE_MAP_FULFILLMENT_TASK_KEYS:
            task_value = _source_map_effective_value(entry, defaults, key)
            if task_value:
                break
        task = str(task_value or "")
        if not task:
            errors.append(f"external evidence source map entry {index} missing task")
            continue
        if task in tasks:
            errors.append(f"duplicate external evidence source map task: {task}")
            continue
        source_uri = _source_map_effective_value(entry, defaults, "source_uri")
        description = _source_map_effective_value(entry, defaults, "description")
        if not str(source_uri or ""):
            errors.append(f"external evidence source map entry {index} missing source_uri")
        if not str(description or ""):
            errors.append(f"external evidence source map entry {index} missing description")
        tasks[task] = {
            "source_uri": source_uri,
            "description": description,
            "snapshot_out": _source_map_effective_value(entry, defaults, "snapshot_out"),
            "intake_out": _source_map_effective_value(entry, defaults, "intake_out"),
        }
    return tasks


def _resolve_collection_run_file_path(root: str | Path, path_value: Any, label: str) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise ValueError(f"{label} is required")
    candidate = Path(path_value)
    windows_candidate = PureWindowsPath(path_value)
    if not candidate.is_absolute() and not windows_candidate.is_absolute() and not windows_candidate.drive:
        if not _is_safe_relative_path(path_value):
            raise ValueError(f"{label} must be repository-relative or absolute: {path_value}")
        candidate = Path(root) / path_value
    return candidate.resolve()


def _allowed_authority_kinds_for_requirement(requirement: dict[str, Any]) -> list[str]:
    text = " ".join(str(item) for item in requirement.get("external_authority_required", [])).lower()
    allowed = [
        kind
        for kind, needles in AUTHORITY_KIND_KEYWORDS.items()
        if any(needle in text for needle in needles)
    ]
    return allowed or ["other"]


def _authority_unit_id(requirement_id: str, authority_kind: str) -> str:
    return content_hash({"authority_kind": authority_kind, "requirement_id": requirement_id})


def _authority_evidence_units(
    requirements: list[dict[str, Any]],
    required_authority_kinds: dict[str, list[str]],
    summary: dict[str, Any],
) -> list[dict[str, Any]]:
    covered = summary.get("covered_authority_kinds_by_requirement", {})
    if not isinstance(covered, dict):
        covered = {}
    units: list[dict[str, Any]] = []
    for requirement in requirements:
        requirement_id = str(requirement.get("id") or "")
        covered_kinds = covered.get(requirement_id, [])
        if not isinstance(covered_kinds, list):
            covered_kinds = []
        for authority_kind in required_authority_kinds.get(requirement_id, []):
            units.append(
                {
                    "unit_id": _authority_unit_id(requirement_id, authority_kind),
                    "unit_ref": f"{requirement_id}:{authority_kind}",
                    "requirement_id": requirement_id,
                    "phase": requirement.get("phase"),
                    "priority": requirement.get("priority"),
                    "title": requirement.get("title"),
                    "authority_kind": authority_kind,
                    "coverage_status": "covered" if authority_kind in covered_kinds else "missing",
                    "external_authority_required": requirement.get("external_authority_required", []),
                }
            )
    return units

def _collection_status_matches(unit: dict[str, Any], status_filter: str) -> bool:
    if status_filter == "all":
        return True
    return unit.get("coverage_status") == status_filter


def _authority_collection_task(unit: dict[str, Any]) -> dict[str, Any]:
    requirement_id = str(unit.get("requirement_id") or "")
    authority_kind = str(unit.get("authority_kind") or "other")
    unit_id = str(unit.get("unit_id") or "")
    unit_ref = str(unit.get("unit_ref") or f"{requirement_id}:{authority_kind}")
    suggested_artifact_path = f"external-evidence/{requirement_id}/{authority_kind}.json"
    description = f"{authority_kind} evidence for {requirement_id}"
    return {
        "task_id": content_hash({"task_kind": "external-authority-evidence", "unit_id": unit_id, "unit_ref": unit_ref}),
        "task_ref": f"external-evidence:{unit_ref}",
        "unit_id": unit_id,
        "unit_ref": unit_ref,
        "requirement_id": requirement_id,
        "phase": unit.get("phase"),
        "priority": unit.get("priority"),
        "title": unit.get("title"),
        "authority_kind": authority_kind,
        "coverage_status": unit.get("coverage_status"),
        "owner_hint": AUTHORITY_KIND_OWNER_HINTS.get(authority_kind, AUTHORITY_KIND_OWNER_HINTS["other"]),
        "suggested_artifact_path": suggested_artifact_path,
        "evidence_argument_template": (
            f"{requirement_id},{authority_kind},{suggested_artifact_path},{description}"
            ";issuer=<issuer>;subject=<subject>;source_uri=<source-uri>;issued_at=<rfc3339>;expires_at=<rfc3339>"
        ),
        "suggested_evidence_sources": AUTHORITY_KIND_EVIDENCE_HINTS.get(authority_kind, AUTHORITY_KIND_EVIDENCE_HINTS["other"]),
        "acceptance_criteria": [
            "Artifact path must be repository-relative and hashable before manifest verification.",
            f"Evidence item authority_kind must be {authority_kind} and accepted for {requirement_id}.",
            "Use issued_at and expires_at metadata when strict freshness verification is required.",
            "Rebuild and verify the external evidence manifest after adding the artifact.",
        ],
        "external_authority_required": unit.get("external_authority_required", []),
    }


def _collection_plan_summary(manifest: dict[str, Any], tasks: list[dict[str, Any]]) -> dict[str, Any]:
    manifest_summary = manifest.get("summary", {})
    if not isinstance(manifest_summary, dict):
        manifest_summary = {}
    units = manifest.get("required_authority_evidence_units", [])
    if not isinstance(units, list):
        units = []
    return {
        "source_manifest_status": manifest_summary.get("status"),
        "total_authority_unit_count": len(units),
        "selected_task_count": len(tasks),
        "selected_missing_task_count": sum(1 for task in tasks if task.get("coverage_status") == "missing"),
        "selected_covered_task_count": sum(1 for task in tasks if task.get("coverage_status") == "covered"),
        "required_authority_kind_count": manifest_summary.get("required_authority_kind_count", 0),
        "covered_authority_kind_count": manifest_summary.get("covered_authority_kind_count", 0),
        "missing_authority_kind_count": manifest_summary.get("missing_authority_kind_count", 0),
        "task_count_by_authority_kind": _count_tasks_by(tasks, "authority_kind"),
        "missing_task_count_by_authority_kind": _count_tasks_by(
            [task for task in tasks if task.get("coverage_status") == "missing"],
            "authority_kind",
        ),
        "task_count_by_phase": _count_tasks_by(tasks, "phase"),
    }


def _count_tasks_by(tasks: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for task in tasks:
        value = str(task.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return {value: counts[value] for value in sorted(counts)}


def _find_collection_task(plan: dict[str, Any], task_ref: str) -> dict[str, Any] | None:
    tasks = plan.get("tasks", [])
    if not isinstance(tasks, list):
        return None
    for task in tasks:
        if not isinstance(task, dict):
            continue
        refs = {
            str(task.get("task_id") or ""),
            str(task.get("task_ref") or ""),
            str(task.get("unit_id") or ""),
            str(task.get("unit_ref") or ""),
        }
        if task_ref in refs:
            return task
    return None


def _collection_plan_source_record(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": plan.get("plan_id"),
        "plan_hash": content_hash(plan),
        "status_filter": plan.get("status_filter"),
        "source_manifest": plan.get("source_manifest"),
    }


def _collection_intake_manifest_record(manifest: dict[str, Any]) -> dict[str, Any]:
    summary = manifest.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    return {
        "manifest_id": manifest.get("manifest_id"),
        "manifest_hash": content_hash(manifest),
        "manifest_ref": manifest.get("manifest_ref"),
        "status": summary.get("status"),
        "required_authority_kind_count": summary.get("required_authority_kind_count", 0),
        "covered_authority_kind_count": summary.get("covered_authority_kind_count", 0),
        "missing_authority_kind_count": summary.get("missing_authority_kind_count", 0),
    }


def _intake_task_record(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task.get("task_id"),
        "task_ref": task.get("task_ref"),
        "unit_id": task.get("unit_id"),
        "unit_ref": task.get("unit_ref"),
        "requirement_id": task.get("requirement_id"),
        "authority_kind": task.get("authority_kind"),
        "coverage_status": task.get("coverage_status"),
        "suggested_artifact_path": task.get("suggested_artifact_path"),
    }


def _evidence_argument(item: dict[str, Any]) -> str:
    description = str(item.get("description") or "")
    if ";" in description:
        raise ValueError("external evidence description cannot contain ';'")
    metadata = []
    for key in ("issuer", "subject", "source_uri", "issued_at", "expires_at"):
        value = item.get(key)
        if value:
            metadata.append(f"{key}={value}")
    suffix = ";" + ";".join(metadata) if metadata else ""
    return f"{item.get('requirement_id')},{item.get('authority_kind')},{item.get('path')},{description}{suffix}"


def _evidence_unit_key(item: dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("requirement_id") or ""), str(item.get("authority_kind") or ""))


def _file_ref(root: Path, path: str | Path) -> dict[str, Any]:
    relative = Path(path).as_posix()
    target = root / relative
    if _is_safe_relative_path(relative) and target.exists() and target.is_file():
        return {
            "path": relative,
            "present": True,
            "sha256": file_sha256_ref(target),
        }
    return {"path": relative, "present": False, "sha256": None}


def _verify_file_ref(root: Path, item: dict[str, Any], errors: list[str]) -> None:
    path = item.get("path")
    if not isinstance(path, str) or not path:
        errors.append("external evidence path is required")
        return
    if not _is_safe_relative_path(path):
        errors.append(f"external evidence path must be repository-relative: {path}")
        return
    target = root / path
    if not target.exists() or not target.is_file():
        errors.append(f"external evidence file missing: {path}")
        return
    actual_hash = file_sha256_ref(target)
    if item.get("sha256") != actual_hash:
        errors.append(f"external evidence hash mismatch: {path}")


def _is_safe_relative_path(path: str) -> bool:
    candidate = Path(path)
    windows_candidate = PureWindowsPath(path)
    return (
        not candidate.is_absolute()
        and not windows_candidate.is_absolute()
        and not windows_candidate.drive
        and ".." not in candidate.parts
        and ".." not in windows_candidate.parts
    )


def _summary(
    required_ids: list[str],
    evidence: list[dict[str, Any]],
    required_authority_kinds: dict[str, list[str]],
    *,
    status: str | None = None,
) -> dict[str, Any]:
    required_set = set(required_ids)
    covered = sorted({
        str(item.get("requirement_id"))
        for item in evidence
        if item.get("requirement_id") in required_set
    })
    covered_authority_kinds_by_requirement: dict[str, list[str]] = {}
    missing_authority_kinds_by_requirement: dict[str, list[str]] = {}
    for requirement_id in required_ids:
        allowed = required_authority_kinds.get(requirement_id, [])
        observed = {
            str(item.get("authority_kind"))
            for item in evidence
            if item.get("requirement_id") == requirement_id
            and item.get("authority_kind") in allowed
        }
        covered_kinds = [authority_kind for authority_kind in allowed if authority_kind in observed]
        missing_kinds = [authority_kind for authority_kind in allowed if authority_kind not in observed]
        if covered_kinds:
            covered_authority_kinds_by_requirement[requirement_id] = covered_kinds
        if missing_kinds:
            missing_authority_kinds_by_requirement[requirement_id] = missing_kinds
    missing = [requirement_id for requirement_id in required_ids if requirement_id not in covered]
    required_authority_kind_count = sum(len(required_authority_kinds.get(requirement_id, [])) for requirement_id in required_ids)
    covered_authority_kind_count = sum(len(kinds) for kinds in covered_authority_kinds_by_requirement.values())
    missing_authority_kind_count = sum(len(kinds) for kinds in missing_authority_kinds_by_requirement.values())
    computed_status = "complete" if not missing and missing_authority_kind_count == 0 else "partial"
    return {
        "status": status or computed_status,
        "required_requirement_count": len(required_ids),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "required_authority_kind_count": required_authority_kind_count,
        "covered_authority_kind_count": covered_authority_kind_count,
        "missing_authority_kind_count": missing_authority_kind_count,
        "evidence_count": len(evidence),
        "issued_at_count": sum(1 for item in evidence if item.get("issued_at")),
        "expires_at_count": sum(1 for item in evidence if item.get("expires_at")),
        "freshness_window_count": sum(1 for item in evidence if item.get("issued_at") and item.get("expires_at")),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
        "covered_authority_kinds_by_requirement": covered_authority_kinds_by_requirement,
        "missing_authority_kinds_by_requirement": missing_authority_kinds_by_requirement,
    }
