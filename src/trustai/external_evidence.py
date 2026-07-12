from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PureWindowsPath
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import CHAIN_SPEC_VERSION, EvidenceChain
from .merkle import merkle_root, verify_inclusion
from .roadmap_audit import ROADMAP_AUDIT_ENTRY_TYPE, STATUS_REFERENCE_ATTESTED, verify_roadmap_audit

EXTERNAL_EVIDENCE_SCHEMA = "trustai.external-evidence-manifest/0.1"
EXTERNAL_EVIDENCE_ENTRY_TYPE = "trustai.external_evidence_manifest.attested"
ROADMAP_EVIDENCE_REPORT_SCHEMA = "trustai.roadmap-evidence-report/0.1"
ROADMAP_EVIDENCE_BUNDLE_SCHEMA = "trustai.roadmap-evidence-bundle/0.1"
EXTERNAL_EVIDENCE_COLLECTION_PLAN_SCHEMA = "trustai.external-evidence-collection-plan/0.1"
EXTERNAL_EVIDENCE_INTAKE_SCHEMA = "trustai.external-evidence-intake/0.1"
EXTERNAL_EVIDENCE_SOURCE_SNAPSHOT_SCHEMA = "trustai.external-evidence-source-snapshot/0.1"
EXTERNAL_EVIDENCE_SOURCE_MAP_SCHEMA = "trustai.external-evidence-source-map/0.1"
EXTERNAL_EVIDENCE_COLLECTION_RUN_SCHEMA = "trustai.external-evidence-collection-run/0.1"
EXTERNAL_EVIDENCE_GAP_REPORT_SCHEMA = "trustai.external-evidence-gap-report/0.1"
EXTERNAL_EVIDENCE_GIT_REMOTE_REF_EXPORT_SCHEMA = "trustai.external-evidence-git-remote-ref-export/0.1"

BUNDLE_SOURCE_ARTIFACT_KINDS = {
    "roadmap-audit",
    "external-evidence-manifest",
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
class ExternalEvidenceGapReportVerification:
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
    if not fulfillments:
        raise ValueError("at least one source map fulfillment is required")

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

    gaps: list[dict[str, Any]] = []
    for entry in source_map.get("entries", []):
        if not isinstance(entry, dict):
            continue
        gaps.append(
            {
                "task": entry.get("task"),
                "task_ref": entry.get("task_ref"),
                "task_id": entry.get("task_id"),
                "unit_id": entry.get("unit_id"),
                "unit_ref": entry.get("unit_ref"),
                "requirement_id": entry.get("requirement_id"),
                "authority_kind": entry.get("authority_kind"),
                "title": entry.get("title"),
                "owner_hint": entry.get("owner_hint"),
                "source_uri": entry.get("source_uri"),
                "snapshot_out": entry.get("snapshot_out"),
                "intake_out": entry.get("intake_out"),
                "suggested_evidence_sources": entry.get("suggested_evidence_sources", []),
                "external_authority_required": entry.get("external_authority_required", []),
            }
        )

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

    return RoadmapEvidenceChainVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        audit_entry_count=len(audit_entries),
        external_evidence_entry_count=len(external_entries),
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
            lines.append(f"- Source URI: `{gap.get('source_uri')}`")
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
        data = target.read_bytes()
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
    embedded_roadmap_audit_hashes: set[str] = set()
    embedded_external_manifest_hashes: set[str] = set()
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
        if not isinstance(path, str) or not path:
            errors.append("bundle source artifact path is required")
        elif not _is_safe_relative_path(path):
            errors.append(f"bundle source artifact path must be repository-relative: {path}")
        try:
            data = base64.b64decode(str(artifact.get("content_b64") or ""), validate=True)
        except (binascii.Error, ValueError):
            errors.append(f"bundle source artifact content_b64 invalid: {path}")
            continue
        actual_sha = "sha256:" + sha256(data).hexdigest()
        if artifact.get("sha256") != actual_sha:
            errors.append(f"bundle source artifact hash mismatch: {path}")
        if kind == "external-evidence-file" and isinstance(path, str):
            embedded_external_file_refs.add((path, actual_sha))
        decoded_artifacts.append((artifact, data))
        if kind == "external-evidence-manifest":
            manifest = _json_source_artifact(artifact, data, errors)
            if isinstance(manifest, dict):
                for evidence in manifest.get("evidence", []):
                    if isinstance(evidence, dict) and evidence.get("path") and evidence.get("sha256"):
                        manifest_evidence_refs.add((str(evidence.get("path")), str(evidence.get("sha256"))))
                manifest_hash = content_hash(manifest)
                embedded_external_manifest_hashes.add(manifest_hash)
                if not _chain_has_external_manifest(chain, manifest_hash):
                    errors.append(f"external evidence manifest artifact is not committed to bundled chain: {path}")
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
        errors,
        require_source_artifacts=require_source_artifacts,
    )
    for path, _sha in sorted(manifest_evidence_refs - embedded_external_file_refs):
        message = f"external evidence file referenced by embedded manifest is not embedded: {path}"
        if require_source_artifacts:
            errors.append(message)
        else:
            warnings.append(message)
    for artifact, _data in decoded_artifacts:
        if artifact.get("kind") != "external-evidence-file":
            continue
        ref = (str(artifact.get("path")), str(artifact.get("sha256")))
        if ref not in manifest_evidence_refs:
            warnings.append(f"external evidence file artifact is not referenced by an embedded manifest: {artifact.get('path')}")


def _verify_required_bundle_source_artifacts(
    chain: EvidenceChain,
    embedded_roadmap_audit_hashes: set[str],
    embedded_external_manifest_hashes: set[str],
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

def _roadmap_evidence_bundle_summary(chain: EvidenceChain, report: dict[str, Any], source_artifacts: list[Any] | None = None) -> dict[str, Any]:
    report_summary = report.get("summary", {}) if isinstance(report, dict) else {}
    return {
        "report_id": report.get("report_id") if isinstance(report, dict) else None,
        "report_hash": content_hash(report),
        "chain_tree": chain.tree(),
        "chain_entry_count": len(chain.entries),
        "roadmap_audit_entry_count": report_summary.get("roadmap_audit_entry_count"),
        "external_evidence_entry_count": report_summary.get("external_evidence_entry_count"),
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
        "complete_external_evidence_entry_count": result.complete_external_evidence_entry_count,
        "fresh_external_evidence_entry_count": result.fresh_external_evidence_entry_count,
        "has_external_evidence": result.external_evidence_entry_count > 0,
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


def _verify_source_roadmap_audit_inclusion_proof(
    chain: EvidenceChain,
    audit_entry: dict[str, Any],
    external_entry: dict[str, Any],
    proof: dict[str, Any],
    errors: list[str],
) -> None:
    if proof.get("entry_id") != audit_entry.get("entry_id"):
        errors.append(f"external evidence entry {external_entry.get('index')} source audit proof entry_id mismatch")
    if proof.get("index") != audit_entry.get("index"):
        errors.append(f"external evidence entry {external_entry.get('index')} source audit proof index mismatch")

    tree_size = proof.get("tree_size")
    if not isinstance(tree_size, int):
        errors.append(f"external evidence entry {external_entry.get('index')} source audit proof tree_size invalid")
        return
    audit_index = int(audit_entry.get("index", -1))
    external_index = int(external_entry.get("index", -1))
    if tree_size <= audit_index:
        errors.append(f"external evidence entry {external_entry.get('index')} source audit proof tree_size excludes audit entry")
        return
    if tree_size > external_index:
        errors.append(f"external evidence entry {external_entry.get('index')} source audit proof was not recorded before append")
        return

    prefix_ids = chain.entry_ids()[:tree_size]
    expected_root = merkle_root(prefix_ids)
    if proof.get("tree_root") != expected_root:
        errors.append(f"external evidence entry {external_entry.get('index')} source audit proof tree_root mismatch")
    audit_path = proof.get("audit_path")
    if not isinstance(audit_path, list):
        errors.append(f"external evidence entry {external_entry.get('index')} source audit proof audit_path invalid")
        return
    if not verify_inclusion(str(audit_entry.get("entry_id")), audit_path, str(proof.get("tree_root") or "")):
        errors.append(f"external evidence entry {external_entry.get('index')} source audit proof inclusion failed")


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
            "sha256": "sha256:" + sha256(target.read_bytes()).hexdigest(),
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
    actual_hash = "sha256:" + sha256(target.read_bytes()).hexdigest()
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
