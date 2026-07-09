from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .roadmap_audit import STATUS_REFERENCE_ATTESTED, verify_roadmap_audit

EXTERNAL_EVIDENCE_SCHEMA = "trustai.external-evidence-manifest/0.1"
EXTERNAL_EVIDENCE_ENTRY_TYPE = "trustai.external_evidence_manifest.attested"

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


@dataclass
class ExternalEvidenceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    covered_count: int = 0
    required_count: int = 0


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
    evidence_items = [
        _build_evidence_item(root_path, item, required_ids)
        for item in (evidence or [])
    ]
    summary = _summary(required_ids, evidence_items, status=status)
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
            }
            for requirement in requirements
        ],
        "evidence": evidence_items,
        "summary": summary,
        "limitations": [
            "This manifest verifies supplied external evidence artifacts by hash; it does not fetch live provider state.",
            "A complete manifest requires at least one evidence item for every reference-attested roadmap requirement.",
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
) -> ExternalEvidenceVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

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

    required_ids = [requirement["id"] for requirement in _reference_attested_requirements(roadmap_audit)]
    required_set = set(required_ids)
    declared_requirements = manifest.get("required_external_requirements", [])
    if not isinstance(declared_requirements, list):
        errors.append("required_external_requirements must be a list")
        declared_requirements = []
    declared_ids = [item.get("id") for item in declared_requirements if isinstance(item, dict)]
    if declared_ids != required_ids:
        errors.append("required_external_requirements do not match reference-attested roadmap requirements")

    evidence = manifest.get("evidence", [])
    if not isinstance(evidence, list):
        errors.append("evidence must be a list")
        evidence = []
    covered_ids: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("external evidence item must be an object")
            continue
        requirement_id = str(item.get("requirement_id") or "")
        if requirement_id not in required_set:
            errors.append(f"external evidence requirement_id is not reference-attested: {requirement_id}")
        else:
            covered_ids.add(requirement_id)
        _verify_evidence_item(root_path, item, errors)

    expected_summary = _summary(required_ids, [item for item in evidence if isinstance(item, dict)])
    if manifest.get("summary") != expected_summary:
        errors.append("summary does not match evidence coverage")

    missing = [requirement_id for requirement_id in required_ids if requirement_id not in covered_ids]
    if missing:
        warnings.append("external evidence missing for: " + ", ".join(missing))
    if require_complete and missing:
        errors.append("external evidence manifest is incomplete")

    return ExternalEvidenceVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        covered_count=len(covered_ids),
        required_count=len(required_ids),
    )



def append_external_evidence_manifest(
    chain: EvidenceChain,
    manifest: dict[str, Any],
    roadmap_audit: dict[str, Any],
    *,
    root: str | Path,
    require_complete: bool = False,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_external_evidence_manifest(
        manifest,
        roadmap_audit,
        root=root,
        require_complete=require_complete,
    )
    if not result.ok:
        raise ValueError("invalid external evidence manifest: " + "; ".join(result.errors))
    summary = manifest.get("summary", {})
    payload = {
        "manifest_id": manifest["manifest_id"],
        "manifest_hash": content_hash(manifest),
        "manifest_ref": manifest.get("manifest_ref"),
        "source_roadmap_audit": manifest.get("source_roadmap_audit"),
        "status": summary.get("status"),
        "require_complete": require_complete,
        "required_requirement_count": summary.get("required_requirement_count"),
        "covered_requirement_count": summary.get("covered_requirement_count"),
        "missing_requirement_count": summary.get("missing_requirement_count"),
        "evidence_count": summary.get("evidence_count"),
        "covered_requirement_ids": summary.get("covered_requirement_ids", []),
        "missing_requirement_ids": summary.get("missing_requirement_ids", []),
        "limitations": manifest.get("limitations", []),
    }
    return chain.append(EXTERNAL_EVIDENCE_ENTRY_TYPE, payload, key=key, timestamp=manifest.get("generated_at"))

def parse_evidence_arg(value: str) -> dict[str, Any]:
    parts = value.split(",", 3)
    if len(parts) != 4:
        raise ValueError("evidence must be requirement_id,authority_kind,path,description")
    requirement_id, authority_kind, path, description = [part.strip() for part in parts]
    return {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
        "path": path,
        "description": description,
    }


def write_external_evidence_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def load_external_evidence_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_markdown(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_markdown(manifest), encoding="utf-8")


def render_external_evidence_markdown(manifest: dict[str, Any]) -> str:
    rows = "\n".join(
        "| {requirement} | {kind} | `{path}` | {description} |".format(
            requirement=item.get("requirement_id", ""),
            kind=item.get("authority_kind", ""),
            path=item.get("path", ""),
            description=item.get("description", ""),
        )
        for item in manifest.get("evidence", [])
    )
    missing = manifest.get("summary", {}).get("missing_requirement_ids", [])
    missing_lines = "\n".join(f"- `{requirement_id}`" for requirement_id in missing)
    summary = manifest.get("summary", {})
    return f"""# TrustAI External Evidence Manifest

Manifest ID: `{manifest.get('manifest_id', '')}`

Status: {summary.get('status', '')}

## Coverage

- Required external requirements: {summary.get('required_requirement_count', 0)}
- Covered requirements: {summary.get('covered_requirement_count', 0)}
- Evidence items: {summary.get('evidence_count', 0)}

## Evidence

| Requirement | Authority | Artifact | Description |
|---|---|---|---|
{rows}

## Missing Requirements

{missing_lines or "- None"}
"""


def _reference_attested_requirements(roadmap_audit: dict[str, Any]) -> list[dict[str, Any]]:
    requirements = roadmap_audit.get("requirements", [])
    if not isinstance(requirements, list):
        return []
    return [
        requirement
        for requirement in requirements
        if isinstance(requirement, dict) and requirement.get("status") == STATUS_REFERENCE_ATTESTED
    ]


def _build_evidence_item(root: Path, item: dict[str, Any], required_ids: list[str]) -> dict[str, Any]:
    requirement_id = str(item.get("requirement_id") or "")
    authority_kind = str(item.get("authority_kind") or "")
    path = str(item.get("path") or "")
    if requirement_id not in required_ids:
        raise ValueError(f"unknown or non-external roadmap requirement: {requirement_id}")
    if authority_kind not in AUTHORITY_KINDS:
        raise ValueError(f"unsupported authority kind: {authority_kind}")
    if not path:
        raise ValueError("external evidence path is required")
    file_ref = _file_ref(root, path)
    if not file_ref["present"]:
        raise ValueError(f"external evidence file is missing: {path}")
    body = {
        "requirement_id": requirement_id,
        "authority_kind": authority_kind,
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


def _verify_evidence_item(root: Path, item: dict[str, Any], errors: list[str]) -> None:
    if item.get("evidence_id") != content_hash(without_keys(item, "evidence_id")):
        errors.append(f"evidence_id does not match evidence body: {item.get('requirement_id')}")
    authority_kind = item.get("authority_kind")
    if authority_kind not in AUTHORITY_KINDS:
        errors.append(f"unsupported authority kind: {authority_kind}")
    if not item.get("description"):
        errors.append(f"external evidence description is required: {item.get('requirement_id')}")
    for timestamp_field in ("issued_at", "expires_at"):
        value = item.get(timestamp_field)
        if value:
            try:
                parse_rfc3339(str(value))
            except ValueError as exc:
                errors.append(f"external evidence {timestamp_field} invalid: {exc}")
    _verify_file_ref(root, item, errors)


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
    return not candidate.is_absolute() and ".." not in candidate.parts


def _summary(required_ids: list[str], evidence: list[dict[str, Any]], *, status: str | None = None) -> dict[str, Any]:
    covered = sorted({
        str(item.get("requirement_id"))
        for item in evidence
        if item.get("requirement_id") in set(required_ids)
    })
    missing = [requirement_id for requirement_id in required_ids if requirement_id not in covered]
    computed_status = "complete" if not missing else "partial"
    return {
        "status": status or computed_status,
        "required_requirement_count": len(required_ids),
        "covered_requirement_count": len(covered),
        "missing_requirement_count": len(missing),
        "evidence_count": len(evidence),
        "covered_requirement_ids": covered,
        "missing_requirement_ids": missing,
    }
