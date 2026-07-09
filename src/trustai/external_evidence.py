from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .merkle import merkle_root, verify_inclusion
from .roadmap_audit import ROADMAP_AUDIT_ENTRY_TYPE, STATUS_REFERENCE_ATTESTED, verify_roadmap_audit

EXTERNAL_EVIDENCE_SCHEMA = "trustai.external-evidence-manifest/0.1"
EXTERNAL_EVIDENCE_ENTRY_TYPE = "trustai.external_evidence_manifest.attested"
ROADMAP_EVIDENCE_REPORT_SCHEMA = "trustai.roadmap-evidence-report/0.1"

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

@dataclass
class RoadmapEvidenceChainVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    audit_entry_count: int = 0
    external_evidence_entry_count: int = 0
    complete_external_evidence_entry_count: int = 0


@dataclass
class RoadmapEvidenceReportVerification:
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



def verify_roadmap_evidence_chain(
    chain: EvidenceChain,
    *,
    key: str | None = None,
    require_external: bool = False,
    require_complete: bool = False,
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

        _verify_external_evidence_entry_summary(entry, errors, warnings, require_complete=require_complete)
        if payload.get("status") == "complete" and payload.get("missing_requirement_count") == 0:
            complete_external_count += 1

    return RoadmapEvidenceChainVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        audit_entry_count=len(audit_entries),
        external_evidence_entry_count=len(external_entries),
        complete_external_evidence_entry_count=complete_external_count,
    )


def build_roadmap_evidence_report(
    chain: EvidenceChain,
    *,
    key: str | None = None,
    require_external: bool = False,
    require_complete: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    result = verify_roadmap_evidence_chain(
        chain,
        key=key,
        require_external=require_external or require_complete,
        require_complete=require_complete,
    )
    body = {
        "schema": ROADMAP_EVIDENCE_REPORT_SCHEMA,
        "generated_at": generated_at or utc_now(),
        "verification_options": {
            "require_external": require_external or require_complete,
            "require_complete": require_complete,
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
    source_audit_proof = _source_roadmap_audit_proof(chain, manifest.get("source_roadmap_audit"))
    payload = {
        "manifest_id": manifest["manifest_id"],
        "manifest_hash": content_hash(manifest),
        "manifest_ref": manifest.get("manifest_ref"),
        "source_roadmap_audit": manifest.get("source_roadmap_audit"),
        "source_roadmap_audit_inclusion_proof": source_audit_proof,
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


def write_roadmap_evidence_report(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def load_roadmap_evidence_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_external_evidence_markdown(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_external_evidence_markdown(manifest), encoding="utf-8")


def write_roadmap_evidence_markdown(path: str | Path, report: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_roadmap_evidence_markdown(report), encoding="utf-8")


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
        "| {index} | `{entry_id}` | `{manifest_id}` | {status} | {covered}/{required} | {missing} |".format(
            index=entry.get("index", ""),
            entry_id=entry.get("entry_id", ""),
            manifest_id=entry.get("manifest_id", ""),
            status=entry.get("status", ""),
            covered=entry.get("covered_requirement_count", 0),
            required=entry.get("required_requirement_count", 0),
            missing=entry.get("missing_requirement_count", 0),
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

## Roadmap Audit Entries

| Index | Entry ID | Audit ID | Implemented / Reference / Missing |
|---|---|---|---|
{audit_rows or "| - | - | - | - |"}

## External Evidence Entries

| Index | Entry ID | Manifest ID | Status | Covered / Required | Missing |
|---|---|---|---|---|---|
{external_rows or "| - | - | - | - | - | - |"}

## Errors

{errors or "- None"}

## Warnings

{warnings or "- None"}

## Limitations

{limitations or "- None"}
"""


def _roadmap_evidence_chain_record(chain: EvidenceChain) -> dict[str, Any]:
    return {
        "tenant_id": chain.tenant_id,
        "entry_count": len(chain.entries),
        "tree": chain.tree(),
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
        "has_external_evidence": result.external_evidence_entry_count > 0,
        "has_complete_external_evidence": result.complete_external_evidence_entry_count > 0,
    }


def _roadmap_evidence_verification_record(result: RoadmapEvidenceChainVerification) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "errors": result.errors,
        "warnings": result.warnings,
        "audit_entry_count": result.audit_entry_count,
        "external_evidence_entry_count": result.external_evidence_entry_count,
        "complete_external_evidence_entry_count": result.complete_external_evidence_entry_count,
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
                "required_requirement_count": payload.get("required_requirement_count"),
                "covered_requirement_count": payload.get("covered_requirement_count"),
                "missing_requirement_count": payload.get("missing_requirement_count"),
                "evidence_count": payload.get("evidence_count"),
                "covered_requirement_ids": payload.get("covered_requirement_ids", []),
                "missing_requirement_ids": payload.get("missing_requirement_ids", []),
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
) -> None:
    payload = entry.get("payload", {})
    required = payload.get("required_requirement_count")
    covered = payload.get("covered_requirement_count")
    missing = payload.get("missing_requirement_count")
    status = payload.get("status")
    if all(isinstance(value, int) for value in (required, covered, missing)) and covered + missing != required:
        errors.append(f"external evidence entry {entry.get('index')} coverage counts do not add up")
    if status == "complete" and missing != 0:
        errors.append(f"external evidence entry {entry.get('index')} is complete but has missing requirements")
    if status != "complete":
        message = f"external evidence entry {entry.get('index')} is partial"
        if require_complete:
            errors.append(message)
        else:
            warnings.append(message)

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
