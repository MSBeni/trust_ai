from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

OWN_COMPLIANCE_SCHEMA = "trustai.own-compliance-dossier/0.1"
OWN_COMPLIANCE_ENTRY_TYPE = "trustai.own_compliance.dossier.attested"

OWN_COMPLIANCE_MODES = {"readiness", "external-certification"}
EVIDENCE_KINDS = {
    "soc2-type-ii-report",
    "iso-42001-certificate",
    "management-system-scope",
    "auditor-bridge-letter",
    "internal-audit-review",
}
REQUIRED_CERTIFICATION_KINDS = {"soc2-type-ii-report", "iso-42001-certificate"}

REQUIRED_SOURCE_PATHS = (
    "docs/specs/own-compliance-dossier-v0.1.md",
    "docs/specs/proof-pack-v0.1.md",
    "docs/specs/compliance-production-authority-v0.1.md",
    "docs/specs/standards-submission-v0.1.md",
    "docs/specs/verifier-conformance-v0.1.md",
    "docs/specs/trust-authority-receipt-v0.1.md",
    "docs/specs/trust-authority-kms-enforcement-v0.1.md",
    "docs/specs/worm-object-store-v0.1.md",
    "docs/specs/roadmap-audit-v0.1.md",
    "docs/architecture/roadmap-coverage.md",
    "src/trustai/own_compliance.py",
    "src/trustai/proofpack.py",
    "src/trustai/verifier.py",
    "src/trustai/compliance.py",
    "src/trustai/compliance_authority.py",
    "src/trustai/standards.py",
    "src/trustai/roadmap_audit.py",
    "src/trustai/trust_authority.py",
    "src/trustai/trust_authority_kms_enforcement.py",
    "src/trustai/object_store.py",
    "src/trustai/keyring.py",
    "tests/test_own_compliance.py",
)


@dataclass
class OwnComplianceVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_own_compliance_dossier(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("own compliance dossier must contain an object")
    return value


def write_own_compliance_dossier(path: str | Path, dossier: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dossier, indent=2, sort_keys=True), encoding="utf-8")


def build_own_compliance_dossier(
    root: str | Path,
    *,
    dossier_ref: str,
    producer_ref: str,
    scope_ref: str,
    evidence: list[dict[str, Any]] | None = None,
    mode: str = "readiness",
    environment: str = "local",
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if mode not in OWN_COMPLIANCE_MODES:
        raise ValueError(f"mode must be one of {sorted(OWN_COMPLIANCE_MODES)}")
    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    normalized_evidence = [_normalize_evidence(item) for item in (evidence or [])]
    root_path = Path(root)
    source_artifacts = [_file_binding(root_path, relative_path) for relative_path in REQUIRED_SOURCE_PATHS]
    metrics = _metrics(normalized_evidence, source_artifacts)
    body: dict[str, Any] = {
        "schema": OWN_COMPLIANCE_SCHEMA,
        "generated_at": timestamp,
        "dossier_ref": _require_text(dossier_ref, "dossier_ref"),
        "producer_ref": _require_text(producer_ref, "producer_ref"),
        "scope_ref": _require_text(scope_ref, "scope_ref"),
        "mode": mode,
        "environment": _require_text(environment, "environment"),
        "framework_targets": [
            {"framework": "SOC 2 Type II", "required_evidence_kind": "soc2-type-ii-report"},
            {"framework": "ISO/IEC 42001", "required_evidence_kind": "iso-42001-certificate"},
        ],
        "certification_evidence": normalized_evidence,
        "metrics": metrics,
        "source_artifacts": source_artifacts,
        "controls": _controls(mode, source_artifacts, normalized_evidence),
        "limitations": [
            "Readiness mode proves local evidence-production readiness only; it is not a SOC 2 Type II report or ISO/IEC 42001 certificate.",
            "External-certification mode requires external SOC 2 Type II and ISO/IEC 42001 evidence references and hashes.",
            "The dossier stores evidence references and hashes, not raw audit reports, customer data, secrets, or private compliance workpapers.",
        ],
    }
    dossier_id = content_hash(body)
    return {
        **body,
        "dossier_id": dossier_id,
        "signatures": [sign_value({"dossier_id": dossier_id, "own_compliance_dossier": body}, key)],
    }


def verify_own_compliance_dossier(
    dossier: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> OwnComplianceVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if dossier.get("schema") != OWN_COMPLIANCE_SCHEMA:
        errors.append(f"unsupported own compliance schema: {dossier.get('schema')}")
    body = without_keys(dossier, "dossier_id", "signatures")
    if dossier.get("dossier_id") != content_hash(body):
        errors.append("dossier_id does not match canonical own compliance body")
    signatures = dossier.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("own compliance dossier must include at least one signature")
    else:
        signed_value = {"dossier_id": dossier.get("dossier_id"), "own_compliance_dossier": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("own compliance dossier signature verification failed")
    try:
        parse_rfc3339(str(dossier.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"own compliance generated_at invalid: {exc}")
    for field in ("dossier_ref", "producer_ref", "scope_ref", "environment"):
        if not dossier.get(field):
            errors.append(f"own compliance {field} is required")
    mode = dossier.get("mode")
    if mode not in OWN_COMPLIANCE_MODES:
        errors.append("own compliance mode is unsupported")

    evidence = dossier.get("certification_evidence", [])
    if not isinstance(evidence, list):
        errors.append("own compliance certification_evidence must be a list")
        evidence = []
    normalized_evidence: list[dict[str, Any]] = []
    seen_evidence_ids: set[str] = set()
    seen_evidence_refs: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict):
            errors.append("own compliance evidence item must be an object")
            continue
        try:
            normalized = _normalize_evidence(item)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if normalized["evidence_id"] in seen_evidence_ids:
            errors.append(f"duplicate own compliance evidence id: {normalized['evidence_id']}")
        if normalized["evidence_ref"] in seen_evidence_refs:
            errors.append(f"duplicate own compliance evidence ref: {normalized['evidence_ref']}")
        seen_evidence_ids.add(normalized["evidence_id"])
        seen_evidence_refs.add(normalized["evidence_ref"])
        if normalized != item:
            errors.append(f"own compliance evidence {normalized['evidence_ref']} is not canonical")
        normalized_evidence.append(normalized)

    artifacts = dossier.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("own compliance source_artifacts must be a list")
        artifacts = []
    expected_paths = set(REQUIRED_SOURCE_PATHS)
    seen_paths: set[str] = set()
    root_path = Path(root)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("own compliance source artifact must be an object")
            continue
        path = str(artifact.get("path") or "")
        if path in seen_paths:
            errors.append(f"duplicate own compliance source artifact: {path}")
        seen_paths.add(path)
        if path not in expected_paths:
            errors.append(f"unexpected own compliance source artifact: {path}")
            continue
        try:
            expected = _file_binding(root_path, path)
        except FileNotFoundError:
            errors.append(f"own compliance source artifact is missing: {path}")
            continue
        if artifact != expected:
            errors.append(f"own compliance source artifact hash mismatch: {path}")
    missing = sorted(expected_paths - seen_paths)
    if missing:
        errors.append("own compliance source artifacts missing: " + ", ".join(missing))

    expected_metrics = _metrics(normalized_evidence, artifacts)
    if dossier.get("metrics") != expected_metrics:
        errors.append("own compliance metrics do not match evidence and source artifacts")
    if mode in OWN_COMPLIANCE_MODES:
        expected_controls = _controls(str(mode), artifacts, normalized_evidence)
        if dossier.get("controls") != expected_controls:
            errors.append("own compliance controls do not match dossier body")
        if mode == "readiness":
            warnings.append("readiness mode does not prove SOC 2 Type II or ISO/IEC 42001 certification")
        elif any(control["status"] == "external-required" for control in expected_controls):
            errors.append("external-certification mode requires SOC 2 Type II and ISO/IEC 42001 evidence references")
    return OwnComplianceVerification(ok=not errors, errors=errors, warnings=warnings)


def append_own_compliance_dossier(
    chain: EvidenceChain,
    dossier: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_own_compliance_dossier(dossier, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid own compliance dossier: " + "; ".join(result.errors))
    payload = {
        "dossier_id": dossier["dossier_id"],
        "dossier_hash": content_hash(dossier),
        "dossier_ref": dossier.get("dossier_ref"),
        "scope_ref": dossier.get("scope_ref"),
        "mode": dossier.get("mode"),
        "environment": dossier.get("environment"),
        "evidence_count": dossier.get("metrics", {}).get("evidence_count", 0),
        "required_certification_evidence_count": dossier.get("metrics", {}).get("required_certification_evidence_count", 0),
        "source_artifact_count": dossier.get("metrics", {}).get("source_artifact_count", 0),
        "control_summary": _status_summary(dossier.get("controls", [])),
    }
    return chain.append(OWN_COMPLIANCE_ENTRY_TYPE, payload, key=key, timestamp=dossier.get("generated_at"))


def parse_own_compliance_evidence(value: str) -> dict[str, Any]:
    parts = [part.strip() for part in value.split(",")]
    if len(parts) not in {5, 6}:
        raise ValueError("evidence must be kind,evidence_ref,evidence_hash,issuer,issued_at[,expires_at]")
    item: dict[str, Any] = {
        "kind": parts[0],
        "evidence_ref": parts[1],
        "evidence_hash": parts[2],
        "issuer": parts[3],
        "issued_at": parts[4],
    }
    if len(parts) == 6 and parts[5]:
        item["expires_at"] = parts[5]
    return item


def _normalize_evidence(item: dict[str, Any]) -> dict[str, Any]:
    kind = str(item.get("kind") or "")
    if kind not in EVIDENCE_KINDS:
        raise ValueError(f"own compliance evidence kind must be one of {sorted(EVIDENCE_KINDS)}")
    evidence_ref = _require_text(item.get("evidence_ref"), "evidence_ref")
    evidence_hash = _require_hash(item.get("evidence_hash"), "evidence_hash")
    issuer = _require_text(item.get("issuer"), "issuer")
    issued_at = _require_text(item.get("issued_at"), "issued_at")
    parse_rfc3339(issued_at)
    normalized: dict[str, Any] = {
        "kind": kind,
        "evidence_ref": evidence_ref,
        "evidence_hash": evidence_hash,
        "issuer": issuer,
        "issued_at": issued_at,
    }
    expires_at = item.get("expires_at")
    if expires_at:
        expires_at_text = _require_text(expires_at, "expires_at")
        parse_rfc3339(expires_at_text)
        normalized["expires_at"] = expires_at_text
    normalized["evidence_id"] = content_hash(normalized)
    return normalized


def _metrics(evidence: list[dict[str, Any]], source_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    kinds = {item.get("kind") for item in evidence}
    required_present = sorted(kind for kind in REQUIRED_CERTIFICATION_KINDS if kind in kinds)
    return {
        "evidence_count": len(evidence),
        "required_certification_evidence_count": len(required_present),
        "required_certification_kinds_present": required_present,
        "source_artifact_count": len(source_artifacts),
    }


def _controls(mode: str, source_artifacts: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> list[dict[str, str]]:
    paths = {artifact.get("path") for artifact in source_artifacts if isinstance(artifact, dict)}
    evidence_kinds = {item.get("kind") for item in evidence if isinstance(item, dict)}
    external_claim_ready = mode == "external-certification"
    return [
        {
            "id": "own-proof-pack-operability-source-bound",
            "status": _status(paths, ["src/trustai/proofpack.py", "src/trustai/verifier.py", "docs/specs/proof-pack-v0.1.md"]),
            "detail": "TrustAI can produce and verify its own proof-pack evidence locally.",
        },
        {
            "id": "soc2-control-evidence-readiness-source-bound",
            "status": _status(paths, ["src/trustai/compliance.py", "src/trustai/compliance_authority.py", "docs/specs/compliance-production-authority-v0.1.md"]),
            "detail": "SOC 2 evidence export readiness is bound to compliance mapper and authority dossier sources.",
        },
        {
            "id": "iso42001-management-system-readiness-source-bound",
            "status": _status(paths, ["src/trustai/standards.py", "docs/specs/standards-submission-v0.1.md"]),
            "detail": "ISO/IEC 42001 management-system readiness is bound to standards package sources.",
        },
        {
            "id": "tamper-evident-retention-readiness-source-bound",
            "status": _status(paths, ["src/trustai/trust_authority.py", "src/trustai/object_store.py", "docs/specs/worm-object-store-v0.1.md"]),
            "detail": "Evidence retention, WORM storage, and trust-authority receipts are source-bound.",
        },
        {
            "id": "roadmap-audit-readiness-source-bound",
            "status": _status(paths, ["src/trustai/roadmap_audit.py", "docs/specs/roadmap-audit-v0.1.md"]),
            "detail": "Roadmap evidence audit source and spec are hash-bound.",
        },
        {
            "id": "external-soc2-type-ii-certification",
            "status": "passed" if external_claim_ready and "soc2-type-ii-report" in evidence_kinds else "external-required",
            "detail": "SOC 2 Type II requires an external auditor report reference and hash.",
        },
        {
            "id": "external-iso42001-certification",
            "status": "passed" if external_claim_ready and "iso-42001-certificate" in evidence_kinds else "external-required",
            "detail": "ISO/IEC 42001 requires an external certificate reference and hash.",
        },
        {
            "id": "raw-sensitive-data-excluded",
            "status": "passed",
            "detail": "Dossier stores references and hashes only, not audit report bodies, customer data, secrets, or workpapers.",
        },
    ]


def _status(paths: set[str], required_paths: list[str]) -> str:
    return "passed" if all(path in paths for path in required_paths) else "failed"


def _status_summary(controls: Any) -> dict[str, int]:
    summary: dict[str, int] = {}
    if not isinstance(controls, list):
        return summary
    for control in controls:
        status = str(control.get("status", "unknown")) if isinstance(control, dict) else "unknown"
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


def _file_binding(root: Path, relative_path: str) -> dict[str, Any]:
    data = (root / relative_path).read_bytes()
    return {
        "path": relative_path,
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"own compliance {field} is required")
    return value.strip()


def _require_hash(value: Any, field: str) -> str:
    text = _require_text(value, field)
    if not text.startswith("sha256:") or len(text) <= len("sha256:"):
        raise ValueError(f"own compliance {field} must be a sha256: hash reference")
    return text