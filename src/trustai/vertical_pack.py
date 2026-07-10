from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys
from .chain import EvidenceChain
from .crypto import sign_value, verify_value

VERTICAL_PACK_SCHEMA = "trustai.vertical-pack/0.1"
VERTICAL_PACK_ENTRY_TYPE = "vertical_pack.published"

COMMON_SOURCE_PATHS = (
    "docs/specs/vertical-pack-v0.1.md",
    "docs/specs/proof-pack-v0.1.md",
    "docs/specs/verification-contract-v0.1.md",
    "docs/specs/runtime-policy-v0.1.md",
    "docs/specs/marketplace-v0.1.md",
    "src/trustai/proofpack.py",
    "src/trustai/contracts.py",
    "src/trustai/policy.py",
    "src/trustai/marketplace.py",
    "examples/aitrade/verification-contract.yaml",
    "examples/aitrade/policy-pack.json",
)

VERTICAL_PACKS: dict[str, dict[str, Any]] = {
    "trading-treasury": {
        "title": "Trading and Treasury Agent Pack",
        "roadmap_ref": "Phase 3 vertical packs: trading/treasury with SR 11-7 native evidence",
        "risk_classes": ["trading-prod-write", "treasury-prod-write"],
        "frameworks": ["SR 11-7", "ISO 42001", "NIST AI RMF", "SOC 2"],
        "source_paths": [
            "docs/specs/compliance-production-authority-v0.1.md",
            "docs/specs/reexecution-report-v0.1.md",
            "src/trustai/compliance.py",
            "src/trustai/reexecution.py",
            "examples/aitrade/reexecution-policy.json",
        ],
        "controls": [
            {
                "id": "sr-11-7-model-risk-native",
                "title": "SR 11-7 model-risk validation mapped from proof-pack controls",
                "paths": ["src/trustai/compliance.py", "docs/specs/compliance-production-authority-v0.1.md"],
            },
            {
                "id": "treasury-reexecution-bound",
                "title": "Distributional re-execution and deterministic replay evidence bound",
                "paths": ["src/trustai/reexecution.py", "docs/specs/reexecution-report-v0.1.md"],
            },
            {
                "id": "trading-policy-risk-class-bound",
                "title": "Trading production-write risk class and approval policy template bound",
                "paths": ["examples/aitrade/policy-pack.json", "examples/aitrade/verification-contract.yaml"],
            },
        ],
        "external_requirements": [
            "Live model-risk owner approval and trading/treasury desk signoff.",
            "Bank examiner, internal audit, or counterparty acceptance of the generated pack.",
        ],
    },
    "insurance-claims": {
        "title": "Insurance Claims Agent Pack",
        "roadmap_ref": "Phase 3 vertical packs: insurance claims with NAIC model bulletin adjacency",
        "risk_classes": ["claims-prod-write", "underwriting-prod-write"],
        "frameworks": ["NAIC Model Bulletin", "ISO 42001", "NIST AI RMF", "SOC 2"],
        "source_paths": [
            "docs/specs/insurer-consent-v0.1.md",
            "docs/specs/underwriting-quote-v0.1.md",
            "docs/specs/actuarial-product-v0.1.md",
            "src/trustai/consent.py",
            "src/trustai/insurer.py",
            "src/trustai/underwriting_quote.py",
            "src/trustai/actuarial.py",
            "examples/aitrade/identity-inventory.json",
        ],
        "controls": [
            {
                "id": "claims-consent-minimization-bound",
                "title": "Claims consent, minimization, and insurer telemetry controls bound",
                "paths": ["src/trustai/consent.py", "docs/specs/insurer-consent-v0.1.md"],
            },
            {
                "id": "underwriting-quote-actuarial-bound",
                "title": "Underwriting quote and actuarial product evidence bound",
                "paths": ["src/trustai/underwriting_quote.py", "src/trustai/actuarial.py"],
            },
            {
                "id": "claims-agent-identity-bound",
                "title": "Claims agent identity inventory fixture bound",
                "paths": ["examples/aitrade/identity-inventory.json"],
            },
        ],
        "external_requirements": [
            "State insurance, NAIC bulletin, or carrier legal review of claims workflow controls.",
            "Live claims platform, policy-system, and underwriter integration exports.",
        ],
    },
    "healthcare-rcm": {
        "title": "Healthcare RCM Agent Pack",
        "roadmap_ref": "Phase 3 vertical packs: healthcare with HIPAA and FDA SaMD-adjacent controls",
        "risk_classes": ["healthcare-rcm-prod-write", "patient-impacting-prod-write"],
        "frameworks": ["HIPAA", "FDA SaMD-adjacent", "ISO 42001", "NIST AI RMF"],
        "source_paths": [
            "docs/specs/regulator-disclosure-v0.1.md",
            "docs/specs/supervised-access-v0.1.md",
            "docs/specs/eu-ai-act-technical-documentation-v0.1.md",
            "src/trustai/regulator.py",
            "src/trustai/supervised_access.py",
            "src/trustai/runtime.py",
            "src/trustai/policy_engine.py",
        ],
        "controls": [
            {
                "id": "hipaa-supervised-disclosure-bound",
                "title": "Selective disclosure and supervised-access controls bound for healthcare review",
                "paths": ["src/trustai/supervised_access.py", "docs/specs/supervised-access-v0.1.md"],
            },
            {
                "id": "clinical-rcm-policy-bound",
                "title": "Runtime policy and proof-decay controls bound for healthcare RCM actions",
                "paths": ["src/trustai/runtime.py", "src/trustai/policy_engine.py"],
            },
            {
                "id": "high-risk-technical-doc-bound",
                "title": "High-risk technical documentation generator bound for regulated clinical workflows",
                "paths": ["docs/specs/eu-ai-act-technical-documentation-v0.1.md", "src/trustai/regulator.py"],
            },
        ],
        "external_requirements": [
            "HIPAA security risk assessment, BAA posture, and PHI handling evidence.",
            "FDA SaMD classification or legal determination when the agent affects clinical decisions.",
        ],
    },
    "public-sector": {
        "title": "Public Sector Agent Pack",
        "roadmap_ref": "Phase 3 vertical packs: public sector with FedRAMP path decision",
        "risk_classes": ["public-sector-prod-write", "regulated-government-prod-write"],
        "frameworks": ["FedRAMP path decision", "NIST AI RMF", "ISO 42001", "SOC 2"],
        "source_paths": [
            "docs/specs/byoc-production-authority-v0.1.md",
            "docs/specs/eu-data-plane-attestation-v0.1.md",
            "deploy/helm/trustai/Chart.yaml",
            "deploy/docker/Dockerfile",
            "src/trustai/deployment.py",
            "src/trustai/byoc_authority.py",
            "src/trustai/object_store.py",
        ],
        "controls": [
            {
                "id": "fedramp-boundary-decision-bound",
                "title": "Deployment, Helm, and BYOC authority sources bound for FedRAMP boundary decisions",
                "paths": ["deploy/helm/trustai/Chart.yaml", "src/trustai/byoc_authority.py"],
            },
            {
                "id": "sovereignty-retention-bound",
                "title": "Data-plane residency, WORM retention, and deployment evidence bound",
                "paths": ["docs/specs/eu-data-plane-attestation-v0.1.md", "src/trustai/object_store.py"],
            },
            {
                "id": "public-sector-self-hosted-bound",
                "title": "Self-hosted Docker and deployment scaffold bound",
                "paths": ["deploy/docker/Dockerfile", "src/trustai/deployment.py"],
            },
        ],
        "external_requirements": [
            "FedRAMP boundary, control inheritance, SSP, POA&M, and ATO path evidence.",
            "Government tenant deployment, access-control, audit-log, and data-residency exports.",
        ],
    },
}

SUPPORTED_VERTICAL_PACKS = set(VERTICAL_PACKS)


@dataclass
class VerticalPackVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def load_vertical_pack(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("vertical pack must contain an object")
    return value


def write_vertical_pack(path: str | Path, pack: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(pack, indent=2, sort_keys=True), encoding="utf-8")


def build_vertical_pack(
    root: str | Path,
    *,
    pack_ref: str,
    vertical: str,
    producer_ref: str,
    environment: str = "local",
    reviewer_ref: str | None = None,
    generated_at: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    if vertical not in SUPPORTED_VERTICAL_PACKS:
        raise ValueError(f"vertical must be one of {sorted(SUPPORTED_VERTICAL_PACKS)}")
    for value, field in ((pack_ref, "pack_ref"), (producer_ref, "producer_ref"), (environment, "environment")):
        _require_text(value, field)
    if reviewer_ref is not None:
        _require_text(reviewer_ref, "reviewer_ref")

    timestamp = generated_at or utc_now()
    parse_rfc3339(timestamp)
    definition = VERTICAL_PACKS[vertical]
    root_path = Path(root)
    source_artifacts = [_file_binding(root_path, path) for path in _expected_paths(vertical)]
    body: dict[str, Any] = {
        "schema": VERTICAL_PACK_SCHEMA,
        "generated_at": timestamp,
        "pack_ref": pack_ref,
        "vertical": vertical,
        "title": definition["title"],
        "roadmap_ref": definition["roadmap_ref"],
        "producer_ref": producer_ref,
        "reviewer_ref": reviewer_ref,
        "environment": environment,
        "risk_classes": definition["risk_classes"],
        "frameworks": definition["frameworks"],
        "source_artifacts": source_artifacts,
        "framework_mappings": _framework_mappings(vertical),
        "controls": _controls(vertical, source_artifacts),
        "external_requirements": definition["external_requirements"],
        "limitations": [
            "This vertical pack proves local templates, policy packs, proof-pack sources, and vertical control mappings are present and hash-bound.",
            "It does not claim live regulator, insurer, auditor, healthcare, government, or customer acceptance.",
            "Production vertical claims require fresh external evidence for the listed external requirements.",
        ],
    }
    pack_id = content_hash(body)
    return {
        **body,
        "pack_id": pack_id,
        "signatures": [sign_value({"pack_id": pack_id, "vertical_pack": body}, key)],
    }


def verify_vertical_pack(
    pack: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> VerticalPackVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if pack.get("schema") != VERTICAL_PACK_SCHEMA:
        errors.append(f"unsupported vertical pack schema: {pack.get('schema')}")
    body = without_keys(pack, "pack_id", "signatures")
    if pack.get("pack_id") != content_hash(body):
        errors.append("pack_id does not match canonical vertical pack body")
    signatures = pack.get("signatures", [])
    if not isinstance(signatures, list) or not signatures:
        errors.append("vertical pack must include at least one signature")
    else:
        signed_value = {"pack_id": pack.get("pack_id"), "vertical_pack": body}
        if not any(isinstance(signature, dict) and verify_value(signed_value, signature, key) for signature in signatures):
            errors.append("vertical pack signature verification failed")

    try:
        parse_rfc3339(str(pack.get("generated_at") or ""))
    except ValueError as exc:
        errors.append(f"vertical pack generated_at invalid: {exc}")
    for field in ("pack_ref", "producer_ref", "environment"):
        if not pack.get(field):
            errors.append(f"vertical pack {field} is required")

    vertical = pack.get("vertical")
    if vertical not in SUPPORTED_VERTICAL_PACKS:
        errors.append("vertical pack vertical is unsupported")
        expected_paths: set[str] = set()
    else:
        definition = VERTICAL_PACKS[str(vertical)]
        expected_paths = set(_expected_paths(str(vertical)))
        if pack.get("title") != definition["title"]:
            errors.append("vertical pack title does not match vertical")
        if pack.get("roadmap_ref") != definition["roadmap_ref"]:
            errors.append("vertical pack roadmap_ref does not match vertical")
        if pack.get("risk_classes") != definition["risk_classes"]:
            errors.append("vertical pack risk_classes do not match vertical")
        if pack.get("frameworks") != definition["frameworks"]:
            errors.append("vertical pack frameworks do not match vertical")
        if pack.get("framework_mappings") != _framework_mappings(str(vertical)):
            errors.append("vertical pack framework_mappings do not match vertical")
        if pack.get("external_requirements") != definition["external_requirements"]:
            errors.append("vertical pack external_requirements do not match vertical")

    artifacts = pack.get("source_artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("vertical pack source_artifacts must be a list")
        artifacts = []
    seen_paths: set[str] = set()
    root_path = Path(root)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("vertical pack source artifact must be an object")
            continue
        path = str(artifact.get("path") or "")
        if path in seen_paths:
            errors.append(f"duplicate vertical pack source artifact: {path}")
        seen_paths.add(path)
        if path not in expected_paths:
            errors.append(f"unexpected vertical pack source artifact: {path}")
            continue
        try:
            expected = _file_binding(root_path, path)
        except FileNotFoundError:
            errors.append(f"vertical pack source artifact is missing: {path}")
            continue
        if artifact != expected:
            errors.append(f"vertical pack source artifact hash mismatch: {path}")
    missing = sorted(expected_paths - seen_paths)
    if missing:
        errors.append("vertical pack source artifacts missing: " + ", ".join(missing))

    if vertical in SUPPORTED_VERTICAL_PACKS:
        expected_controls = _controls(str(vertical), artifacts)
        if pack.get("controls") != expected_controls:
            errors.append("vertical pack controls do not match source artifacts")
        if pack.get("external_requirements"):
            warnings.append("vertical pack has external requirements before production acceptance")
    return VerticalPackVerification(ok=not errors, errors=errors, warnings=warnings)


def append_vertical_pack(
    chain: EvidenceChain,
    pack: dict[str, Any],
    *,
    root: str | Path = ".",
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_vertical_pack(pack, root=root, key=key)
    if not result.ok:
        raise ValueError("invalid vertical pack: " + "; ".join(result.errors))
    payload = {
        "pack_id": pack["pack_id"],
        "pack_hash": content_hash(pack),
        "pack_ref": pack.get("pack_ref"),
        "vertical": pack.get("vertical"),
        "title": pack.get("title"),
        "producer_ref": pack.get("producer_ref"),
        "reviewer_ref": pack.get("reviewer_ref"),
        "environment": pack.get("environment"),
        "risk_classes": pack.get("risk_classes", []),
        "frameworks": pack.get("frameworks", []),
        "source_artifact_count": len(pack.get("source_artifacts", [])),
        "control_summary": _status_summary(pack.get("controls", [])),
        "external_requirement_count": len(pack.get("external_requirements", [])),
    }
    return chain.append(VERTICAL_PACK_ENTRY_TYPE, payload, key=key, timestamp=pack.get("generated_at"))


def _expected_paths(vertical: str) -> tuple[str, ...]:
    paths = list(COMMON_SOURCE_PATHS)
    for path in VERTICAL_PACKS[vertical]["source_paths"]:
        if path not in paths:
            paths.append(path)
    return tuple(paths)


def _framework_mappings(vertical: str) -> list[dict[str, str]]:
    return [
        {
            "framework": framework,
            "mapping_ref": f"{vertical}:{framework.lower().replace(' ', '-').replace('/', '-')}",
            "evidence_role": "local-template-and-control-binding",
        }
        for framework in VERTICAL_PACKS[vertical]["frameworks"]
    ]


def _controls(vertical: str, source_artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    paths = {artifact.get("path") for artifact in source_artifacts if isinstance(artifact, dict)}
    controls = [
        {
            "id": "verification-contract-template-bound",
            "status": _status(paths, ["docs/specs/verification-contract-v0.1.md", "examples/aitrade/verification-contract.yaml"]),
            "detail": "Pre-registration contract template and example are hash-bound.",
        },
        {
            "id": "runtime-policy-pack-bound",
            "status": _status(paths, ["docs/specs/runtime-policy-v0.1.md", "examples/aitrade/policy-pack.json"]),
            "detail": "Runtime policy pack and proof-decay source are hash-bound.",
        },
        {
            "id": "proof-pack-compiler-bound",
            "status": _status(paths, ["docs/specs/proof-pack-v0.1.md", "src/trustai/proofpack.py"]),
            "detail": "Portable proof-pack source and spec are hash-bound.",
        },
        {
            "id": "marketplace-distribution-bound",
            "status": _status(paths, ["docs/specs/marketplace-v0.1.md", "src/trustai/marketplace.py"]),
            "detail": "Certified template marketplace source and spec are hash-bound.",
        },
    ]
    for control in VERTICAL_PACKS[vertical]["controls"]:
        controls.append(
            {
                "id": control["id"],
                "status": _status(paths, control["paths"]),
                "detail": control["title"],
            }
        )
    controls.append(
        {
            "id": "production-claim-limited",
            "status": "external-required",
            "detail": "Vertical pack records local/reference evidence only; production acceptance requires the listed external requirements.",
        }
    )
    return controls


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


def _require_text(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"vertical pack {field} is required")
