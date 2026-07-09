from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .verifier import verify_proof_pack

TRUST_NETWORK_SCHEMA = "trustai.trust-network-manifest/0.1"

DEFAULT_PROCUREMENT_CLAUSE = (
    "Agent vendors must supply TrustAI-format proof packs for production or "
    "money-touching agents. Packs must verify offline and satisfy the buyer's "
    "required gate outcome, framework mappings, and risk-class constraints "
    "before procurement acceptance."
)


@dataclass
class TrustNetworkVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    accepted_count: int = 0
    submission_count: int = 0


def build_trust_network_manifest(
    proof_packs: list[dict[str, Any]],
    *,
    vendor_names: list[str] | None = None,
    buyer: str = "local-buyer",
    clause_name: str = "TrustAI proof-pack procurement clause",
    procurement_clause: str | None = None,
    required_frameworks: list[str] | None = None,
    accepted_risk_classes: list[str] | None = None,
    required_gate_outcome: str = "passed",
) -> dict[str, Any]:
    if not proof_packs:
        raise ValueError("at least one proof pack is required")
    if vendor_names is not None and len(vendor_names) != len(proof_packs):
        raise ValueError("vendor_names length must match proof_packs length")

    clause = {
        "name": clause_name,
        "text": procurement_clause or DEFAULT_PROCUREMENT_CLAUSE,
        "required_gate_outcome": required_gate_outcome,
        "required_frameworks": sorted(set(required_frameworks or [])),
        "accepted_risk_classes": sorted(set(accepted_risk_classes or [])),
    }
    submissions = [
        _submission_for_pack(
            pack,
            vendor=vendor_names[index] if vendor_names else f"vendor-{index + 1}",
            clause=clause,
        )
        for index, pack in enumerate(proof_packs)
    ]
    body = {
        "schema": TRUST_NETWORK_SCHEMA,
        "generated_at": utc_now(),
        "buyer": buyer,
        "procurement_clause": clause,
        "submissions": submissions,
        "network_summary": _summary(submissions),
        "limitations": [
            "Local trust-network manifest only; no external registry or procurement platform integration is claimed.",
            "Source proof packs must be supplied for deep offline verification.",
        ],
    }
    return {**body, "manifest_id": content_hash(body)}


def verify_trust_network_manifest(
    manifest: dict[str, Any],
    *,
    proof_packs: list[dict[str, Any]] | None = None,
    key: str | None = None,
) -> TrustNetworkVerification:
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.get("schema") != TRUST_NETWORK_SCHEMA:
        errors.append(f"unsupported trust-network schema: {manifest.get('schema')}")
    body = without_keys(manifest, "manifest_id")
    if manifest.get("manifest_id") != content_hash(body):
        errors.append("manifest_id does not match canonical manifest body")

    submissions = manifest.get("submissions", [])
    if not isinstance(submissions, list) or not submissions:
        errors.append("trust-network manifest must include vendor submissions")
        submissions = []

    clause = manifest.get("procurement_clause", {})
    pack_by_id = _pack_map(proof_packs or [], errors)
    deep_verify = proof_packs is not None
    seen_submission_pack_ids: set[str] = set()

    for submission in submissions:
        if not isinstance(submission, dict):
            errors.append("vendor submission must be an object")
            continue
        vendor = submission.get("vendor", "unknown-vendor")
        pack_id = submission.get("proof_pack", {}).get("pack_id")
        if not pack_id:
            errors.append(f"vendor {vendor} submission missing proof pack id")
        elif pack_id in seen_submission_pack_ids:
            errors.append(f"duplicate vendor submission proof pack id: {pack_id}")
        else:
            seen_submission_pack_ids.add(pack_id)

        expected = _requirements_for_summary(submission, clause)
        if submission.get("requirement_results") != expected:
            errors.append(f"vendor {vendor} requirement results do not match procurement clause")
        expected_accepted = all(item["passed"] for item in expected)
        if submission.get("accepted") != expected_accepted:
            errors.append(f"vendor {vendor} accepted flag does not match requirement results")
        if not expected_accepted:
            errors.append(f"vendor {vendor} does not satisfy procurement clause")

        if deep_verify:
            pack = pack_by_id.get(pack_id)
            if pack is None:
                errors.append(f"source proof pack not supplied for vendor {vendor}: {pack_id}")
                continue
            _verify_pack_link(submission, pack, vendor, errors, warnings, key)
        else:
            warnings.append(f"source proof pack not supplied for deep verification: {pack_id}")

    expected_summary = _summary([item for item in submissions if isinstance(item, dict)])
    if manifest.get("network_summary") != expected_summary:
        errors.append("network_summary does not match vendor submissions")

    return TrustNetworkVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        accepted_count=expected_summary["accepted_vendor_count"],
        submission_count=expected_summary["vendor_count"],
    )


def write_trust_network_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def write_trust_network_markdown(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_trust_network_markdown(manifest), encoding="utf-8")


def render_trust_network_markdown(manifest: dict[str, Any]) -> str:
    clause = manifest.get("procurement_clause", {})
    submissions = "\n".join(
        f"- {submission.get('vendor')}: {submission.get('proof_pack', {}).get('pack_id')} "
        f"({'accepted' if submission.get('accepted') else 'rejected'})"
        for submission in manifest.get("submissions", [])
    )
    requirements = "\n".join(
        f"- `{key}`: {value}"
        for key, value in clause.items()
        if key != "text"
    )
    return f"""# TrustAI Vendor Trust Network Manifest

Manifest ID: `{manifest.get('manifest_id', '')}`

Buyer: {manifest.get('buyer', '')}

## Procurement Clause

{clause.get('text', '')}

## Requirements

{requirements}

## Vendor Submissions

{submissions}
"""


def load_trust_network_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _submission_for_pack(pack: dict[str, Any], *, vendor: str, clause: dict[str, Any]) -> dict[str, Any]:
    decision = pack.get("gate_decision", {})
    agent = decision.get("agent", {})
    proof_pack = {
        "pack_id": pack.get("pack_id"),
        "content_hash": content_hash(pack),
        "issued_at": pack.get("issued_at"),
        "contract_id": decision.get("contract_id"),
        "contract_hash": decision.get("contract_hash") or pack.get("contract", {}).get("hash"),
        "gate_outcome": decision.get("outcome"),
        "chain_root": pack.get("chain", {}).get("tree", {}).get("root"),
        "chain_size": pack.get("chain", {}).get("tree", {}).get("size"),
    }
    summary = {
        "vendor": vendor,
        "proof_pack": proof_pack,
        "agent": {
            "name": agent.get("name"),
            "version": agent.get("version"),
            "framework": agent.get("framework"),
            "risk_class": agent.get("risk_class"),
        },
        "frameworks": _frameworks(pack),
    }
    requirement_results = _requirements_for_summary(summary, clause)
    return {
        **summary,
        "requirement_results": requirement_results,
        "accepted": all(item["passed"] for item in requirement_results),
        "submission_id": content_hash(
            {
                "vendor": vendor,
                "pack_id": proof_pack["pack_id"],
                "content_hash": proof_pack["content_hash"],
            }
        ),
    }


def _requirements_for_summary(summary: dict[str, Any], clause: dict[str, Any]) -> list[dict[str, Any]]:
    required_outcome = clause.get("required_gate_outcome", "passed")
    outcome = summary.get("proof_pack", {}).get("gate_outcome")
    results = [
        {
            "id": "proof-pack-gate-outcome",
            "description": f"Gate outcome must be {required_outcome}.",
            "actual": outcome,
            "passed": outcome == required_outcome,
        }
    ]
    accepted_risk_classes = clause.get("accepted_risk_classes", [])
    risk_class = summary.get("agent", {}).get("risk_class")
    if accepted_risk_classes:
        results.append(
            {
                "id": "accepted-risk-class",
                "description": "Agent risk class must be accepted by buyer policy.",
                "actual": risk_class,
                "accepted": accepted_risk_classes,
                "passed": risk_class in accepted_risk_classes,
            }
        )
    frameworks = set(summary.get("frameworks", []))
    for framework in clause.get("required_frameworks", []):
        results.append(
            {
                "id": f"required-framework:{framework}",
                "description": "Proof pack must include the required framework mapping.",
                "actual": sorted(frameworks),
                "required": framework,
                "passed": framework in frameworks,
            }
        )
    return results


def _verify_pack_link(
    submission: dict[str, Any],
    pack: dict[str, Any],
    vendor: str,
    errors: list[str],
    warnings: list[str],
    key: str | None,
) -> None:
    source = submission.get("proof_pack", {})
    if source.get("content_hash") != content_hash(pack):
        errors.append(f"vendor {vendor} proof pack source hash mismatch")
    result = verify_proof_pack(pack, key=key)
    if not result.ok:
        errors.extend(f"vendor {vendor} proof pack invalid: {error}" for error in result.errors)
    warnings.extend(f"vendor {vendor} proof pack warning: {warning}" for warning in result.warnings)

    expected = _submission_for_pack(pack, vendor=vendor, clause={"required_gate_outcome": source.get("gate_outcome")})
    if source.get("pack_id") != pack.get("pack_id"):
        errors.append(f"vendor {vendor} proof pack id mismatch")
    if source.get("contract_id") != expected["proof_pack"].get("contract_id"):
        errors.append(f"vendor {vendor} contract id mismatch")
    if source.get("chain_root") != expected["proof_pack"].get("chain_root"):
        errors.append(f"vendor {vendor} chain root mismatch")
    if submission.get("agent") != expected.get("agent"):
        errors.append(f"vendor {vendor} agent summary mismatch")
    if submission.get("frameworks") != expected.get("frameworks"):
        errors.append(f"vendor {vendor} framework summary mismatch")


def _pack_map(packs: list[dict[str, Any]], errors: list[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for pack in packs:
        pack_id = pack.get("pack_id")
        if not pack_id:
            errors.append("source proof pack missing pack_id")
            continue
        if pack_id in result:
            errors.append(f"duplicate source proof pack id: {pack_id}")
            continue
        result[pack_id] = pack
    return result


def _frameworks(pack: dict[str, Any]) -> list[str]:
    return sorted(
        mapping.get("framework")
        for mapping in pack.get("framework_mappings", [])
        if isinstance(mapping, dict) and mapping.get("framework")
    )


def _summary(submissions: list[dict[str, Any]]) -> dict[str, Any]:
    risk_classes: dict[str, int] = {}
    frameworks: dict[str, int] = {}
    for submission in submissions:
        risk_class = submission.get("agent", {}).get("risk_class") or "unknown"
        risk_classes[risk_class] = risk_classes.get(risk_class, 0) + 1
        for framework in submission.get("frameworks", []):
            frameworks[framework] = frameworks.get(framework, 0) + 1
    return {
        "vendor_count": len(submissions),
        "accepted_vendor_count": sum(1 for item in submissions if item.get("accepted")),
        "rejected_vendor_count": sum(1 for item in submissions if not item.get("accepted")),
        "risk_classes": risk_classes,
        "frameworks": frameworks,
    }
