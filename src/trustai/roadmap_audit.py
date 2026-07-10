from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys
from .chain import EvidenceChain

ROADMAP_AUDIT_SCHEMA = "trustai.roadmap-audit/0.1"
ROADMAP_AUDIT_ENTRY_TYPE = "trustai.roadmap_audit.attested"

STATUS_IMPLEMENTED_LOCAL = "implemented-local"
STATUS_REFERENCE_ATTESTED = "reference-attested"
STATUS_MISSING_LOCAL_EVIDENCE = "missing-local-evidence"
ALLOWED_STATUSES = {
    STATUS_IMPLEMENTED_LOCAL,
    STATUS_REFERENCE_ATTESTED,
    STATUS_MISSING_LOCAL_EVIDENCE,
}

ROADMAP_REQUIREMENTS: tuple[dict[str, Any], ...] = (
    {
        "id": "verification-contract-dsl",
        "phase": "P0",
        "priority": "P0",
        "title": "Verification Contract DSL and registry",
        "roadmap_ref": "Phase 0 Wk 1-2; Core primitive 1",
        "evidence_paths": [
            "docs/specs/verification-contract-v0.1.md",
            "src/trustai/contracts.py",
            "src/trustai/registry.py",
            "examples/aitrade/verification-contract.yaml",
            "tests/test_proofpack_flow.py",
        ],
    },
    {
        "id": "proof-pack-spec-and-compiler",
        "phase": "P0",
        "priority": "P0",
        "title": "Proof Pack spec, compiler, and offline verification",
        "roadmap_ref": "Phase 0 Wk 6-8; Core primitive 5",
        "evidence_paths": [
            "docs/specs/proof-pack-v0.1.md",
            "src/trustai/proofpack.py",
            "src/trustai/verifier.py",
            "src/trustai/frameworks.py",
            "src/trustai/pdf.py",
            "tests/test_proofpack_flow.py",
            "tests/test_temporal_holdout.py",
            "tests/test_mcp_gateway.py",
            "tests/test_phase1_phase2.py",
        ],
    },
    {
        "id": "evidence-chain-and-tamper-tests",
        "phase": "P0",
        "priority": "P0",
        "title": "Merkle evidence chain, signing, timestamping, and tamper stress",
        "roadmap_ref": "Phase 0 Wk 2-4; Core primitive 2",
        "evidence_paths": [
            "src/trustai/chain.py",
            "src/trustai/merkle.py",
            "src/trustai/timestamping.py",
            "src/trustai/tamper_stress.py",
            "docs/specs/tamper-stress-report-v0.1.md",
            "tests/test_merkle.py",
            "tests/test_tamper_stress.py",
        ],
    },
    {
        "id": "oss-verifier-and-public-spec",
        "phase": "P0",
        "priority": "P0",
        "title": "Open verifier, public specs, source distribution, and release workflow",
        "roadmap_ref": "Phase 0 exit criteria; Architecture verifier decision",
        "evidence_paths": [
            "verifier/go/trustai-verify/main.go",
            "verifier/go/trustai-verify/README.md",
            "docs/specs/go-verifier-v0.1.md",
            "docs/specs/verifier-release-v0.1.md",
            "docs/specs/verifier-distribution-v0.1.md",
            ".github/workflows/go-verifier.yml",
            "tests/test_go_verifier_source.py",
            "tests/test_verifier_distribution.py",
        ],
        "external_authority": [
            "Released static Go verifier binaries and hosted provenance require a completed CI/release run or local Go toolchain.",
        ],
    },
    {
        "id": "gate-engine-and-aitrade-flow",
        "phase": "P0",
        "priority": "P0",
        "title": "Contract registry, promotion gate, and bundled aitrade flow",
        "roadmap_ref": "Phase 0 Wk 4-8; aitrade customer #0",
        "evidence_paths": [
            "src/trustai/gate.py",
            "src/trustai/control_plane.py",
            "examples/aitrade/eval-results.json",
            "examples/aitrade/soak-window.json",
            "tests/test_proofpack_flow.py",
        ],
    },
    {
        "id": "otel-ingest-and-sdks",
        "phase": "P0-P1",
        "priority": "P0",
        "title": "OTel GenAI ingest plus Python and TypeScript SDK capture",
        "roadmap_ref": "Phase 0 Wk 6-8; Feature master list",
        "evidence_paths": [
            "docs/specs/otel-ingest-v0.1.md",
            "docs/specs/python-sdk-v0.1.md",
            "docs/specs/typescript-sdk-v0.1.md",
            "src/trustai/ingest.py",
            "src/trustai/sdk.py",
            "sdk/typescript/src/index.mjs",
            "tests/test_ingest_runtime.py",
            "tests/test_typescript_sdk.py",
        ],
    },
    {
        "id": "mcp-gateway",
        "phase": "P1",
        "priority": "P0",
        "title": "MCP evidence gateway reference capture",
        "roadmap_ref": "Phase 1 feature 1",
        "evidence_paths": [
            "docs/specs/mcp-gateway-v0.1.md",
            "src/trustai/mcp_gateway.py",
            "examples/aitrade/mcp-transcript.json",
            "tests/test_mcp_gateway.py",
            "tests/test_ingest_runtime.py",
        ],
        "external_authority": [
            "Continuously operated production MCP proxy workers and immutable production audit exports remain external deployment evidence.",
        ],
    },
    {
        "id": "shadow-replay-temporal-holdout",
        "phase": "P1",
        "priority": "P0",
        "title": "Shadow replay, temporal holdout, soak reports, and distributional re-execution",
        "roadmap_ref": "Phase 1 feature 2 and 5; Core primitive 3",
        "evidence_paths": [
            "docs/specs/shadow-replay-v0.1.md",
            "docs/specs/temporal-holdout-manifest-v0.1.md",
            "docs/specs/reexecution-report-v0.1.md",
            "src/trustai/shadow.py",
            "src/trustai/reexecution.py",
            "src/trustai/reexecution_runner.py",
            "examples/aitrade/shadow-replay.json",
            "examples/aitrade/reexecution-runner-plan.json",
            "tests/test_temporal_holdout.py",
            "tests/test_reexecution.py",
            "tests/test_reexecution_runner.py",
        ],
        "external_authority": [
            "Production runner isolation requires runtime-native scheduler, queue, container, kernel, and audit-log exports.",
        ],
    },
    {
        "id": "cicd-provider-approvals",
        "phase": "P1",
        "priority": "P0",
        "title": "CI/CD promotion gates, provider callbacks, and Slack approvals",
        "roadmap_ref": "Phase 1 feature 3",
        "evidence_paths": [
            "src/trustai/cicd.py",
            "src/trustai/approval_callback.py",
            "src/trustai/provider_delivery_service.py",
            "src/trustai/provider_webhook.py",
            "docs/specs/approval-callback-v0.1.md",
            "docs/specs/provider-delivery-v0.1.md",
            "tests/test_approval_callback.py",
            "tests/test_provider_delivery.py",
        ],
        "external_authority": [
            "Credentialed live GitHub/GitLab/Slack operations require production credentials, public ingress, and provider-owned response logs.",
        ],
    },
    {
        "id": "framework-adapters",
        "phase": "P1",
        "priority": "P1",
        "title": "Framework adapters for LangGraph, OpenAI Agents, Claude, CrewAI, Bedrock, and Vertex",
        "roadmap_ref": "Phase 1 feature 4",
        "evidence_paths": [
            "docs/specs/framework-adapters-v0.1.md",
            "docs/specs/framework-adapter-matrix-v0.1.md",
            "src/trustai/adapters.py",
            "src/trustai/framework_adapter_matrix.py",
            "examples/aitrade/framework-traces.json",
            "examples/aitrade/framework-adapter-matrix.json",
            "tests/test_framework_adapters.py",
            "tests/test_framework_adapter_matrix.py",
        ],
        "external_authority": [
            "Native hooks for exact production runtime releases require continuously maintained adapter packages and release matrices.",
        ],
    },
    {
        "id": "auditor-and-review-portal",
        "phase": "P1-P3",
        "priority": "P1",
        "title": "Auditor view, supervised access, regulator view, and review portal attestations",
        "roadmap_ref": "Phase 1 feature 6; Phase 3 regulator portal",
        "evidence_paths": [
            "src/trustai/auditor.py",
            "src/trustai/regulator.py",
            "src/trustai/regulator_view.py",
            "src/trustai/supervised_access.py",
            "src/trustai/review_portal_service.py",
            "docs/specs/supervised-access-v0.1.md",
            "docs/specs/review-portal-service-attestation-v0.1.md",
            "tests/test_supervised_access.py",
            "tests/test_review_portal_service.py",
        ],
        "external_authority": [
            "Hosted reviewer identity sessions, immutable access logs, and production portal workers remain deployment evidence.",
        ],
    },
    {
        "id": "byoc-self-hosted",
        "phase": "P1-P2",
        "priority": "P0",
        "title": "BYOC and self-hosted deployment scaffold with WORM/Object Lock attestations",
        "roadmap_ref": "Phase 1 feature 7; Architecture deployment decision",
        "evidence_paths": [
            "deploy/docker/Dockerfile",
            "deploy/helm/trustai/Chart.yaml",
            "deploy/helm/trustai/values.yaml",
            "src/trustai/deployment.py",
            "src/trustai/byoc_operator.py",
            "src/trustai/object_store.py",
            "docs/deployment/byoc.md",
            "tests/test_deployment.py",
            "tests/test_byoc_operator.py",
            "tests/test_worm_legal_hold.py",
        ],
        "external_authority": [
            "Cloud Object Lock enforcement, legal holds, air-gapped operations, and immutable provider logs require live cloud accounts.",
        ],
    },
    {
        "id": "compliance-mapper-and-eu-ai-act",
        "phase": "P2-P3",
        "priority": "P0",
        "title": "Compliance framework mapper and EU AI Act technical documentation",
        "roadmap_ref": "Phase 2 feature 1; Phase 3 feature 1",
        "evidence_paths": [
            "src/trustai/compliance.py",
            "src/trustai/eu_ai_act.py",
            "src/trustai/eu_data_plane.py",
            "docs/specs/eu-ai-act-technical-documentation-v0.1.md",
            "docs/specs/eu-data-plane-attestation-v0.1.md",
            "tests/test_eu_ai_act.py",
            "tests/test_eu_data_plane.py",
        ],
        "external_authority": [
            "A continuously operated Frankfurt/EU data plane and provider-native residency exports remain live deployment evidence.",
        ],
    },
    {
        "id": "insurer-api-and-actuarial-products",
        "phase": "P2-P4",
        "priority": "P0",
        "title": "Consent-gated insurer telemetry, underwriting quotes, and actuarial products",
        "roadmap_ref": "Phase 2 feature 2; Phase 4 actuarial data products",
        "evidence_paths": [
            "src/trustai/consent.py",
            "src/trustai/insurer.py",
            "src/trustai/underwriting_quote.py",
            "src/trustai/insurer_partner_service.py",
            "src/trustai/actuarial.py",
            "docs/specs/insurer-consent-v0.1.md",
            "docs/specs/underwriting-quote-v0.1.md",
            "docs/specs/actuarial-product-v0.1.md",
            "tests/test_consent_insurer.py",
            "tests/test_underwriting_quote.py",
            "tests/test_actuarial_product.py",
        ],
        "external_authority": [
            "Live partner authentication, underwriter APIs, binding policy workflows, and partner-owned delivery logs remain external evidence.",
        ],
    },
    {
        "id": "runtime-policy-and-attestation",
        "phase": "P2",
        "priority": "P1",
        "title": "Runtime attestation, policy engine receipts, and proof decay",
        "roadmap_ref": "Core primitive 6; Phase 2 feature 3",
        "evidence_paths": [
            "docs/specs/runtime-policy-v0.1.md",
            "docs/specs/policy-engine-receipt-v0.1.md",
            "src/trustai/runtime.py",
            "src/trustai/policy.py",
            "src/trustai/policy_engine.py",
            "src/trustai/policy_backend_enforcement.py",
            "tests/test_policy_engine.py",
            "tests/test_policy_backend_enforcement.py",
        ],
        "external_authority": [
            "Production Cedar/OPA services require operated policy backends, decision-log roots, and service audit exports.",
        ],
    },
    {
        "id": "agent-inventory-and-identity",
        "phase": "P2",
        "priority": "P1",
        "title": "Agent registry, inventory, identity provider attestations, and lifecycle receipts",
        "roadmap_ref": "Phase 2 feature 4",
        "evidence_paths": [
            "docs/specs/agent-registry-v0.1.md",
            "src/trustai/identity.py",
            "src/trustai/identity_provider_attestation.py",
            "src/trustai/identity_provider_session.py",
            "src/trustai/identity_provider_lifecycle_operation.py",
            "src/trustai/identity_provider_lifecycle_worker.py",
            "docs/specs/identity-provider-attestation-v0.1.md",
            "docs/specs/identity-provider-session-v0.1.md",
            "docs/specs/identity-provider-lifecycle-operation-v0.1.md",
            "docs/specs/identity-provider-lifecycle-worker-v0.1.md",
            "examples/aitrade/identity-inventory.json",
            "tests/test_identity_provider_attestation.py",
            "tests/test_identity_provider_session.py",
            "tests/test_identity_provider_lifecycle_operation.py",
            "tests/test_identity_provider_lifecycle_worker.py",
        ],
        "external_authority": [
            "Live identity-provider event streams, token/session propagation, and provider audit exports remain external evidence.",
        ],
    },
    {
        "id": "multi-agent-evidence",
        "phase": "P2",
        "priority": "P2",
        "title": "Multi-agent delegation evidence graphs",
        "roadmap_ref": "Phase 2 feature 5",
        "evidence_paths": [
            "src/trustai/identity.py",
            "examples/aitrade/delegation.json",
            "docs/specs/trust-network-v0.1.md",
            "tests/test_phase1_phase2.py",
        ],
    },
    {
        "id": "standards-track-and-auditor-ecosystem",
        "phase": "P3",
        "priority": "P1",
        "title": "Standards-track package and auditor certification ecosystem",
        "roadmap_ref": "Phase 3 features 3 and 5",
        "evidence_paths": [
            "src/trustai/standards.py",
            "src/trustai/standards_body_submission.py",
            "src/trustai/certification.py",
            "src/trustai/auditor_accreditation.py",
            "docs/specs/standards-submission-v0.1.md",
            "docs/specs/auditor-certification-v0.1.md",
            "tests/test_standards.py",
            "tests/test_certification.py",
            "tests/test_auditor_accreditation.py",
        ],
        "external_authority": [
            "Actual standards-body acceptance and sponsor-owned KMS/HSM enforcement require external governance events.",
        ],
    },
    {
        "id": "trust-network-procurement-and-marketplace",
        "phase": "P4",
        "priority": "P1",
        "title": "Trust network, procurement clauses, and marketplace distribution",
        "roadmap_ref": "Phase 4 trust network and marketplace",
        "evidence_paths": [
            "src/trustai/trust_network.py",
            "src/trustai/trust_network_registry.py",
            "src/trustai/vendor_identity.py",
            "src/trustai/procurement_clause.py",
            "src/trustai/procurement_integration.py",
            "src/trustai/marketplace.py",
            "src/trustai/marketplace_settlement.py",
            "src/trustai/trust_network_service.py",
            "src/trustai/trust_network_worker.py",
            "src/trustai/trust_network_worker_bundle.py",
            "src/trustai/trust_network_authority.py",
            "docs/specs/procurement-clause-v0.1.md",
            "docs/specs/marketplace-v0.1.md",
            "docs/specs/trust-network-service-attestation-v0.1.md",
            "docs/specs/trust-network-worker-v0.1.md",
            "docs/specs/trust-network-worker-bundle-v0.1.md",
            "docs/specs/trust-network-production-authority-v0.1.md",
            "tests/test_trust_network.py",
            "tests/test_procurement_clause.py",
            "tests/test_marketplace.py",
            "tests/test_trust_network_service.py",
            "tests/test_trust_network_worker.py",
            "tests/test_trust_network_worker_bundle.py",
            "tests/test_trust_network_authority.py",
        ],
        "external_authority": [
            "Signed trust-network service attestations, worker receipts, worker review bundles, and production authority dossiers cover local/reference proof, but live hosted services, provider-owned identity events, marketplace payouts, revocation propagation, callbacks, and procurement propagation remain external evidence until fresh provider-owned exports are supplied.",
        ],
    },
)


@dataclass
class RoadmapAuditVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]
    missing_count: int = 0
    deferred_external_count: int = 0


def build_roadmap_audit(
    root: str | Path,
    *,
    roadmap_path: str | Path = "ROADMAP.md",
    coverage_path: str | Path = "docs/architecture/roadmap-coverage.md",
) -> dict[str, Any]:
    root_path = Path(root)
    roadmap_ref = _file_ref(root_path, roadmap_path)
    coverage_ref = _file_ref(root_path, coverage_path)
    requirements = [_requirement_report(root_path, requirement) for requirement in ROADMAP_REQUIREMENTS]
    summary = _summary(requirements)
    body = {
        "schema": ROADMAP_AUDIT_SCHEMA,
        "generated_at": utc_now(),
        "source": {
            "roadmap": roadmap_ref,
            "coverage": coverage_ref,
            "requirement_count": len(ROADMAP_REQUIREMENTS),
        },
        "summary": summary,
        "requirements": requirements,
        "completion_position": _completion_position(summary),
        "limitations": [
            "This audit proves local repository evidence and hashes; it does not claim live external services exist.",
            "Statuses marked reference-attested require provider-owned, cloud, regulator, insurer, standards-body, or customer evidence before production completion can be claimed.",
            "Business milestones such as paying design partners, ARR, external regulator acceptance, and insurer discounts are out of scope for local repository verification.",
        ],
    }
    return {**body, "audit_id": content_hash(body)}


def verify_roadmap_audit(
    audit: dict[str, Any],
    *,
    root: str | Path,
    roadmap_path: str | Path | None = None,
    coverage_path: str | Path | None = None,
) -> RoadmapAuditVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if audit.get("schema") != ROADMAP_AUDIT_SCHEMA:
        errors.append(f"unsupported roadmap audit schema: {audit.get('schema')}")
    if audit.get("audit_id") != content_hash(without_keys(audit, "audit_id")):
        errors.append("audit_id does not match canonical audit body")

    source = audit.get("source", {})
    if not isinstance(source, dict):
        errors.append("roadmap audit source must be an object")
        source = {}
    _verify_source_ref(root_path, source.get("roadmap"), roadmap_path, "roadmap", errors)
    _verify_source_ref(root_path, source.get("coverage"), coverage_path, "coverage", errors)

    requirements = audit.get("requirements", [])
    if not isinstance(requirements, list) or not requirements:
        errors.append("roadmap audit must include requirements")
        requirements = []

    known_ids = {item["id"] for item in ROADMAP_REQUIREMENTS}
    seen_ids: set[str] = set()
    missing_count = 0
    deferred_external_count = 0
    for requirement in requirements:
        if not isinstance(requirement, dict):
            errors.append("roadmap requirement entry must be an object")
            continue
        req_id = str(requirement.get("id") or "")
        if not req_id:
            errors.append("roadmap requirement missing id")
        elif req_id in seen_ids:
            errors.append(f"duplicate roadmap requirement id: {req_id}")
        seen_ids.add(req_id)
        if req_id and req_id not in known_ids:
            errors.append(f"unknown roadmap requirement id: {req_id}")

        status = requirement.get("status")
        if status not in ALLOWED_STATUSES:
            errors.append(f"requirement {req_id or '<missing>'} has unsupported status: {status}")
        if status == STATUS_MISSING_LOCAL_EVIDENCE:
            missing_count += 1
        if status == STATUS_REFERENCE_ATTESTED:
            deferred_external_count += 1
            external = requirement.get("external_authority_required", [])
            if not isinstance(external, list) or not external:
                errors.append(f"requirement {req_id} is reference-attested without external_authority_required")

        evidence = requirement.get("evidence", [])
        if not isinstance(evidence, list) or not evidence:
            errors.append(f"requirement {req_id or '<missing>'} must include evidence")
            evidence = []
        present_evidence = 0
        missing_evidence = 0
        for item in evidence:
            if not isinstance(item, dict):
                errors.append(f"requirement {req_id or '<missing>'} evidence entry must be an object")
                continue
            present = bool(item.get("present"))
            if present:
                present_evidence += 1
            else:
                missing_evidence += 1
            _verify_evidence_ref(root_path, item, req_id, errors)
        if requirement.get("present_evidence_count") != present_evidence:
            errors.append(f"requirement {req_id} present_evidence_count does not match evidence")
        if requirement.get("missing_evidence_count") != missing_evidence:
            errors.append(f"requirement {req_id} missing_evidence_count does not match evidence")
        if missing_evidence and status != STATUS_MISSING_LOCAL_EVIDENCE:
            errors.append(f"requirement {req_id} has missing evidence but status is {status}")
        if not missing_evidence and status == STATUS_MISSING_LOCAL_EVIDENCE:
            errors.append(f"requirement {req_id} is marked missing but all evidence is present")

    missing_required_ids = known_ids - seen_ids
    if missing_required_ids:
        errors.append("roadmap audit omitted required ids: " + ", ".join(sorted(missing_required_ids)))

    expected_summary = _summary([req for req in requirements if isinstance(req, dict)])
    if audit.get("summary") != expected_summary:
        errors.append("summary does not match requirement statuses")
    if missing_count:
        errors.append(f"{missing_count} roadmap requirements have missing local evidence")
    if not deferred_external_count:
        warnings.append("roadmap audit has no deferred external authority requirements")

    return RoadmapAuditVerification(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        missing_count=missing_count,
        deferred_external_count=deferred_external_count,
    )


def append_roadmap_audit(
    chain: EvidenceChain,
    audit: dict[str, Any],
    *,
    root: str | Path,
    roadmap_path: str | Path | None = None,
    coverage_path: str | Path | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    result = verify_roadmap_audit(
        audit,
        root=root,
        roadmap_path=roadmap_path,
        coverage_path=coverage_path,
    )
    if not result.ok:
        raise ValueError("invalid roadmap audit: " + "; ".join(result.errors))
    summary = audit.get("summary", {})
    payload = {
        "audit_id": audit["audit_id"],
        "audit_hash": content_hash(audit),
        "source": audit.get("source"),
        "completion_position": audit.get("completion_position"),
        "requirement_count": summary.get("requirement_count"),
        "implemented_local_count": summary.get(STATUS_IMPLEMENTED_LOCAL),
        "reference_attested_count": summary.get(STATUS_REFERENCE_ATTESTED),
        "missing_local_evidence_count": summary.get(STATUS_MISSING_LOCAL_EVIDENCE),
        "deferred_external_count": result.deferred_external_count,
        "limitations": audit.get("limitations", []),
    }
    return chain.append(ROADMAP_AUDIT_ENTRY_TYPE, payload, key=key, timestamp=audit.get("generated_at"))

def write_roadmap_audit(path: str | Path, audit: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")


def load_roadmap_audit(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_roadmap_audit_markdown(path: str | Path, audit: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_roadmap_audit_markdown(audit), encoding="utf-8")


def render_roadmap_audit_markdown(audit: dict[str, Any]) -> str:
    summary = audit.get("summary", {})
    rows = "\n".join(
        "| {phase} | {priority} | `{id}` | {status} | {present}/{total} |".format(
            phase=requirement.get("phase", ""),
            priority=requirement.get("priority", ""),
            id=requirement.get("id", ""),
            status=requirement.get("status", ""),
            present=requirement.get("present_evidence_count", 0),
            total=requirement.get("evidence_count", 0),
        )
        for requirement in audit.get("requirements", [])
    )
    deferred = [
        requirement
        for requirement in audit.get("requirements", [])
        if requirement.get("status") == STATUS_REFERENCE_ATTESTED
    ]
    deferred_lines = "\n".join(
        f"- `{requirement.get('id')}`: " + "; ".join(requirement.get("external_authority_required", []))
        for requirement in deferred
    )
    return f"""# TrustAI Roadmap Audit

Audit ID: `{audit.get('audit_id', '')}`

Completion position: {audit.get('completion_position', '')}

## Summary

- Requirements: {summary.get('requirement_count', 0)}
- Implemented locally: {summary.get(STATUS_IMPLEMENTED_LOCAL, 0)}
- Reference-attested, external authority required: {summary.get(STATUS_REFERENCE_ATTESTED, 0)}
- Missing local evidence: {summary.get(STATUS_MISSING_LOCAL_EVIDENCE, 0)}

## Requirements

| Phase | Priority | Requirement | Status | Evidence |
|---|---|---|---|---|
{rows}

## Deferred External Authority

{deferred_lines or "- None"}
"""


def _requirement_report(root: Path, requirement: dict[str, Any]) -> dict[str, Any]:
    evidence = [_file_ref(root, path) for path in requirement["evidence_paths"]]
    present_count = sum(1 for item in evidence if item["present"])
    missing_count = len(evidence) - present_count
    external_authority = list(requirement.get("external_authority", []))
    if missing_count:
        status = STATUS_MISSING_LOCAL_EVIDENCE
    elif external_authority:
        status = STATUS_REFERENCE_ATTESTED
    else:
        status = STATUS_IMPLEMENTED_LOCAL
    return {
        "id": requirement["id"],
        "phase": requirement["phase"],
        "priority": requirement["priority"],
        "title": requirement["title"],
        "roadmap_ref": requirement["roadmap_ref"],
        "status": status,
        "evidence_count": len(evidence),
        "present_evidence_count": present_count,
        "missing_evidence_count": missing_count,
        "evidence": evidence,
        "external_authority_required": external_authority,
    }


def _file_ref(root: Path, path: str | Path) -> dict[str, Any]:
    relative = Path(path).as_posix()
    target = root / relative
    if target.exists() and target.is_file():
        digest = "sha256:" + sha256(target.read_bytes()).hexdigest()
        return {"path": relative, "present": True, "sha256": digest}
    return {"path": relative, "present": False, "sha256": None}


def _verify_source_ref(
    root: Path,
    value: Any,
    expected_path: str | Path | None,
    label: str,
    errors: list[str],
) -> None:
    if not isinstance(value, dict):
        errors.append(f"roadmap audit {label} source must be an object")
        return
    if expected_path is not None and value.get("path") != Path(expected_path).as_posix():
        errors.append(f"roadmap audit {label} source path mismatch")
    _verify_evidence_ref(root, value, f"source:{label}", errors)


def _verify_evidence_ref(root: Path, item: dict[str, Any], req_id: str, errors: list[str]) -> None:
    path_value = item.get("path")
    if not isinstance(path_value, str) or not path_value:
        errors.append(f"requirement {req_id} evidence missing path")
        return
    if Path(path_value).is_absolute() or ".." in Path(path_value).parts:
        errors.append(f"requirement {req_id} evidence path must be repository-relative: {path_value}")
        return
    target = root / path_value
    present = bool(item.get("present"))
    if present:
        if not target.exists() or not target.is_file():
            errors.append(f"requirement {req_id} evidence path missing: {path_value}")
            return
        expected_hash = item.get("sha256")
        actual_hash = "sha256:" + sha256(target.read_bytes()).hexdigest()
        if expected_hash != actual_hash:
            errors.append(f"requirement {req_id} evidence hash mismatch: {path_value}")
    else:
        if item.get("sha256") is not None:
            errors.append(f"requirement {req_id} missing evidence must not include sha256: {path_value}")


def _summary(requirements: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    by_phase: dict[str, dict[str, int]] = {}
    for requirement in requirements:
        status = requirement.get("status")
        if status in by_status:
            by_status[status] += 1
        phase = str(requirement.get("phase") or "unknown")
        phase_summary = by_phase.setdefault(phase, {status: 0 for status in sorted(ALLOWED_STATUSES)})
        if status in phase_summary:
            phase_summary[status] += 1
    return {
        "requirement_count": len(requirements),
        **by_status,
        "by_phase": by_phase,
    }


def _completion_position(summary: dict[str, Any]) -> str:
    if summary.get(STATUS_MISSING_LOCAL_EVIDENCE):
        return "local-evidence-missing"
    if summary.get(STATUS_REFERENCE_ATTESTED):
        return "local-reference-complete-with-external-authority-deferred"
    return "local-roadmap-evidence-complete"
