from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .approvals import APPROVAL_ENTRY_TYPE
from .auditor_accreditation import AUDITOR_ACCREDITATION_ENTRY_TYPE
from .auditor_accreditation_countersignature import AUDITOR_ACCREDITATION_COUNTERSIGNATURE_ENTRY_TYPE
from .auditor_accreditation_kms_enforcement import AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_ENTRY_TYPE
from .auditor_accreditation_signing_audit import AUDITOR_ACCREDITATION_SIGNING_AUDIT_ENTRY_TYPE
from .auditor_accreditation_signing_ceremony import AUDITOR_ACCREDITATION_SIGNING_CEREMONY_ENTRY_TYPE
from .auditor_credential_registry import AUDITOR_CREDENTIAL_REGISTRY_ENTRY_TYPE
from .auditor_program_governance import AUDITOR_PROGRAM_GOVERNANCE_ENTRY_TYPE
from .auditor_program_sponsorship import AUDITOR_PROGRAM_SPONSORSHIP_ENTRY_TYPE
from .byoc_authority import BYOC_AUTHORITY_ENTRY_TYPE
from .byoc_operator import BYOC_OPERATOR_ENTRY_TYPE
from .canonical import content_hash, parse_rfc3339, utc_now
from .chain import EvidenceChain
from .cicd import PROMOTION_STATUS_ENTRY_TYPE
from .compliance_authority import COMPLIANCE_AUTHORITY_ENTRY_TYPE
from .contracts import CONTRACT_ENTRY_TYPE
from .delivery import PROVIDER_DELIVERY_ENTRY_TYPE
from .design_partner import DESIGN_PARTNER_ENTRY_TYPE, P1_PARTNER_TARGET, P1_SIGNED_VALUE_TARGET_USD
from .eu_data_plane import EU_DATA_PLANE_ENTRY_TYPE
from .external_evidence import (
    AUTHORITY_KIND_EVIDENCE_HINTS,
    AUTHORITY_KIND_OWNER_HINTS,
    AUTHORITY_KIND_ORDER,
    EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE,
    EXTERNAL_EVIDENCE_ENTRY_TYPE,
)
from .framework_adapter_authority import FRAMEWORK_ADAPTER_AUTHORITY_ENTRY_TYPE
from .framework_adapter_matrix import FRAMEWORK_ADAPTER_MATRIX_ENTRY_TYPE
from .framework_hook_operation import FRAMEWORK_HOOK_OPERATION_ENTRY_TYPE
from .framework_hook_release import FRAMEWORK_HOOK_RELEASE_ENTRY_TYPE
from .gate import EVAL_ENTRY_TYPE, GATE_ENTRY_TYPE
from .identity_provider_attestation import IDENTITY_PROVIDER_ATTESTATION_ENTRY_TYPE
from .identity_provider_authority import IDENTITY_PROVIDER_AUTHORITY_ENTRY_TYPE
from .identity_provider_lifecycle_operation import IDENTITY_PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE
from .identity_provider_lifecycle_worker import IDENTITY_PROVIDER_LIFECYCLE_WORKER_ENTRY_TYPE
from .identity_provider_session import IDENTITY_PROVIDER_SESSION_ENTRY_TYPE
from .phase_scoreboard import PHASE_SCOREBOARD_ENTRY_TYPE
from .product_scope import PRODUCT_SCOPE_ENTRY_TYPE
from .provider_approval_authority import PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE
from .provider_audit import PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE
from .provider_audit_stream import PROVIDER_AUDIT_STREAM_ENTRY_TYPE
from .provider_audit_worker import PROVIDER_AUDIT_WORKER_ENTRY_TYPE
from .provider_callback_storage import PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE
from .provider_callback_store import PROVIDER_CALLBACK_STORE_ENTRY_TYPE
from .provider_credential_custody import PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE
from .provider_delivery_authority import PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE
from .provider_delivery_service import PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE
from .provider_delivery_worker import PROVIDER_DELIVERY_WORKER_ENTRY_TYPE
from .provider_delivery_worker_bundle import PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE
from .provider_ingress import PROVIDER_INGRESS_ENTRY_TYPE
from .provider_installation import PROVIDER_INSTALLATION_ENTRY_TYPE
from .provider_lifecycle import PROVIDER_LIFECYCLE_ENTRY_TYPE
from .provider_lifecycle_operation import PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE
from .provider_operations_authority import PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE
from .provider_operations_service import PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE
from .provider_webhook import PROVIDER_WEBHOOK_ENTRY_TYPE
from .ingest import INGEST_ENTRY_TYPE
from .insurer_partner_authority import INSURER_PARTNER_AUTHORITY_ENTRY_TYPE
from .lifecycle import DEMOTION_ENTRY_TYPE, INCIDENT_ENTRY_TYPE, ROLLBACK_ENTRY_TYPE, SOAK_DEMOTION_ENTRY_TYPE
from .mcp_gateway import MCP_PROXY_CAPTURE_ENTRY_TYPE, MCP_TOOL_CALL_ENTRY_TYPE
from .onboarding import SELF_SERVE_ONBOARDING_ENTRY_TYPE
from .marketplace import MARKETPLACE_DISTRIBUTION_ENTRY_TYPE
from .marketplace_author import MARKETPLACE_AUTHOR_ENTRY_TYPE
from .marketplace_settlement import MARKETPLACE_SETTLEMENT_ENTRY_TYPE
from .own_compliance import OWN_COMPLIANCE_ENTRY_TYPE, REQUIRED_CERTIFICATION_KINDS
from .procurement_clause import PROCUREMENT_CLAUSE_ENTRY_TYPE
from .procurement_integration import PROCUREMENT_INTEGRATION_ENTRY_TYPE
from .policy import POLICY_DECISION_ENTRY_TYPE
from .policy_backend_authority import (
    POLICY_BACKEND_AUTHORITY_ENTRY_TYPE,
    POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
)
from .policy_backend_enforcement import POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE
from .policy_backend_provider import POLICY_BACKEND_PROVIDER_ENTRY_TYPE
from .policy_backend_provider_bundle import POLICY_BACKEND_PROVIDER_BUNDLE_ENTRY_TYPE
from .policy_backend_service import POLICY_BACKEND_SERVICE_ENTRY_TYPE
from .policy_backend_service_bundle import POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE
from .policy_backend_worker import POLICY_BACKEND_WORKER_ENTRY_TYPE
from .policy_engine import POLICY_ENGINE_ENTRY_TYPE
from .proofpack import PROOF_PACK_SPEC_VERSION
from .reliability_report import RELIABILITY_REPORT_ENTRY_TYPE
from .regulator_acceptance import REGULATOR_ACCEPTANCE_ENTRY_TYPE
from .registry import AGENT_INVENTORY_ENTRY_TYPE, DELEGATION_ENTRY_TYPE, DELEGATION_GRAPH_ENTRY_TYPE
from .review_portal_authority import REVIEW_PORTAL_AUTHORITY_ENTRY_TYPE
from .review_portal_service import REVIEW_PORTAL_SERVICE_ENTRY_TYPE
from .roadmap_audit import ROADMAP_AUDIT_ENTRY_TYPE
from .runtime import RUNTIME_ENTRY_TYPE
from .supervised_access import SUPERVISED_ACCESS_ENTRY_TYPE
from .underwriting_quote import UNDERWRITING_QUOTE_ENTRY_TYPE
from .standards_body_ballot import STANDARDS_BODY_BALLOT_ENTRY_TYPE
from .standards_body_ballot_system import STANDARDS_BODY_BALLOT_SYSTEM_ENTRY_TYPE
from .standards_body_provider_posting import STANDARDS_BODY_PROVIDER_POSTING_ENTRY_TYPE
from .standards_body_status import STANDARDS_BODY_STATUS_ENTRY_TYPE
from .standards_body_submission import STANDARDS_BODY_SUBMISSION_ENTRY_TYPE
from .shadow import (
    SHADOW_REPLAY_ENTRY_TYPE,
    SOAK_REPORT_ENTRY_TYPE,
    TEMPORAL_HOLDOUT_ENTRY_TYPE,
    TRAFFIC_COMPLETENESS_ENTRY_TYPE,
    TRAFFIC_HOLDOUT_EXPORT_ENTRY_TYPE,
)
from .shadow_authority import SHADOW_AUTHORITY_ENTRY_TYPE
from .trust_network_authority import TRUST_NETWORK_AUTHORITY_ENTRY_TYPE
from .trust_network_registry import TRUST_NETWORK_REGISTRY_ENTRY_TYPE
from .trust_network_registry_status import TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE
from .trust_network_service import TRUST_NETWORK_SERVICE_ENTRY_TYPE
from .trust_network_worker import TRUST_NETWORK_WORKER_ENTRY_TYPE
from .trust_network_worker_bundle import TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE
from .vendor_identity import VENDOR_IDENTITY_ENTRY_TYPE
from .vertical_pack import VERTICAL_PACK_ENTRY_TYPE

SCHEMA_VERSION = "trustai.control-plane/0.1"

INDEX_TABLES = (
    "contracts",
    "agents",
    "agent_delegations",
    "agent_delegation_graphs",
    "chain_entries",
    "proof_packs",
    "anchors",
    "byoc_operator_attestations",
    "byoc_authority_dossiers",
    "vendor_identity_receipts",
    "identity_provider_attestations",
    "identity_provider_sessions",
    "identity_provider_lifecycle_operations",
    "identity_provider_lifecycle_workers",
    "identity_provider_authority_dossiers",
    "ingest_events",
    "mcp_tool_calls",
    "mcp_proxy_captures",
    "self_serve_onboarding_receipts",
    "framework_adapter_matrices",
    "framework_hook_releases",
    "framework_hook_operations",
    "framework_adapter_authority_dossiers",
    "supervised_access_receipts",
    "regulator_acceptances",
    "review_portal_service_attestations",
    "review_portal_authority_dossiers",
    "standards_body_evidence",
    "auditor_ecosystem_evidence",
    "trust_network_evidence",
    "provider_delivery_evidence",
    "provider_operations_evidence",
    "compliance_evidence",
    "eval_runs",
    "gate_decisions",
    "human_approvals",
    "promotion_demotions",
    "promotion_rollbacks",
    "soak_demotion_receipts",
    "promotion_statuses",
    "runtime_attestations",
    "policy_decisions",
    "policy_engine_receipts",
    "policy_backend_evidence",
    "incidents",
    "roadmap_audits",
    "external_evidence_collection_runs",
    "external_evidence_manifests",
    "authority_dossiers",
    "phase_scoreboards",
    "design_partner_dossiers",
    "own_compliance_dossiers",
    "product_scope_decisions",
    "vertical_packs",
    "reliability_reports",
    "underwriting_quotes",
    "insurer_partner_authority_dossiers",
    "temporal_holdout_manifests",
    "shadow_replays",
    "soak_reports",
    "traffic_holdout_exports",
    "traffic_completeness_receipts",
)

STANDARDS_BODY_ENTRY_TYPES = {
    STANDARDS_BODY_SUBMISSION_ENTRY_TYPE,
    STANDARDS_BODY_STATUS_ENTRY_TYPE,
    STANDARDS_BODY_BALLOT_ENTRY_TYPE,
    STANDARDS_BODY_BALLOT_SYSTEM_ENTRY_TYPE,
    STANDARDS_BODY_PROVIDER_POSTING_ENTRY_TYPE,
}

STANDARDS_BODY_ARTIFACT_KINDS = {
    STANDARDS_BODY_SUBMISSION_ENTRY_TYPE: "standards-body-submission",
    STANDARDS_BODY_STATUS_ENTRY_TYPE: "standards-body-status",
    STANDARDS_BODY_BALLOT_ENTRY_TYPE: "standards-body-ballot",
    STANDARDS_BODY_BALLOT_SYSTEM_ENTRY_TYPE: "standards-body-ballot-system",
    STANDARDS_BODY_PROVIDER_POSTING_ENTRY_TYPE: "standards-body-provider-posting",
}

AUDITOR_ECOSYSTEM_ENTRY_TYPES = {
    AUDITOR_PROGRAM_GOVERNANCE_ENTRY_TYPE,
    AUDITOR_PROGRAM_SPONSORSHIP_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_COUNTERSIGNATURE_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_SIGNING_CEREMONY_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_SIGNING_AUDIT_ENTRY_TYPE,
    AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_ENTRY_TYPE,
    AUDITOR_CREDENTIAL_REGISTRY_ENTRY_TYPE,
}

AUDITOR_ECOSYSTEM_ARTIFACT_KINDS = {
    AUDITOR_PROGRAM_GOVERNANCE_ENTRY_TYPE: "auditor-program-governance",
    AUDITOR_PROGRAM_SPONSORSHIP_ENTRY_TYPE: "auditor-program-sponsorship",
    AUDITOR_ACCREDITATION_ENTRY_TYPE: "auditor-accreditation",
    AUDITOR_ACCREDITATION_COUNTERSIGNATURE_ENTRY_TYPE: "auditor-accreditation-countersignature",
    AUDITOR_ACCREDITATION_SIGNING_CEREMONY_ENTRY_TYPE: "auditor-accreditation-signing-ceremony",
    AUDITOR_ACCREDITATION_SIGNING_AUDIT_ENTRY_TYPE: "auditor-accreditation-signing-audit",
    AUDITOR_ACCREDITATION_KMS_ENFORCEMENT_ENTRY_TYPE: "auditor-accreditation-kms-enforcement",
    AUDITOR_CREDENTIAL_REGISTRY_ENTRY_TYPE: "auditor-credential-registry",
}

TRUST_NETWORK_ENTRY_TYPES = {
    PROCUREMENT_CLAUSE_ENTRY_TYPE,
    PROCUREMENT_INTEGRATION_ENTRY_TYPE,
    TRUST_NETWORK_REGISTRY_ENTRY_TYPE,
    TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE,
    MARKETPLACE_DISTRIBUTION_ENTRY_TYPE,
    MARKETPLACE_AUTHOR_ENTRY_TYPE,
    MARKETPLACE_SETTLEMENT_ENTRY_TYPE,
    TRUST_NETWORK_SERVICE_ENTRY_TYPE,
    TRUST_NETWORK_WORKER_ENTRY_TYPE,
    TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE,
    TRUST_NETWORK_AUTHORITY_ENTRY_TYPE,
}

TRUST_NETWORK_ARTIFACT_KINDS = {
    PROCUREMENT_CLAUSE_ENTRY_TYPE: "procurement-clause",
    PROCUREMENT_INTEGRATION_ENTRY_TYPE: "procurement-integration",
    TRUST_NETWORK_REGISTRY_ENTRY_TYPE: "trust-network-registry",
    TRUST_NETWORK_REGISTRY_STATUS_ENTRY_TYPE: "trust-network-registry-status",
    MARKETPLACE_DISTRIBUTION_ENTRY_TYPE: "marketplace-distribution",
    MARKETPLACE_AUTHOR_ENTRY_TYPE: "marketplace-author-governance",
    MARKETPLACE_SETTLEMENT_ENTRY_TYPE: "marketplace-settlement",
    TRUST_NETWORK_SERVICE_ENTRY_TYPE: "trust-network-service-attestation",
    TRUST_NETWORK_WORKER_ENTRY_TYPE: "trust-network-worker",
    TRUST_NETWORK_WORKER_BUNDLE_ENTRY_TYPE: "trust-network-worker-bundle",
    TRUST_NETWORK_AUTHORITY_ENTRY_TYPE: "trust-network-authority",
}

PROVIDER_DELIVERY_ENTRY_TYPES = {
    PROVIDER_DELIVERY_ENTRY_TYPE,
    PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE,
    PROVIDER_DELIVERY_WORKER_ENTRY_TYPE,
    PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE,
    PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE,
}

PROVIDER_DELIVERY_ARTIFACT_KINDS = {
    PROVIDER_DELIVERY_ENTRY_TYPE: "provider-delivery",
    PROVIDER_DELIVERY_SERVICE_ENTRY_TYPE: "provider-delivery-service",
    PROVIDER_DELIVERY_WORKER_ENTRY_TYPE: "provider-delivery-worker",
    PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE: "provider-delivery-worker-bundle",
    PROVIDER_DELIVERY_AUTHORITY_ENTRY_TYPE: "provider-delivery-authority",
}

PROVIDER_OPERATIONS_ENTRY_TYPES = {
    PROVIDER_INSTALLATION_ENTRY_TYPE,
    PROVIDER_INGRESS_ENTRY_TYPE,
    PROVIDER_LIFECYCLE_ENTRY_TYPE,
    PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE,
    PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE,
    PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE,
    PROVIDER_WEBHOOK_ENTRY_TYPE,
    PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE,
    PROVIDER_CALLBACK_STORE_ENTRY_TYPE,
    PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE,
    PROVIDER_AUDIT_STREAM_ENTRY_TYPE,
    PROVIDER_AUDIT_WORKER_ENTRY_TYPE,
    PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE,
    PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE,
}

COMPLIANCE_EVIDENCE_ENTRY_TYPES = {
    COMPLIANCE_AUTHORITY_ENTRY_TYPE,
    EU_DATA_PLANE_ENTRY_TYPE,
}

COMPLIANCE_EVIDENCE_ARTIFACT_KINDS = {
    COMPLIANCE_AUTHORITY_ENTRY_TYPE: "compliance-production-authority",
    EU_DATA_PLANE_ENTRY_TYPE: "eu-data-plane-attestation",
}

PROVIDER_OPERATIONS_ARTIFACT_KINDS = {
    PROVIDER_INSTALLATION_ENTRY_TYPE: "provider-installation",
    PROVIDER_INGRESS_ENTRY_TYPE: "provider-ingress",
    PROVIDER_LIFECYCLE_ENTRY_TYPE: "provider-lifecycle",
    PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE: "provider-lifecycle-operation",
    PROVIDER_OPERATIONS_SERVICE_ENTRY_TYPE: "provider-operations-service",
    PROVIDER_OPERATIONS_AUTHORITY_ENTRY_TYPE: "provider-operations-authority",
    PROVIDER_WEBHOOK_ENTRY_TYPE: "provider-webhook",
    PROVIDER_CALLBACK_STORAGE_ENTRY_TYPE: "provider-callback-storage",
    PROVIDER_CALLBACK_STORE_ENTRY_TYPE: "provider-callback-store",
    PROVIDER_AUDIT_CORRELATION_ENTRY_TYPE: "provider-audit-correlation",
    PROVIDER_AUDIT_STREAM_ENTRY_TYPE: "provider-audit-stream",
    PROVIDER_AUDIT_WORKER_ENTRY_TYPE: "provider-audit-worker",
    PROVIDER_CREDENTIAL_CUSTODY_ENTRY_TYPE: "provider-credential-custody",
    PROVIDER_APPROVAL_AUTHORITY_ENTRY_TYPE: "provider-approval-authority",
}

POLICY_BACKEND_ENTRY_TYPES = {
    POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE,
    POLICY_BACKEND_SERVICE_ENTRY_TYPE,
    POLICY_BACKEND_WORKER_ENTRY_TYPE,
    POLICY_BACKEND_PROVIDER_ENTRY_TYPE,
    POLICY_BACKEND_PROVIDER_BUNDLE_ENTRY_TYPE,
    POLICY_BACKEND_AUTHORITY_ENTRY_TYPE,
    POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE,
    POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE,
}

POLICY_BACKEND_ARTIFACT_KINDS = {
    POLICY_BACKEND_ENFORCEMENT_ENTRY_TYPE: "policy-backend-enforcement",
    POLICY_BACKEND_SERVICE_ENTRY_TYPE: "policy-backend-service",
    POLICY_BACKEND_WORKER_ENTRY_TYPE: "policy-backend-worker",
    POLICY_BACKEND_PROVIDER_ENTRY_TYPE: "policy-backend-provider-export",
    POLICY_BACKEND_PROVIDER_BUNDLE_ENTRY_TYPE: "policy-backend-provider-bundle",
    POLICY_BACKEND_AUTHORITY_ENTRY_TYPE: "policy-backend-authority",
    POLICY_BACKEND_AUTHORITY_EVIDENCE_BUNDLE_ENTRY_TYPE: "policy-backend-authority-evidence-bundle",
    POLICY_BACKEND_SERVICE_BUNDLE_ENTRY_TYPE: "policy-backend-service-bundle",
}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _payload_contract_hash(entry: dict[str, Any]) -> str | None:
    payload = entry.get("payload", {})
    if not isinstance(payload, dict):
        return None
    if payload.get("contract_hash"):
        return payload["contract_hash"]
    contract = payload.get("contract")
    if isinstance(contract, dict) and contract.get("hash"):
        return contract.get("hash")
    traffic_export = payload.get("traffic_export")
    if isinstance(traffic_export, dict):
        traffic_contract = traffic_export.get("contract")
        if isinstance(traffic_contract, dict) and traffic_contract.get("hash"):
            return traffic_contract.get("hash")
    decision = payload.get("decision")
    if isinstance(decision, dict):
        return decision.get("contract_hash")
    trace = payload.get("trace")
    if isinstance(trace, dict):
        contract_hashes = trace.get("contract_hashes")
        if isinstance(contract_hashes, list):
            for item in contract_hashes:
                if item:
                    return str(item)
    return None


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
        elif isinstance(value, (int, float)):
            return str(value)
    return None


def _source_artifact_count(payload: dict[str, Any]) -> int:
    artifacts = payload.get("source_artifacts")
    if isinstance(artifacts, list):
        return len(artifacts)
    refs = payload.get("source_refs")
    return len(refs) if isinstance(refs, list) else 0


def _source_artifacts(payload: dict[str, Any]) -> list[Any]:
    artifacts = payload.get("source_artifacts")
    if isinstance(artifacts, list):
        return artifacts
    refs = payload.get("source_refs")
    return refs if isinstance(refs, list) else []


def _control_count(payload: dict[str, Any]) -> int:
    controls = payload.get("controls")
    if isinstance(controls, list):
        return len(controls)
    if isinstance(controls, dict):
        return len(controls)
    return 0


def _standards_body_record(entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    entry_type = str(entry.get("entry_type") or "")
    standards_body = _object(payload.get("standards_body"))
    submission = _object(payload.get("submission"))
    status_update = _object(payload.get("status_update"))
    ballot = _object(payload.get("ballot"))
    request = _object(payload.get("request"))
    response = _object(payload.get("response"))
    target = _object(payload.get("target_submission"))
    target_body = _object(target.get("standards_body"))
    source = _object(payload.get("source"))
    source_body = _object(source.get("standards_body"))
    actor = _object(status_update.get("actor") or request.get("actor") or payload.get("actor"))
    artifact_id = _first_text(
        payload.get("submission_id"),
        payload.get("status_id"),
        payload.get("ballot_id"),
        payload.get("ballot_system_id"),
        payload.get("posting_id"),
        content_hash(payload),
    )
    return {
        "artifact_id": artifact_id,
        "entry_id": entry.get("entry_id"),
        "entry_type": entry_type,
        "artifact_kind": STANDARDS_BODY_ARTIFACT_KINDS.get(entry_type, entry_type),
        "artifact_hash": content_hash(payload),
        "artifact_ref": _first_text(
            submission.get("submission_ref"),
            status_update.get("status_ref"),
            status_update.get("docket_ref"),
            ballot.get("ballot_ref"),
            request.get("request_ref"),
            response.get("response_ref"),
            payload.get("posting_ref"),
            artifact_id,
        ),
        "status": _first_text(
            submission.get("status"),
            status_update.get("new_status"),
            ballot.get("outcome"),
            request.get("mode"),
            response.get("status"),
            payload.get("mode"),
        ),
        "standards_body_name": _first_text(standards_body.get("name"), target_body.get("name"), source_body.get("name")),
        "program_ref": _first_text(standards_body.get("program_ref"), target_body.get("program_ref"), source_body.get("program_ref")),
        "target_track": _first_text(standards_body.get("target_track"), target_body.get("target_track"), source_body.get("target_track")),
        "actor_ref": _first_text(actor.get("ref"), actor.get("actor_ref"), submission.get("submitter_ref")),
        "source_artifact_count": _source_artifact_count(payload),
        "control_count": _control_count(payload),
        "observed_at": _first_text(
            payload.get("submitted_at"),
            payload.get("decided_at"),
            payload.get("effective_at"),
            payload.get("certified_at"),
            payload.get("exported_at"),
            payload.get("posted_at"),
            payload.get("published_at"),
            entry.get("timestamp"),
        ),
        "source_artifacts": _source_artifacts(payload),
        "controls": payload.get("controls") if isinstance(payload.get("controls"), (dict, list)) else {},
    }


def _auditor_ecosystem_record(entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    entry_type = str(entry.get("entry_type") or "")
    program = _object(payload.get("program"))
    governance = _object(payload.get("governance"))
    accreditation_body = _object(payload.get("accreditation_body"))
    auditor = _object(payload.get("auditor"))
    credential = _object(payload.get("credential"))
    credential_record = _object(payload.get("credential_record"))
    sponsorship = _object(payload.get("sponsorship"))
    ceremony = _object(payload.get("signing_ceremony"))
    audit = _object(payload.get("signing_audit"))
    enforcement = _object(payload.get("kms_enforcement"))
    registry = _object(payload.get("registry"))
    artifact_id = _first_text(
        payload.get("program_id"),
        payload.get("sponsorship_id"),
        payload.get("accreditation_id"),
        payload.get("countersignature_id"),
        payload.get("ceremony_id"),
        payload.get("signing_audit_id"),
        payload.get("enforcement_id"),
        payload.get("registry_id"),
        content_hash(payload),
    )
    return {
        "artifact_id": artifact_id,
        "entry_id": entry.get("entry_id"),
        "entry_type": entry_type,
        "artifact_kind": AUDITOR_ECOSYSTEM_ARTIFACT_KINDS.get(entry_type, entry_type),
        "artifact_hash": content_hash(payload),
        "artifact_ref": _first_text(
            program.get("program_ref"),
            governance.get("governance_ref"),
            sponsorship.get("sponsorship_ref"),
            credential.get("credential_id"),
            credential_record.get("credential_id"),
            ceremony.get("ceremony_ref"),
            audit.get("audit_ref"),
            enforcement.get("enforcement_ref"),
            registry.get("publication_ref"),
            artifact_id,
        ),
        "status": _first_text(
            program.get("status"),
            sponsorship.get("status"),
            credential.get("status"),
            credential_record.get("status"),
            payload.get("status"),
            enforcement.get("mode"),
            payload.get("mode"),
        ),
        "program_ref": _first_text(program.get("program_ref"), accreditation_body.get("program_ref"), payload.get("program_ref")),
        "auditor_ref": _first_text(auditor.get("subject_ref"), credential_record.get("subject_ref"), credential.get("auditor_ref")),
        "auditor_organization": _first_text(auditor.get("organization"), credential_record.get("organization")),
        "authority_ref": _first_text(accreditation_body.get("name"), program.get("accreditation_body"), payload.get("provider"), registry.get("name")),
        "actor_ref": _first_text(governance.get("operator_ref"), payload.get("operator_ref"), audit.get("actor_ref"), enforcement.get("actor_ref")),
        "source_artifact_count": _source_artifact_count(payload),
        "control_count": _control_count(payload),
        "observed_at": _first_text(
            payload.get("issued_at"),
            payload.get("effective_at"),
            payload.get("countersigned_at"),
            payload.get("signed_at"),
            payload.get("published_at"),
            payload.get("recorded_at"),
            payload.get("enforced_at"),
            entry.get("timestamp"),
        ),
        "source_artifacts": _source_artifacts(payload),
        "controls": payload.get("controls") if isinstance(payload.get("controls"), (dict, list)) else {},
    }


def _trust_network_source_artifacts(payload: dict[str, Any]) -> list[Any]:
    artifacts = _source_artifacts(payload)
    if artifacts:
        return artifacts
    source = _object(payload.get("source"))
    source_artifacts = source.get("source_artifacts")
    if isinstance(source_artifacts, list):
        return source_artifacts
    source_refs = source.get("source_refs")
    return source_refs if isinstance(source_refs, list) else []


def _trust_network_controls(payload: dict[str, Any]) -> Any:
    for key in ("controls", "control_summary", "control_status_summary"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            return value
    return {}


def _trust_network_control_count(payload: dict[str, Any]) -> int:
    controls = _trust_network_controls(payload)
    return len(controls) if isinstance(controls, (dict, list)) else 0


def _trust_network_record(entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    entry_type = str(entry.get("entry_type") or "")
    buyer = _object(payload.get("buyer"))
    contract = _object(payload.get("contract"))
    request = _object(payload.get("request"))
    response = _object(payload.get("response"))
    registry = _object(payload.get("registry"))
    registration = _object(payload.get("registration"))
    status_update = _object(payload.get("status_update"))
    vendor = _object(payload.get("vendor"))
    trust_network = _object(payload.get("trust_network"))
    procurement = _object(payload.get("procurement"))
    channel = _object(payload.get("channel"))
    subscriber = _object(payload.get("subscriber"))
    catalog = _object(payload.get("catalog"))
    distribution = _object(payload.get("distribution"))
    author = _object(payload.get("author"))
    identity = _object(payload.get("identity"))
    settlement = _object(payload.get("settlement"))
    invoice = _object(payload.get("invoice"))
    payout = _object(payload.get("payout"))
    service = _object(payload.get("service"))
    marketplace = _object(payload.get("marketplace"))
    worker = _object(payload.get("worker"))
    scheduler = _object(payload.get("scheduler"))
    summary = _object(payload.get("summary"))
    service_binding = _object(payload.get("service_attestation_binding"))
    artifact_id = _first_text(
        payload.get("receipt_id"),
        payload.get("integration_id"),
        payload.get("registration_id"),
        payload.get("status_id"),
        payload.get("distribution_id"),
        payload.get("governance_id"),
        payload.get("settlement_id"),
        payload.get("attestation_id"),
        payload.get("worker_operation_id"),
        payload.get("bundle_id"),
        payload.get("dossier_id"),
        content_hash(payload),
    )
    return {
        "artifact_id": artifact_id,
        "entry_id": entry.get("entry_id"),
        "entry_type": entry_type,
        "artifact_kind": TRUST_NETWORK_ARTIFACT_KINDS.get(entry_type, entry_type),
        "artifact_hash": content_hash(payload),
        "artifact_ref": _first_text(
            contract.get("contract_ref"),
            request.get("request_ref"),
            response.get("response_ref"),
            registration.get("registration_ref"),
            status_update.get("status_ref"),
            status_update.get("docket_ref"),
            payload.get("distribution_ref"),
            distribution.get("distribution_ref"),
            catalog.get("catalog_ref"),
            author.get("author_ref"),
            author.get("subject_ref"),
            settlement.get("settlement_ref"),
            service.get("service_ref"),
            worker.get("worker_ref"),
            worker.get("operation_ref"),
            scheduler.get("run_ref"),
            payload.get("bundle_ref"),
            payload.get("dossier_ref"),
            payload.get("authority_ref"),
            artifact_id,
        ),
        "status": _first_text(
            contract.get("status"),
            response.get("status"),
            registration.get("status"),
            status_update.get("new_status"),
            invoice.get("status"),
            payout.get("status"),
            settlement.get("status"),
            service.get("status"),
            worker.get("status"),
            summary.get("status"),
            payload.get("status"),
            payload.get("mode"),
        ),
        "mode": _first_text(payload.get("mode"), request.get("mode")),
        "environment": _first_text(payload.get("environment"), service.get("environment"), worker.get("environment")),
        "party_ref": _first_text(
            buyer.get("ref"),
            buyer.get("buyer_ref"),
            vendor.get("subject_ref"),
            vendor.get("name"),
            subscriber.get("ref"),
            subscriber.get("subscriber_ref"),
            author.get("ref"),
            author.get("subject_ref"),
            identity.get("subject_ref"),
            payload.get("producer_ref"),
            payload.get("reviewer_ref"),
        ),
        "service_ref": _first_text(service.get("service_ref"), service_binding.get("service_ref"), payload.get("service_ref")),
        "registry_ref": _first_text(registry.get("registry_ref"), registry.get("name"), registration.get("registry_ref"), trust_network.get("registry_ref")),
        "marketplace_ref": _first_text(marketplace.get("marketplace_ref"), channel.get("channel_ref"), procurement.get("marketplace_ref")),
        "source_artifact_count": len(_trust_network_source_artifacts(payload)),
        "control_count": _trust_network_control_count(payload),
        "observed_at": _first_text(
            payload.get("issued_at"),
            payload.get("recorded_at"),
            payload.get("generated_at"),
            payload.get("distributed_at"),
            payload.get("delivered_at"),
            payload.get("published_at"),
            payload.get("decided_at"),
            payload.get("attested_at"),
            status_update.get("effective_at"),
            entry.get("timestamp"),
        ),
        "source_artifacts": _trust_network_source_artifacts(payload),
        "controls": _trust_network_controls(payload),
    }


def _first_int(*values: Any) -> int | None:
    for value in values:
        if value is None or isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                continue
    return None


def _first_bool(*values: Any) -> bool | None:
    for value in values:
        if isinstance(value, bool):
            return value
    return None


def _provider_delivery_source_artifacts(payload: dict[str, Any]) -> list[Any]:
    artifacts = _source_artifacts(payload)
    if artifacts:
        return artifacts
    source = _object(payload.get("source"))
    source_artifacts = source.get("source_artifacts")
    if isinstance(source_artifacts, list):
        return source_artifacts
    source_refs = source.get("source_refs")
    if isinstance(source_refs, list):
        return source_refs
    payload_artifact = payload.get("payload_artifact")
    return [payload_artifact] if isinstance(payload_artifact, dict) else []


def _provider_delivery_controls(payload: dict[str, Any]) -> Any:
    for key in ("controls", "control_summary", "control_status_summary"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            return value
    return {}


def _provider_delivery_control_count(payload: dict[str, Any]) -> int:
    controls = _provider_delivery_controls(payload)
    return len(controls) if isinstance(controls, (dict, list)) else 0


def _provider_delivery_record(entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    entry_type = str(entry.get("entry_type") or "")
    request = _object(payload.get("request"))
    response = _object(payload.get("response"))
    service = _object(payload.get("service"))
    dispatch = _object(payload.get("dispatch"))
    worker = _object(payload.get("worker"))
    source_delivery = _object(payload.get("source_delivery"))
    provider_response = _object(payload.get("provider_response"))
    summary = _object(payload.get("summary"))
    service_binding = _object(payload.get("service_attestation_binding"))
    worker_bundle_bindings = payload.get("worker_bundle_bindings")
    bundle_binding = (
        worker_bundle_bindings[0]
        if isinstance(worker_bundle_bindings, list)
        and worker_bundle_bindings
        and isinstance(worker_bundle_bindings[0], dict)
        else {}
    )
    artifact_id = _first_text(
        payload.get("delivery_id"),
        payload.get("attestation_id"),
        payload.get("worker_operation_id"),
        payload.get("bundle_id"),
        payload.get("dossier_id"),
        content_hash(payload),
    )
    success = _first_bool(
        response.get("accepted"),
        worker.get("success"),
        dispatch.get("response_accepted"),
        provider_response.get("accepted"),
        provider_response.get("success"),
    )
    return {
        "artifact_id": artifact_id,
        "entry_id": entry.get("entry_id"),
        "entry_type": entry_type,
        "artifact_kind": PROVIDER_DELIVERY_ARTIFACT_KINDS.get(entry_type, entry_type),
        "artifact_hash": content_hash(payload),
        "artifact_ref": _first_text(
            payload.get("target_url"),
            dispatch.get("destination_ref"),
            source_delivery.get("target_url"),
            payload.get("bundle_ref"),
            payload.get("dossier_ref"),
            payload.get("authority_ref"),
            service.get("service_ref"),
            worker.get("worker_ref"),
            artifact_id,
        ),
        "status": _first_text(
            summary.get("status"),
            service.get("status"),
            worker.get("status"),
            response.get("status"),
            dispatch.get("response_status"),
            provider_response.get("status"),
            payload.get("mode"),
        ),
        "mode": _first_text(payload.get("mode"), source_delivery.get("mode")),
        "environment": _first_text(payload.get("environment"), service.get("environment")),
        "provider": _first_text(payload.get("provider"), service.get("provider"), source_delivery.get("provider")),
        "service_ref": _first_text(service.get("service_ref"), service_binding.get("service_ref")),
        "worker_ref": _first_text(worker.get("worker_ref"), dispatch.get("dispatch_worker_ref")),
        "bundle_ref": _first_text(payload.get("bundle_ref"), bundle_binding.get("bundle_ref")),
        "authority_ref": _first_text(payload.get("authority_ref"), payload.get("producer_ref"), payload.get("reviewer_ref")),
        "pack_id": _first_text(payload.get("pack_id"), source_delivery.get("pack_id")),
        "contract_id": _first_text(payload.get("contract_id"), source_delivery.get("contract_id")),
        "contract_hash": _first_text(payload.get("contract_hash"), source_delivery.get("contract_hash")),
        "target_ref": _first_text(payload.get("target_url"), dispatch.get("destination_ref"), source_delivery.get("target_url"), request.get("path")),
        "provider_endpoint": _first_text(payload.get("endpoint_base"), dispatch.get("provider_endpoint_base"), dispatch.get("destination_ref")),
        "response_status": _first_int(response.get("status"), dispatch.get("response_status"), provider_response.get("status")),
        "success": success,
        "source_artifact_count": len(_provider_delivery_source_artifacts(payload)),
        "control_count": _provider_delivery_control_count(payload),
        "observed_at": _first_text(
            payload.get("delivered_at"),
            payload.get("attested_at"),
            payload.get("recorded_at"),
            payload.get("generated_at"),
            entry.get("timestamp"),
        ),
        "source_artifacts": _provider_delivery_source_artifacts(payload),
        "controls": _provider_delivery_controls(payload),
    }


def _provider_operations_source_artifacts(payload: dict[str, Any]) -> list[Any]:
    artifacts = _source_artifacts(payload)
    if artifacts:
        return artifacts
    for key in ("source", "sources", "source_binding", "service_attestation_binding"):
        source = _object(payload.get(key))
        for field in ("source_artifacts", "source_refs", "source_receipts"):
            value = source.get(field)
            if isinstance(value, list):
                return value
    payload_artifact = payload.get("payload_artifact")
    return [payload_artifact] if isinstance(payload_artifact, dict) else []


def _provider_operations_controls(payload: dict[str, Any]) -> Any:
    for key in ("controls", "control_summary", "control_status_summary"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            return value
    return {}


def _provider_operations_control_count(payload: dict[str, Any]) -> int:
    controls = _provider_operations_controls(payload)
    return len(controls) if isinstance(controls, (dict, list)) else 0


def _provider_operations_source_artifact_count(payload: dict[str, Any]) -> int:
    artifacts = _provider_operations_source_artifacts(payload)
    explicit_count = _first_int(payload.get("source_artifact_count"))
    return explicit_count if explicit_count is not None else len(artifacts)


def _provider_operations_record(entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    entry_type = str(entry.get("entry_type") or "")
    names = (
        "app", "installation", "ingress", "lifecycle", "operation", "credential",
        "token_store", "audit_log", "storage", "database", "service", "operations",
        "webhook", "payload", "verification", "source", "security", "operation_actor",
        "source_binding", "service_attestation_binding", "summary", "stream", "worker",
        "scheduler", "sources", "custody", "vault", "policy",
    )
    o = {name: _object(payload.get(name)) for name in names}
    actor_credential = _object(o["operation_actor"].get("credential"))
    artifact_id = _first_text(
        payload.get("manifest_id"), payload.get("ingress_manifest_id"), payload.get("lifecycle_manifest_id"),
        payload.get("operation_receipt_id"), payload.get("attestation_id"), payload.get("dossier_id"),
        payload.get("receipt_id"), payload.get("storage_manifest_id"), payload.get("store_manifest_id"),
        payload.get("correlation_id"), payload.get("stream_receipt_id"), payload.get("worker_operation_id"),
        payload.get("custody_id"), content_hash(payload),
    )
    operation_kind = _first_text(
        o["operation"].get("operation_kind"), o["operation"].get("kind"), o["operation"].get("type"),
        o["operations"].get("operation_kind"), o["lifecycle"].get("operation_kind"),
        o["webhook"].get("event_type"), o["webhook"].get("event"), o["payload"].get("event_type"),
        payload.get("operation_kind"),
    )
    return {
        "artifact_id": artifact_id,
        "entry_id": entry.get("entry_id"),
        "entry_type": entry_type,
        "artifact_kind": PROVIDER_OPERATIONS_ARTIFACT_KINDS.get(entry_type, entry_type),
        "artifact_hash": content_hash(payload),
        "artifact_ref": _first_text(
            payload.get("dossier_ref"), payload.get("authority_ref"), o["service"].get("service_ref"),
            o["operation"].get("operation_ref"), o["operation"].get("operation_id"),
            o["installation"].get("installation_ref"), o["installation"].get("installation_id"),
            o["ingress"].get("ingress_ref"), o["ingress"].get("endpoint_ref"),
            o["webhook"].get("webhook_ref"), o["webhook"].get("event_id"),
            o["storage"].get("storage_ref"), o["database"].get("store_ref"),
            o["audit_log"].get("audit_log_ref"), o["audit_log"].get("log_ref"), payload.get("audit_log_ref"),
            o["stream"].get("stream_ref"), o["worker"].get("worker_ref"),
            o["custody"].get("custody_ref"), o["credential"].get("credential_ref"),
            o["credential"].get("subject_ref"), o["vault"].get("vault_ref"), o["app"].get("app_ref"), artifact_id,
        ),
        "status": _first_text(
            o["summary"].get("status"), o["service"].get("status"), o["operations"].get("status"),
            o["operation"].get("status"), o["lifecycle"].get("status"), o["installation"].get("status"),
            o["ingress"].get("status"), o["webhook"].get("status"), o["verification"].get("status"),
            o["storage"].get("status"), o["database"].get("status"), o["stream"].get("status"),
            o["worker"].get("status"), o["custody"].get("status"), o["policy"].get("status"),
            o["security"].get("status"), payload.get("mode"),
        ),
        "mode": _first_text(payload.get("mode"), o["storage"].get("mode"), o["source"].get("mode")),
        "environment": _first_text(payload.get("environment"), o["service"].get("environment"), o["storage"].get("environment"), o["stream"].get("environment"), o["worker"].get("environment"), o["source"].get("environment")),
        "provider": _first_text(payload.get("provider"), o["service"].get("provider"), o["operations"].get("provider"), o["operation"].get("provider"), o["installation"].get("provider"), o["ingress"].get("provider"), o["webhook"].get("provider"), o["audit_log"].get("provider"), o["credential"].get("provider"), o["stream"].get("provider"), o["worker"].get("provider")),
        "operation_kind": operation_kind,
        "service_ref": _first_text(o["service"].get("service_ref"), o["service_attestation_binding"].get("service_ref"), o["source_binding"].get("service_ref")),
        "installation_ref": _first_text(o["installation"].get("installation_ref"), o["installation"].get("installation_id"), o["source_binding"].get("installation_ref"), o["source_binding"].get("installation_id"), payload.get("installation_ref")),
        "webhook_ref": _first_text(o["webhook"].get("webhook_ref"), o["webhook"].get("delivery_id"), o["webhook"].get("event_id"), o["source_binding"].get("webhook_ref"), payload.get("receipt_id") if entry_type == PROVIDER_WEBHOOK_ENTRY_TYPE else None),
        "callback_ref": _first_text(o["storage"].get("storage_ref"), o["database"].get("store_ref"), o["database"].get("database_ref"), payload.get("storage_manifest_id"), payload.get("store_manifest_id"), o["source_binding"].get("callback_ref")),
        "audit_ref": _first_text(o["audit_log"].get("audit_log_ref"), o["audit_log"].get("log_ref"), payload.get("audit_log_ref"), o["stream"].get("audit_log_ref"), o["stream"].get("stream_ref"), o["sources"].get("audit_log_ref"), o["source_binding"].get("audit_log_ref")),
        "credential_ref": _first_text(o["credential"].get("credential_ref"), o["credential"].get("subject_ref"), actor_credential.get("credential_ref"), actor_credential.get("subject_ref"), o["token_store"].get("credential_ref"), o["custody"].get("credential_ref"), o["vault"].get("vault_ref")),
        "authority_ref": _first_text(payload.get("authority_ref"), payload.get("producer_ref"), o["source_binding"].get("authority_ref"), o["source_binding"].get("provider_operations_authority_ref"), o["source_binding"].get("provider_approval_authority_ref")),
        "target_ref": _first_text(o["webhook"].get("target_ref"), o["webhook"].get("endpoint_ref"), o["ingress"].get("endpoint_ref"), o["service"].get("endpoint_ref"), o["operations"].get("endpoint_ref"), o["stream"].get("stream_ref"), o["storage"].get("schema_ref"), o["database"].get("schema_version"), o["scheduler"].get("run_ref")),
        "source_artifact_count": _provider_operations_source_artifact_count(payload),
        "control_count": _provider_operations_control_count(payload),
        "observed_at": _first_text(payload.get("installed_at"), payload.get("attested_at"), payload.get("recorded_at"), payload.get("received_at"), payload.get("correlated_at"), payload.get("issued_at"), payload.get("generated_at"), entry.get("timestamp")),
        "source_artifacts": _provider_operations_source_artifacts(payload),
        "controls": _provider_operations_controls(payload),
    }


def _policy_backend_source_artifacts(payload: dict[str, Any]) -> list[Any]:
    artifacts = _source_artifacts(payload)
    if artifacts:
        return artifacts
    for key in (
        "source", "sources", "source_enforcement", "enforcement", "service", "worker",
        "provider_exports", "provider_export", "provider_bundle_binding", "source_binding",
    ):
        source = _object(payload.get(key))
        for field in ("source_artifacts", "source_refs", "source_receipts", "artifact_refs"):
            value = source.get(field)
            if isinstance(value, list):
                return value
    authority_evidence = payload.get("authority_evidence")
    return authority_evidence if isinstance(authority_evidence, list) else []


def _policy_backend_controls(payload: dict[str, Any]) -> Any:
    for key in ("controls", "control_summary", "controls_summary", "control_status_summary"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            return value
    return {}


def _policy_backend_control_count(payload: dict[str, Any]) -> int:
    controls = _policy_backend_controls(payload)
    return len(controls) if isinstance(controls, (dict, list)) else 0


def _policy_backend_source_artifact_count(payload: dict[str, Any]) -> int:
    explicit_count = _first_int(payload.get("source_artifact_count"))
    return explicit_count if explicit_count is not None else len(_policy_backend_source_artifacts(payload))


def _policy_backend_record(entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    entry_type = str(entry.get("entry_type") or "")
    names = (
        "backend", "credential", "backend_credential", "policy", "action", "proof_pack",
        "decision", "backend_decision", "policy_export", "policy_engine_receipt", "source",
        "enforcement", "source_enforcement", "service", "security", "operation", "audit_log",
        "worker", "scheduler", "execution", "observability", "provider_exports", "provider",
        "provider_export", "provider_exchange", "matched_scheduler_record", "matched_queue_record",
        "matched_lease_record", "matched_backend_record", "matched_decision_log_record",
        "matched_audit_record", "provider_bundle_binding", "source_binding", "summary",
    )
    o = {name: _object(payload.get(name)) for name in names}
    artifact_id = _first_text(
        payload.get("enforcement_id"),
        payload.get("attestation_id"),
        payload.get("provider_receipt_id"),
        payload.get("worker_operation_id"),
        payload.get("bundle_id"),
        payload.get("dossier_id"),
        content_hash(payload),
    )
    return {
        "artifact_id": artifact_id,
        "entry_id": entry.get("entry_id"),
        "entry_type": entry_type,
        "artifact_kind": POLICY_BACKEND_ARTIFACT_KINDS.get(entry_type, entry_type),
        "artifact_hash": content_hash(payload),
        "artifact_ref": _first_text(
            payload.get("dossier_ref"), payload.get("bundle_ref"), payload.get("authority_ref"),
            o["backend"].get("backend_ref"), o["service"].get("service_ref"),
            o["worker"].get("worker_ref"), o["provider_export"].get("export_ref"),
            o["provider_export"].get("provider_export_ref"), o["provider"].get("provider_ref"),
            o["policy"].get("policy_ref"), o["policy"].get("policy_id"),
            o["action"].get("action_ref"), o["action"].get("action_id"), artifact_id,
        ),
        "status": _first_text(
            o["summary"].get("status"), o["backend_decision"].get("status"),
            o["backend_decision"].get("outcome"), o["decision"].get("outcome"),
            o["service"].get("status"), o["worker"].get("status"),
            o["execution"].get("status"), o["operation"].get("status"),
            o["provider_export"].get("status"), o["provider"].get("status"),
            o["matched_backend_record"].get("status"), payload.get("mode"),
        ),
        "mode": _first_text(payload.get("mode"), o["backend"].get("mode"), o["service"].get("mode")),
        "environment": _first_text(payload.get("environment"), o["backend"].get("environment"), o["service"].get("environment"), o["worker"].get("environment")),
        "backend_ref": _first_text(o["backend"].get("backend_ref"), o["enforcement"].get("backend_ref"), o["source_enforcement"].get("backend_ref"), o["matched_backend_record"].get("backend_ref")),
        "engine": _first_text(o["backend"].get("engine"), o["backend"].get("engine_name"), o["service"].get("engine"), o["source_enforcement"].get("engine"), o["policy_engine_receipt"].get("engine_name")),
        "policy_ref": _first_text(o["policy"].get("policy_ref"), o["policy"].get("policy_id"), o["policy_export"].get("policy_ref"), o["policy_export"].get("policy_pack_id"), o["policy_engine_receipt"].get("policy_pack_id")),
        "action_ref": _first_text(o["action"].get("action_ref"), o["action"].get("action_id"), o["source_enforcement"].get("action_ref"), o["source_enforcement"].get("action_id")),
        "decision_ref": _first_text(o["backend_decision"].get("decision_ref"), o["backend_decision"].get("decision_id"), o["decision"].get("decision_ref"), o["decision"].get("decision_id"), o["policy_engine_receipt"].get("receipt_id")),
        "service_ref": _first_text(o["service"].get("service_ref"), o["source"].get("service_ref"), o["provider_bundle_binding"].get("service_ref")),
        "worker_ref": _first_text(o["worker"].get("worker_ref"), o["scheduler"].get("worker_ref"), payload.get("worker_operation_id")),
        "provider_ref": _first_text(o["provider"].get("provider_ref"), o["provider_export"].get("provider_ref"), o["provider_exports"].get("provider_ref"), o["provider_exchange"].get("provider_ref")),
        "bundle_ref": _first_text(payload.get("bundle_ref"), o["provider_bundle_binding"].get("bundle_ref"), o["provider_bundle_binding"].get("bundle_id")),
        "authority_ref": _first_text(payload.get("authority_ref"), payload.get("producer_ref"), o["source_binding"].get("authority_ref")),
        "credential_ref": _first_text(payload.get("credential_ref"), o["credential"].get("credential_ref"), o["credential"].get("ref"), o["credential"].get("subject_ref"), o["backend_credential"].get("credential_ref"), o["backend_credential"].get("ref")),
        "audit_ref": _first_text(o["audit_log"].get("audit_log_ref"), o["audit_log"].get("log_ref"), o["observability"].get("audit_log_ref"), o["matched_audit_record"].get("audit_log_ref")),
        "response_status": _first_int(o["backend_decision"].get("response_status"), o["backend"].get("response_status"), o["provider_exchange"].get("response_status")),
        "allowed": _first_bool(o["backend_decision"].get("allowed"), o["decision"].get("allowed")),
        "source_artifact_count": _policy_backend_source_artifact_count(payload),
        "control_count": _policy_backend_control_count(payload),
        "observed_at": _first_text(payload.get("enforced_at"), payload.get("attested_at"), payload.get("recorded_at"), payload.get("generated_at"), entry.get("timestamp")),
        "source_artifacts": _policy_backend_source_artifacts(payload),
        "controls": _policy_backend_controls(payload),
    }

def _compliance_source_artifacts(payload: dict[str, Any]) -> list[Any]:
    artifacts = _source_artifacts(payload)
    if artifacts:
        return artifacts
    source_artifacts = payload.get("source_artifacts")
    if isinstance(source_artifacts, list):
        return source_artifacts
    source_binding = _object(payload.get("source_binding"))
    if source_binding:
        items = []
        for name, value in source_binding.items():
            if isinstance(value, dict):
                item = {"type": name}
                item.update(value)
                items.append(item)
        return items
    source = _object(payload.get("source"))
    if source:
        return [{"type": key, "value": value} for key, value in source.items() if value is not None]
    authority_evidence = payload.get("authority_evidence")
    return authority_evidence if isinstance(authority_evidence, list) else []


def _compliance_controls(payload: dict[str, Any]) -> Any:
    for key in ("controls", "control_summary", "control_status_summary"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            return value
    return {}


def _compliance_record(entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    entry_type = str(entry.get("entry_type") or "")
    source_binding = _object(payload.get("source_binding"))
    source = _object(payload.get("source"))
    compliance_export = _object(source_binding.get("compliance_export"))
    eu_document = _object(source_binding.get("eu_ai_act_document"))
    proof_pack = _object(source_binding.get("proof_pack"))
    regulator_disclosure = _object(source_binding.get("regulator_disclosure"))
    eu_data_plane = _object(source_binding.get("eu_data_plane"))
    regions = _object(payload.get("regions"))
    residency = _object(payload.get("residency"))
    sovereignty = _object(payload.get("sovereignty"))
    audit = _object(payload.get("audit"))
    operation = _object(payload.get("operation"))
    summary = _object(payload.get("summary"))
    controls = _compliance_controls(payload)
    source_artifacts = _compliance_source_artifacts(payload)
    return {
        "artifact_id": _first_text(payload.get("dossier_id"), payload.get("attestation_id"), content_hash(payload)),
        "entry_id": entry.get("entry_id"),
        "entry_type": entry_type,
        "artifact_kind": COMPLIANCE_EVIDENCE_ARTIFACT_KINDS.get(entry_type, entry_type),
        "artifact_hash": _first_text(payload.get("dossier_hash"), payload.get("attestation_hash"), content_hash(payload)),
        "artifact_ref": _first_text(
            payload.get("dossier_ref"), residency.get("data_plane_ref"), source.get("byoc_data_plane_ref"),
            eu_data_plane.get("data_plane_ref"), payload.get("authority_ref"), eu_document.get("document_id"),
            source.get("eu_ai_act_document_id"), payload.get("attestation_id"), payload.get("dossier_id"),
        ),
        "status": _first_text(summary.get("status"), payload.get("status"), payload.get("mode")),
        "mode": payload.get("mode"),
        "environment": payload.get("environment"),
        "dossier_ref": payload.get("dossier_ref"),
        "authority_ref": payload.get("authority_ref"),
        "producer_ref": _first_text(payload.get("producer_ref"), operation.get("actor_ref")),
        "document_id": _first_text(eu_document.get("document_id"), source.get("eu_ai_act_document_id")),
        "pack_id": _first_text(compliance_export.get("pack_id"), proof_pack.get("pack_id")),
        "disclosure_id": regulator_disclosure.get("disclosure_id"),
        "data_plane_ref": _first_text(residency.get("data_plane_ref"), source.get("byoc_data_plane_ref"), eu_data_plane.get("data_plane_ref")),
        "tenant_id": _first_text(residency.get("tenant_id"), source.get("byoc_tenant_id")),
        "primary_region": regions.get("primary_region"),
        "kms_key_region": sovereignty.get("kms_key_region"),
        "audit_ref": _first_text(audit.get("audit_log_ref"), audit.get("access_log_ref"), audit.get("transfer_log_ref")),
        "required_requirement_count": int(summary.get("required_requirement_count") or 0),
        "covered_requirement_count": int(summary.get("covered_requirement_count") or 0),
        "missing_requirement_count": int(summary.get("missing_requirement_count") or 0),
        "authority_evidence_count": len(payload.get("authority_evidence") if isinstance(payload.get("authority_evidence"), list) else []),
        "source_artifact_count": len(source_artifacts),
        "control_count": len(controls) if isinstance(controls, (dict, list)) else 0,
        "observed_at": _first_text(payload.get("generated_at"), payload.get("attested_at"), entry.get("timestamp")),
        "source_artifacts": source_artifacts,
        "source_binding": source_binding or source,
        "controls": controls,
        "summary": summary,
    }

def _decode_json_object(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _bool_fields(item: dict[str, Any], *fields: str) -> dict[str, Any]:
    for field in fields:
        if item.get(field) is not None:
            item[field] = bool(item[field])
    return item


def _decode_json_array(value: Any) -> list[Any]:
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return decoded if isinstance(decoded, list) else []


def _is_authority_dossier_payload(entry: dict[str, Any], payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if not payload.get("dossier_id") or not payload.get("authority_ref"):
        return False
    if not isinstance(payload.get("summary"), dict):
        return False
    if not isinstance(payload.get("authority_evidence"), list):
        return False
    entry_type = str(entry.get("entry_type") or "")
    return "authority" in entry_type or str(payload.get("mode") or "").endswith("dossier")


def _authority_freshness_window_count(evidence_items: list[Any]) -> int:
    return sum(
        1
        for item in evidence_items
        if isinstance(item, dict) and item.get("issued_at") and item.get("expires_at")
    )


def _authority_freshness_counts(evidence_items: list[Any], reference: Any) -> dict[str, int]:
    counts = {"fresh": 0, "stale": 0, "missing": 0}
    try:
        reference_time = parse_rfc3339(str(reference))
    except (TypeError, ValueError):
        counts["missing"] = len(evidence_items)
        return counts
    for item in evidence_items:
        if not isinstance(item, dict) or not item.get("issued_at") or not item.get("expires_at"):
            counts["missing"] += 1
            continue
        try:
            issued_at = parse_rfc3339(str(item["issued_at"]))
            expires_at = parse_rfc3339(str(item["expires_at"]))
        except ValueError:
            counts["missing"] += 1
            continue
        if issued_at <= reference_time < expires_at:
            counts["fresh"] += 1
        else:
            counts["stale"] += 1
    return counts


def _decode_string_list_map(value: Any) -> dict[str, list[str]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    if not isinstance(value, dict):
        return {}
    result: dict[str, list[str]] = {}
    for key, raw_items in value.items():
        if not isinstance(raw_items, list):
            continue
        items = sorted(str(item) for item in raw_items if item)
        if items:
            result[str(key)] = items
    return {key: result[key] for key in sorted(result)}


def _count_items_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return {value: counts[value] for value in sorted(counts)}


def _roadmap_requirement_index(source_roadmap_audit: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(source_roadmap_audit, dict):
        return {}
    requirements = source_roadmap_audit.get("requirements")
    if not isinstance(requirements, list):
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for requirement in requirements:
        if not isinstance(requirement, dict):
            continue
        requirement_id = requirement.get("id")
        if requirement_id:
            indexed[str(requirement_id)] = requirement
    return indexed


def _authority_kind_rank(authority_kind: str) -> int:
    try:
        return AUTHORITY_KIND_ORDER.index(authority_kind) + 1
    except ValueError:
        return len(AUTHORITY_KIND_ORDER) + 1


def _authority_collection_priority(authority_kind: str) -> str:
    if authority_kind in {
        "ci-run",
        "kms-hsm",
        "tsa",
        "cloud-object-lock",
        "provider-api",
        "hosted-service",
        "identity-provider",
    }:
        return "deployment-operations"
    if authority_kind in {"customer", "regulator", "insurer", "standards-body"}:
        return "external-acceptance"
    return "other"


def _authority_gap_units(
    missing_authority_kinds_by_requirement: dict[str, list[str]],
    roadmap_requirements: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    for requirement_id in sorted(missing_authority_kinds_by_requirement):
        requirement = (roadmap_requirements or {}).get(requirement_id, {})
        for authority_kind in sorted(missing_authority_kinds_by_requirement[requirement_id]):
            unit_id = content_hash({"authority_kind": authority_kind, "requirement_id": requirement_id})
            unit_ref = f"{requirement_id}:{authority_kind}"
            units.append(
                {
                    "unit_id": unit_id,
                    "unit_ref": unit_ref,
                    "task_id": content_hash(
                        {"task_kind": "external-authority-evidence", "unit_id": unit_id, "unit_ref": unit_ref}
                    ),
                    "task_ref": f"external-evidence:{unit_ref}",
                    "requirement_id": requirement_id,
                    "requirement_title": requirement.get("title"),
                    "requirement_phase": requirement.get("phase"),
                    "requirement_priority": requirement.get("priority"),
                    "requirement_status": requirement.get("status"),
                    "roadmap_ref": requirement.get("roadmap_ref"),
                    "authority_kind": authority_kind,
                    "authority_kind_rank": _authority_kind_rank(authority_kind),
                    "collection_priority": _authority_collection_priority(authority_kind),
                    "owner_hint": AUTHORITY_KIND_OWNER_HINTS.get(
                        authority_kind,
                        AUTHORITY_KIND_OWNER_HINTS["other"],
                    ),
                    "suggested_evidence_sources": AUTHORITY_KIND_EVIDENCE_HINTS.get(
                        authority_kind,
                        AUTHORITY_KIND_EVIDENCE_HINTS["other"],
                    ),
                }
            )
    return units


def _external_authority_gap_summary(units: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "missing_authority_unit_count": len(units),
        "gap_count_by_authority_kind": _count_items_by(units, "authority_kind"),
        "gap_count_by_collection_priority": _count_items_by(units, "collection_priority"),
        "gap_count_by_requirement": _count_items_by(units, "requirement_id"),
        "gap_count_by_requirement_phase": _count_items_by(units, "requirement_phase"),
        "gap_count_by_requirement_priority": _count_items_by(units, "requirement_priority"),
        "missing_authority_units": units,
    }


def _sqlite_nolock_uri(path: Path) -> str:
    posix_path = path.as_posix()
    if posix_path.startswith("//") and not posix_path.startswith("////"):
        posix_path = "//" + posix_path
    return "file:" + posix_path + "?nolock=1"


class ControlPlane:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.uses_nolock = False
        self.conn = self._connect_normal()
        try:
            self.initialize()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                self.conn.close()
                raise
            self.conn.close()
            self.uses_nolock = True
            self.conn = self._connect_nolock()
            self.initialize()
        except Exception:
            self.conn.close()
            raise

    def _configure(self, conn: sqlite3.Connection) -> sqlite3.Connection:
        conn.execute("PRAGMA busy_timeout = 2000")
        conn.row_factory = sqlite3.Row
        return conn

    def _connect_normal(self) -> sqlite3.Connection:
        return self._configure(sqlite3.connect(self.path, timeout=2))

    def _connect_nolock(self) -> sqlite3.Connection:
        return self._configure(sqlite3.connect(_sqlite_nolock_uri(self.path), timeout=2, uri=True))

    def close(self) -> None:
        self.conn.close()

    def initialize(self) -> None:
        self.conn.executescript(
            """
            PRAGMA journal_mode = DELETE;
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contracts (
                contract_hash TEXT PRIMARY KEY,
                contract_id TEXT NOT NULL,
                version TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                registered_entry_id TEXT,
                body_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agents (
                agent_hash TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                owner TEXT,
                risk_class TEXT,
                governed INTEGER NOT NULL,
                source TEXT,
                observed_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agent_delegations (
                entry_id TEXT PRIMARY KEY,
                delegation_hash TEXT NOT NULL,
                contract_hash TEXT,
                parent_agent_name TEXT,
                parent_agent_version TEXT,
                parent_agent_ref TEXT,
                child_agent_name TEXT,
                child_agent_version TEXT,
                child_agent_ref TEXT,
                reason TEXT,
                scope_json TEXT NOT NULL,
                delegated_at TEXT,
                delegation_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agent_delegation_graphs (
                delegation_graph_id TEXT PRIMARY KEY,
                entry_id TEXT,
                delegation_graph_hash TEXT,
                contract_hash TEXT,
                contract_hash_filter TEXT,
                root_agent_filter TEXT,
                source_chain_tenant_id TEXT,
                source_chain_entry_count INTEGER NOT NULL,
                node_count INTEGER NOT NULL,
                edge_count INTEGER NOT NULL,
                max_depth INTEGER,
                cycle_detected INTEGER NOT NULL,
                root_agents_json TEXT NOT NULL,
                leaf_agents_json TEXT NOT NULL,
                missing_inventory_json TEXT NOT NULL,
                contract_hashes_json TEXT NOT NULL,
                agent_refs_json TEXT NOT NULL,
                node_root TEXT,
                edge_root TEXT,
                filters_json TEXT NOT NULL,
                source_chain_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chain_entries (
                entry_id TEXT PRIMARY KEY,
                idx INTEGER NOT NULL,
                tenant_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                contract_hash TEXT,
                payload_hash TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS proof_packs (
                pack_id TEXT PRIMARY KEY,
                spec_version TEXT NOT NULL,
                contract_hash TEXT NOT NULL,
                contract_id TEXT,
                agent_name TEXT,
                agent_version TEXT,
                outcome TEXT,
                issued_at TEXT,
                path TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ingest_events (
                entry_id TEXT PRIMARY KEY,
                event_hash TEXT NOT NULL,
                contract_hash TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                event_name TEXT NOT NULL,
                agent_name TEXT,
                agent_version TEXT,
                risk_class TEXT,
                schema_url TEXT,
                observed_at TEXT,
                attributes_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mcp_tool_calls (
                entry_id TEXT PRIMARY KEY,
                session_id TEXT,
                request_id TEXT,
                tool_name TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                risk_class TEXT,
                request_hash TEXT,
                response_hash TEXT,
                tool_call_hash TEXT,
                transcript_sequence INTEGER NOT NULL,
                transcript_call_count INTEGER NOT NULL,
                previous_transcript_node_hash TEXT,
                transcript_node_hash TEXT,
                transcript_root TEXT,
                observed_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mcp_proxy_captures (
                capture_id TEXT PRIMARY KEY,
                entry_id TEXT,
                proxy_ref TEXT,
                upstream_ref TEXT,
                session_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                risk_class TEXT,
                event_count INTEGER NOT NULL,
                tool_call_count INTEGER NOT NULL,
                event_chain_root TEXT,
                transcript_root TEXT,
                proxy_events_artifact_json TEXT NOT NULL,
                event_hashes_json TEXT NOT NULL,
                tool_call_hashes_json TEXT NOT NULL,
                captured_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS self_serve_onboarding_receipts (
                receipt_id TEXT PRIMARY KEY,
                entry_id TEXT,
                receipt_hash TEXT NOT NULL,
                onboarding_ref TEXT,
                tenant_ref TEXT,
                agent_ref TEXT,
                requester_ref TEXT,
                environment TEXT,
                sdk_scope TEXT,
                gateway_mode TEXT,
                source_artifact_count INTEGER NOT NULL,
                quickstart_step_count INTEGER NOT NULL,
                quickstart_replay_count INTEGER NOT NULL,
                control_passed_count INTEGER NOT NULL,
                control_not_applicable_count INTEGER NOT NULL,
                control_failed_count INTEGER NOT NULL,
                generated_at TEXT,
                control_summary_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS framework_adapter_matrices (
                matrix_id TEXT PRIMARY KEY,
                entry_id TEXT,
                matrix_hash TEXT NOT NULL,
                matrix_ref TEXT,
                adapter_schema_url TEXT,
                adapter_package_version TEXT,
                row_count INTEGER NOT NULL,
                framework_count INTEGER NOT NULL,
                production_certified_count INTEGER NOT NULL,
                total_fixture_events INTEGER NOT NULL,
                summary_json TEXT NOT NULL,
                frameworks_json TEXT NOT NULL,
                compatibility_hashes_json TEXT NOT NULL,
                issued_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS framework_hook_releases (
                release_id TEXT PRIMARY KEY,
                entry_id TEXT,
                release_hash TEXT NOT NULL,
                release_ref TEXT,
                matrix_id TEXT,
                matrix_hash TEXT,
                row_count INTEGER NOT NULL,
                framework_count INTEGER NOT NULL,
                production_certified_count INTEGER NOT NULL,
                adapter_matrix_json TEXT NOT NULL,
                frameworks_json TEXT NOT NULL,
                hook_release_hashes_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                released_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS framework_hook_operations (
                operation_id TEXT PRIMARY KEY,
                entry_id TEXT,
                operation_hash TEXT NOT NULL,
                mode TEXT,
                environment TEXT,
                operation_ref TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                risk_class TEXT,
                framework TEXT,
                runtime_package TEXT,
                runtime_version TEXT,
                hook_package TEXT,
                hook_version TEXT,
                collector_hook_ref TEXT,
                hook_release_hash TEXT,
                source_trace_id TEXT,
                trace_id TEXT,
                event_count INTEGER NOT NULL,
                event_root TEXT,
                runtime_json TEXT NOT NULL,
                hook_json TEXT NOT NULL,
                release_binding_json TEXT NOT NULL,
                trace_json TEXT NOT NULL,
                collector_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                captured_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS framework_adapter_authority_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                dossier_hash TEXT NOT NULL,
                dossier_ref TEXT,
                mode TEXT,
                environment TEXT,
                authority_ref TEXT,
                producer_ref TEXT,
                matrix_id TEXT,
                matrix_hash TEXT,
                release_id TEXT,
                release_hash TEXT,
                production_claimed INTEGER NOT NULL,
                production_ready INTEGER NOT NULL,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                authority_evidence_count INTEGER NOT NULL,
                fresh_evidence_count INTEGER NOT NULL,
                stale_evidence_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                source_binding_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                authority_evidence_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS byoc_operator_attestations (
                attestation_id TEXT PRIMARY KEY,
                entry_id TEXT,
                attestation_hash TEXT NOT NULL,
                mode TEXT,
                environment TEXT,
                deployment_manifest_id TEXT,
                deployment_manifest_hash TEXT,
                deployment_name TEXT,
                deployment_mode TEXT,
                deployment_artifact_type TEXT,
                operator_ref TEXT,
                operator_version TEXT,
                operator_image TEXT,
                operator_image_digest TEXT,
                namespace TEXT,
                tenant_id TEXT,
                customer_account_ref TEXT,
                data_plane_ref TEXT,
                control_plane_ref TEXT,
                keyring_ref TEXT,
                object_lock_provider TEXT,
                object_lock_bucket_ref TEXT,
                object_lock_region TEXT,
                object_lock_enabled INTEGER NOT NULL,
                versioning_enabled INTEGER NOT NULL,
                legal_hold_required INTEGER NOT NULL,
                legal_hold_active INTEGER NOT NULL,
                backup_policy_ref TEXT,
                restore_test_ref TEXT,
                private_endpoint INTEGER NOT NULL,
                audit_log_ref TEXT,
                audit_log_root TEXT,
                source_artifact_count INTEGER NOT NULL,
                control_summary_json TEXT NOT NULL,
                attested_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS byoc_authority_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                dossier_hash TEXT NOT NULL,
                mode TEXT,
                environment TEXT,
                dossier_ref TEXT,
                authority_ref TEXT,
                producer_ref TEXT,
                production_claimed INTEGER NOT NULL,
                production_ready INTEGER NOT NULL,
                deployment_manifest_id TEXT,
                deployment_manifest_hash TEXT,
                deployment_environment TEXT,
                byoc_operator_attestation_id TEXT,
                operator_ref TEXT,
                operator_image_digest TEXT,
                namespace TEXT,
                object_lock_bucket_ref TEXT,
                customer_account_ref TEXT,
                data_plane_ref TEXT,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                authority_evidence_count INTEGER NOT NULL,
                fresh_evidence_count INTEGER NOT NULL,
                stale_evidence_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                authority_artifact_count INTEGER NOT NULL,
                authority_artifact_requirement_count INTEGER NOT NULL,
                source_binding_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                artifact_summary_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                authority_evidence_json TEXT NOT NULL,
                authority_artifacts_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vendor_identity_receipts (
                receipt_id TEXT PRIMARY KEY,
                entry_id TEXT,
                receipt_hash TEXT NOT NULL,
                vendor_name TEXT,
                legal_name TEXT,
                subject_ref TEXT,
                domain TEXT,
                identity_provider TEXT,
                identity_id TEXT,
                proof_pack_count INTEGER NOT NULL,
                trust_network_manifest_id TEXT,
                trust_network_manifest_hash TEXT,
                issued_at TEXT,
                expires_at TEXT,
                vendor_json TEXT NOT NULL,
                proof_packs_json TEXT NOT NULL,
                trust_network_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_provider_attestations (
                attestation_id TEXT PRIMARY KEY,
                entry_id TEXT,
                attestation_hash TEXT NOT NULL,
                provider TEXT,
                authentication_method TEXT,
                tenant_ref TEXT,
                observed_at TEXT,
                source TEXT,
                subject_ref TEXT,
                identity_provider TEXT,
                identity_id TEXT,
                identity_record_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                vendor_receipt_id TEXT,
                vendor_receipt_hash TEXT,
                source_artifact_count INTEGER NOT NULL,
                issued_at TEXT,
                authentication_json TEXT NOT NULL,
                subject_json TEXT NOT NULL,
                vendor_binding_json TEXT NOT NULL,
                source_payload_json TEXT NOT NULL,
                source_artifacts_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_provider_sessions (
                session_id TEXT PRIMARY KEY,
                entry_id TEXT,
                session_hash TEXT NOT NULL,
                provider TEXT,
                mode TEXT,
                environment TEXT,
                attestation_id TEXT,
                attestation_hash TEXT,
                session_ref TEXT,
                event_kind TEXT,
                provider_event_id TEXT,
                identity_provider TEXT,
                identity_id TEXT,
                identity_record_hash TEXT,
                decision TEXT,
                risk_level TEXT,
                response_status INTEGER,
                success INTEGER NOT NULL,
                session_log_ref TEXT,
                session_log_root TEXT,
                audit_log_ref TEXT,
                audit_log_root TEXT,
                recorded_at TEXT,
                identity_attestation_json TEXT NOT NULL,
                session_json TEXT NOT NULL,
                authentication_context_json TEXT NOT NULL,
                provider_evidence_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_provider_lifecycle_operations (
                operation_id TEXT PRIMARY KEY,
                entry_id TEXT,
                operation_hash TEXT NOT NULL,
                provider TEXT,
                mode TEXT,
                environment TEXT,
                attestation_id TEXT,
                attestation_hash TEXT,
                source_session_id TEXT,
                source_session_hash TEXT,
                operation_kind TEXT,
                operation_ref TEXT,
                provider_operation_id TEXT,
                identity_provider TEXT,
                identity_id TEXT,
                identity_record_hash TEXT,
                target_state TEXT,
                outcome TEXT,
                success INTEGER NOT NULL,
                response_status INTEGER,
                system_log_ref TEXT,
                system_log_root TEXT,
                audit_log_ref TEXT,
                audit_log_root TEXT,
                recorded_at TEXT,
                identity_attestation_json TEXT NOT NULL,
                source_session_json TEXT NOT NULL,
                operation_json TEXT NOT NULL,
                change_refs_json TEXT NOT NULL,
                provider_evidence_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_provider_lifecycle_workers (
                worker_operation_id TEXT PRIMARY KEY,
                entry_id TEXT,
                worker_operation_hash TEXT NOT NULL,
                provider TEXT,
                mode TEXT,
                environment TEXT,
                source_operation_id TEXT,
                source_operation_hash TEXT,
                identity_id TEXT,
                identity_record_hash TEXT,
                operation_kind TEXT,
                worker_ref TEXT,
                run_ref TEXT,
                worker_success INTEGER NOT NULL,
                schedule_ref TEXT,
                queue_ref TEXT,
                destination_ref TEXT,
                response_status INTEGER,
                propagation_log_ref TEXT,
                propagation_log_root TEXT,
                audit_log_ref TEXT,
                audit_log_root TEXT,
                recorded_at TEXT,
                source_operation_json TEXT NOT NULL,
                worker_json TEXT NOT NULL,
                scheduler_json TEXT NOT NULL,
                propagation_json TEXT NOT NULL,
                observability_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_provider_authority_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                dossier_hash TEXT NOT NULL,
                mode TEXT,
                environment TEXT,
                dossier_ref TEXT,
                authority_ref TEXT,
                producer_ref TEXT,
                production_claimed INTEGER NOT NULL,
                production_ready INTEGER NOT NULL,
                worker_operation_id TEXT,
                worker_receipt_hash TEXT,
                provider TEXT,
                identity_id TEXT,
                identity_record_hash TEXT,
                operation_kind TEXT,
                worker_ref TEXT,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                authority_evidence_count INTEGER NOT NULL,
                fresh_evidence_count INTEGER NOT NULL,
                stale_evidence_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                worker_binding_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                authority_evidence_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS supervised_access_receipts (
                receipt_id TEXT PRIMARY KEY,
                entry_id TEXT,
                receipt_hash TEXT NOT NULL,
                session_id TEXT,
                audience_type TEXT,
                audience_purpose TEXT,
                reviewer_subject_ref TEXT,
                reviewer_organization TEXT,
                reviewer_role TEXT,
                artifact_count INTEGER NOT NULL,
                issued_at TEXT,
                expires_at TEXT,
                artifact_refs_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS regulator_acceptances (
                acceptance_id TEXT PRIMARY KEY,
                entry_id TEXT,
                acceptance_hash TEXT NOT NULL,
                regulator_name TEXT,
                authority_ref TEXT,
                reviewer_ref TEXT,
                outcome TEXT,
                accepted INTEGER NOT NULL,
                examination_ref TEXT,
                purpose TEXT,
                framework TEXT,
                source_ref_count INTEGER NOT NULL,
                source_refs_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL,
                issued_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS review_portal_service_attestations (
                attestation_id TEXT PRIMARY KEY,
                entry_id TEXT,
                attestation_hash TEXT NOT NULL,
                mode TEXT,
                environment TEXT,
                service_ref TEXT,
                service_version TEXT,
                portal_kind TEXT,
                endpoint_url TEXT,
                service_image_digest TEXT,
                frontend_bundle_ref TEXT,
                frontend_bundle_hash TEXT,
                api_ref TEXT,
                supervised_access_receipt_id TEXT,
                session_id TEXT,
                audience_type TEXT,
                reviewer_subject_ref TEXT,
                reviewer_organization TEXT,
                reviewer_role TEXT,
                artifact_count INTEGER NOT NULL,
                source_count INTEGER NOT NULL,
                control_summary_json TEXT NOT NULL,
                attested_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS review_portal_authority_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                dossier_hash TEXT NOT NULL,
                mode TEXT,
                environment TEXT,
                dossier_ref TEXT,
                authority_ref TEXT,
                producer_ref TEXT,
                production_claimed INTEGER NOT NULL,
                production_ready INTEGER NOT NULL,
                service_attestation_id TEXT,
                service_ref TEXT,
                portal_kind TEXT,
                audience_type TEXT,
                reviewer_subject_ref TEXT,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                authority_evidence_count INTEGER NOT NULL,
                fresh_evidence_count INTEGER NOT NULL,
                stale_evidence_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                service_attestation_binding_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                authority_evidence_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS standards_body_evidence (
                artifact_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                artifact_ref TEXT,
                status TEXT,
                standards_body_name TEXT,
                program_ref TEXT,
                target_track TEXT,
                actor_ref TEXT,
                source_artifact_count INTEGER NOT NULL,
                control_count INTEGER NOT NULL,
                observed_at TEXT,
                source_artifacts_json TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auditor_ecosystem_evidence (
                artifact_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                artifact_ref TEXT,
                status TEXT,
                program_ref TEXT,
                auditor_ref TEXT,
                auditor_organization TEXT,
                authority_ref TEXT,
                actor_ref TEXT,
                source_artifact_count INTEGER NOT NULL,
                control_count INTEGER NOT NULL,
                observed_at TEXT,
                source_artifacts_json TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trust_network_evidence (
                artifact_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                artifact_ref TEXT,
                status TEXT,
                mode TEXT,
                environment TEXT,
                party_ref TEXT,
                service_ref TEXT,
                registry_ref TEXT,
                marketplace_ref TEXT,
                source_artifact_count INTEGER NOT NULL,
                control_count INTEGER NOT NULL,
                observed_at TEXT,
                source_artifacts_json TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provider_delivery_evidence (
                artifact_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                artifact_ref TEXT,
                status TEXT,
                mode TEXT,
                environment TEXT,
                provider TEXT,
                service_ref TEXT,
                worker_ref TEXT,
                bundle_ref TEXT,
                authority_ref TEXT,
                pack_id TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                target_ref TEXT,
                provider_endpoint TEXT,
                response_status INTEGER,
                success INTEGER,
                source_artifact_count INTEGER NOT NULL,
                control_count INTEGER NOT NULL,
                observed_at TEXT,
                source_artifacts_json TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provider_operations_evidence (
                artifact_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                artifact_ref TEXT,
                status TEXT,
                mode TEXT,
                environment TEXT,
                provider TEXT,
                operation_kind TEXT,
                service_ref TEXT,
                installation_ref TEXT,
                webhook_ref TEXT,
                callback_ref TEXT,
                audit_ref TEXT,
                credential_ref TEXT,
                authority_ref TEXT,
                target_ref TEXT,
                source_artifact_count INTEGER NOT NULL,
                control_count INTEGER NOT NULL,
                observed_at TEXT,
                source_artifacts_json TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_backend_evidence (
                artifact_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                artifact_ref TEXT,
                status TEXT,
                mode TEXT,
                environment TEXT,
                backend_ref TEXT,
                engine TEXT,
                policy_ref TEXT,
                action_ref TEXT,
                decision_ref TEXT,
                service_ref TEXT,
                worker_ref TEXT,
                provider_ref TEXT,
                bundle_ref TEXT,
                authority_ref TEXT,
                credential_ref TEXT,
                audit_ref TEXT,
                response_status INTEGER,
                allowed INTEGER,
                source_artifact_count INTEGER NOT NULL,
                control_count INTEGER NOT NULL,
                observed_at TEXT,
                source_artifacts_json TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS eval_runs (
                entry_id TEXT PRIMARY KEY,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                results_hash TEXT,
                evaluated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS gate_decisions (
                entry_id TEXT PRIMARY KEY,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                outcome TEXT,
                passed INTEGER NOT NULL,
                eval_entry_id TEXT,
                contract_entry_id TEXT,
                results_hash TEXT,
                check_count INTEGER NOT NULL,
                failed_check_count INTEGER NOT NULL,
                holdout_passed INTEGER,
                approvals_passed INTEGER,
                evaluated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS human_approvals (
                entry_id TEXT PRIMARY KEY,
                approval_hash TEXT NOT NULL,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                role TEXT,
                approver TEXT,
                source TEXT,
                external_ref TEXT,
                approved_at TEXT,
                metadata_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS promotion_demotions (
                entry_id TEXT PRIMARY KEY,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                from_environment TEXT,
                to_environment TEXT,
                reason TEXT,
                triggering_entry_id TEXT,
                trigger_json TEXT NOT NULL,
                decided_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS promotion_rollbacks (
                entry_id TEXT PRIMARY KEY,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                target_agent_version TEXT,
                reason TEXT,
                triggering_entry_id TEXT,
                decided_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS soak_demotion_receipts (
                receipt_id TEXT PRIMARY KEY,
                entry_id TEXT,
                receipt_hash TEXT NOT NULL,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                soak_report_entry_id TEXT,
                demotion_entry_id TEXT,
                source_json TEXT NOT NULL,
                violation_count INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                attested_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS promotion_statuses (
                receipt_id TEXT PRIMARY KEY,
                entry_id TEXT,
                provider TEXT,
                pack_id TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                gate_outcome TEXT,
                passed INTEGER NOT NULL,
                provider_status_kind TEXT,
                provider_status_success INTEGER,
                target_ref_json TEXT NOT NULL,
                violation_count INTEGER NOT NULL,
                attested_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_attestations (
                entry_id TEXT PRIMARY KEY,
                contract_id TEXT,
                contract_hash TEXT,
                action_hash TEXT,
                action_id TEXT,
                action_type TEXT,
                risk_class TEXT,
                passed INTEGER NOT NULL,
                outcome TEXT,
                check_count INTEGER NOT NULL,
                failed_check_count INTEGER NOT NULL,
                attested_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_decisions (
                entry_id TEXT PRIMARY KEY,
                policy_pack_id TEXT,
                policy_pack_version TEXT,
                policy_pack_hash TEXT,
                contract_hash TEXT,
                action_hash TEXT,
                passed INTEGER NOT NULL,
                outcome TEXT,
                matched_rule_count INTEGER NOT NULL,
                check_count INTEGER NOT NULL,
                failed_check_count INTEGER NOT NULL,
                evaluated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_engine_receipts (
                receipt_id TEXT PRIMARY KEY,
                entry_id TEXT,
                engine_name TEXT,
                engine_mode TEXT,
                policy_pack_id TEXT,
                policy_pack_version TEXT,
                policy_pack_hash TEXT,
                action_hash TEXT,
                action_id TEXT,
                action_type TEXT,
                risk_class TEXT,
                pack_id TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                decision_entry_id TEXT,
                decision_outcome TEXT,
                decision_passed INTEGER,
                evaluated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                entry_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                severity TEXT,
                summary TEXT,
                detected_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS roadmap_audits (
                audit_id TEXT PRIMARY KEY,
                entry_id TEXT,
                audit_hash TEXT NOT NULL,
                completion_position TEXT,
                requirement_count INTEGER NOT NULL,
                implemented_local_count INTEGER NOT NULL,
                reference_attested_count INTEGER NOT NULL,
                missing_local_evidence_count INTEGER NOT NULL,
                deferred_external_count INTEGER NOT NULL,
                source_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS external_evidence_collection_runs (
                run_id TEXT PRIMARY KEY,
                entry_id TEXT,
                run_hash TEXT NOT NULL,
                source_map_hash TEXT,
                manifest_id TEXT,
                manifest_ref TEXT,
                manifest_hash TEXT,
                audit_id TEXT,
                audit_hash TEXT,
                require_fresh INTEGER NOT NULL,
                require_live_source_uris INTEGER NOT NULL,
                require_source_snapshot_artifacts INTEGER NOT NULL,
                require_fresh_source_snapshot_artifacts INTEGER NOT NULL,
                collected_count INTEGER NOT NULL,
                task_count INTEGER NOT NULL,
                collected_tasks_json TEXT NOT NULL,
                snapshot_ids_json TEXT NOT NULL,
                intake_ids_json TEXT NOT NULL,
                source_plan_json TEXT NOT NULL,
                source_manifest_json TEXT NOT NULL,
                source_roadmap_audit_json TEXT NOT NULL,
                freshness_checked_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS external_evidence_manifests (
                manifest_id TEXT PRIMARY KEY,
                entry_id TEXT,
                manifest_ref TEXT,
                manifest_hash TEXT NOT NULL,
                status TEXT,
                require_complete INTEGER NOT NULL,
                require_fresh INTEGER NOT NULL,
                require_live_source_uris INTEGER NOT NULL,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                required_authority_kind_count INTEGER NOT NULL,
                covered_authority_kind_count INTEGER NOT NULL,
                missing_authority_kind_count INTEGER NOT NULL,
                evidence_count INTEGER NOT NULL,
                fresh_evidence_count INTEGER NOT NULL,
                stale_evidence_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                source_roadmap_audit_json TEXT NOT NULL,
                missing_requirement_ids_json TEXT NOT NULL,
                freshness_checked_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS authority_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                dossier_hash TEXT NOT NULL,
                dossier_ref TEXT,
                mode TEXT,
                environment TEXT,
                authority_ref TEXT,
                producer_ref TEXT,
                production_claimed INTEGER NOT NULL,
                production_ready INTEGER NOT NULL,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                authority_evidence_count INTEGER NOT NULL,
                freshness_window_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                control_summary_json TEXT NOT NULL,
                covered_requirement_ids_json TEXT NOT NULL,
                missing_requirement_ids_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS phase_scoreboards (
                scoreboard_id TEXT PRIMARY KEY,
                entry_id TEXT,
                scoreboard_hash TEXT NOT NULL,
                scoreboard_ref TEXT,
                mode TEXT,
                environment TEXT,
                milestone_count INTEGER NOT NULL,
                phase_counts_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS design_partner_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                dossier_hash TEXT NOT NULL,
                dossier_ref TEXT,
                mode TEXT,
                environment TEXT,
                partner_count INTEGER NOT NULL,
                signed_partner_count INTEGER NOT NULL,
                signed_pilot_value_usd INTEGER NOT NULL,
                external_scrutiny_survival_count INTEGER NOT NULL,
                source_artifact_count INTEGER NOT NULL,
                control_summary_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS own_compliance_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                dossier_hash TEXT NOT NULL,
                dossier_ref TEXT,
                scope_ref TEXT,
                mode TEXT,
                environment TEXT,
                evidence_count INTEGER NOT NULL,
                required_certification_evidence_count INTEGER NOT NULL,
                source_artifact_count INTEGER NOT NULL,
                control_summary_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS compliance_evidence (
                artifact_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                artifact_ref TEXT,
                status TEXT,
                mode TEXT,
                environment TEXT,
                dossier_ref TEXT,
                authority_ref TEXT,
                producer_ref TEXT,
                document_id TEXT,
                pack_id TEXT,
                disclosure_id TEXT,
                data_plane_ref TEXT,
                tenant_id TEXT,
                primary_region TEXT,
                kms_key_region TEXT,
                audit_ref TEXT,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                authority_evidence_count INTEGER NOT NULL,
                source_artifact_count INTEGER NOT NULL,
                control_count INTEGER NOT NULL,
                observed_at TEXT,
                source_artifacts_json TEXT NOT NULL,
                source_binding_json TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS product_scope_decisions (
                decision_id TEXT PRIMARY KEY,
                entry_id TEXT,
                decision_hash TEXT NOT NULL,
                decision_ref TEXT,
                decision TEXT,
                feature_title TEXT,
                proof_impacts_json TEXT NOT NULL,
                anti_focus_flags_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vertical_packs (
                pack_id TEXT PRIMARY KEY,
                entry_id TEXT,
                pack_hash TEXT NOT NULL,
                pack_ref TEXT,
                vertical TEXT,
                title TEXT,
                producer_ref TEXT,
                reviewer_ref TEXT,
                environment TEXT,
                risk_classes_json TEXT NOT NULL,
                frameworks_json TEXT NOT NULL,
                source_artifact_count INTEGER NOT NULL,
                external_requirement_count INTEGER NOT NULL,
                control_summary_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reliability_reports (
                report_id TEXT PRIMARY KEY,
                entry_id TEXT,
                report_hash TEXT NOT NULL,
                report_ref TEXT,
                mode TEXT,
                reporting_period_json TEXT NOT NULL,
                cohort_count INTEGER NOT NULL,
                source_product_count INTEGER NOT NULL,
                incident_rate_per_100k_actions INTEGER,
                gate_pass_rate_bps INTEGER,
                control_summary_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS underwriting_quotes (
                quote_id TEXT PRIMARY KEY,
                entry_id TEXT,
                quote_hash TEXT NOT NULL,
                underwriter_name TEXT,
                underwriter_mode TEXT,
                product TEXT,
                quote_ref TEXT,
                status TEXT,
                currency TEXT,
                coverage_limit_usd REAL,
                base_premium_usd REAL,
                discount_percent REAL,
                quoted_premium_usd REAL,
                term_start TEXT,
                term_end TEXT,
                consent_id TEXT,
                consent_active INTEGER NOT NULL,
                pack_id TEXT,
                contract_id TEXT,
                chain_root TEXT,
                risk_score REAL,
                risk_tier TEXT,
                gate_outcome TEXT,
                issued_at TEXT,
                applicant_risk_json TEXT NOT NULL,
                quote_json TEXT NOT NULL,
                risk_evidence_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS insurer_partner_authority_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                dossier_hash TEXT NOT NULL,
                mode TEXT,
                environment TEXT,
                dossier_ref TEXT,
                authority_ref TEXT,
                producer_ref TEXT,
                production_claimed INTEGER NOT NULL,
                production_ready INTEGER NOT NULL,
                service_attestation_id TEXT,
                service_attestation_hash TEXT,
                service_ref TEXT,
                partner_api_endpoint TEXT,
                underwriter TEXT,
                quote_id TEXT,
                quote_ref TEXT,
                telemetry_hash TEXT,
                consent_id TEXT,
                risk_tier TEXT,
                worker_receipt_count INTEGER NOT NULL,
                worker_bundle_count INTEGER NOT NULL,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                authority_evidence_count INTEGER NOT NULL,
                fresh_evidence_count INTEGER NOT NULL,
                stale_evidence_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                service_binding_json TEXT NOT NULL,
                worker_receipt_bindings_json TEXT NOT NULL,
                worker_bundle_bindings_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                authority_evidence_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS temporal_holdout_manifests (
                manifest_id TEXT PRIMARY KEY,
                entry_id TEXT,
                manifest_hash TEXT NOT NULL,
                run_id TEXT,
                dataset_id TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                candidate_version TEXT,
                record_count INTEGER NOT NULL,
                violation_count INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                records_root TEXT,
                earliest_record_timestamp TEXT,
                latest_record_timestamp TEXT,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shadow_replays (
                entry_id TEXT PRIMARY KEY,
                run_id TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                candidate_version TEXT,
                replay_hash TEXT,
                records_checked INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                outcome TEXT,
                holdout_passed INTEGER,
                holdout_error_count INTEGER NOT NULL,
                check_count INTEGER NOT NULL,
                failed_check_count INTEGER NOT NULL,
                temporal_holdout_manifest_id TEXT,
                temporal_holdout_manifest_hash TEXT,
                evaluated_at TEXT,
                metrics_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS soak_reports (
                entry_id TEXT PRIMARY KEY,
                report_id TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                candidate_version TEXT,
                soak_hash TEXT,
                window_count INTEGER NOT NULL,
                incident_count INTEGER NOT NULL,
                drift_alarm_count INTEGER NOT NULL,
                blocking_drift_alarm_count INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                outcome TEXT,
                check_count INTEGER NOT NULL,
                failed_check_count INTEGER NOT NULL,
                evaluated_at TEXT,
                metrics_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_holdout_exports (
                export_id TEXT PRIMARY KEY,
                entry_id TEXT,
                export_hash TEXT NOT NULL,
                export_ref TEXT,
                source_ref TEXT,
                exporter_ref TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                candidate_version TEXT,
                record_count INTEGER NOT NULL,
                violation_count INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                extraction_window_json TEXT NOT NULL,
                records_root TEXT,
                earliest_record_timestamp TEXT,
                latest_record_timestamp TEXT,
                produced_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_completeness_receipts (
                completeness_id TEXT PRIMARY KEY,
                entry_id TEXT,
                completeness_hash TEXT NOT NULL,
                mode TEXT,
                authority_ref TEXT,
                export_id TEXT,
                export_hash TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                candidate_version TEXT,
                record_count INTEGER NOT NULL,
                violation_count INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                source_completeness_json TEXT NOT NULL,
                provider_exchange_json TEXT NOT NULL,
                produced_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anchors (
                anchor_id TEXT PRIMARY KEY,
                entry_id TEXT,
                tree_root TEXT NOT NULL,
                tree_size INTEGER NOT NULL,
                tenant_id TEXT,
                published_at TEXT,
                body_json TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("schema_version", SCHEMA_VERSION),
        )
        self.conn.commit()

    def clear_index(self) -> dict[str, int]:
        deleted: dict[str, int] = {}
        with self.conn:
            for table in INDEX_TABLES:
                deleted[table] = int(
                    self.conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
                )
                self.conn.execute(f"DELETE FROM {table}")
        return deleted

    def rebuild_from_chain(self, chain: EvidenceChain) -> dict[str, int]:
        self.clear_index()
        return self.index_chain(chain)

    def index_chain(self, chain: EvidenceChain) -> dict[str, int]:
        counts = {
            "chain_entries": 0,
            "contracts": 0,
            "agents": 0,
            "agent_delegations": 0,
            "agent_delegation_graphs": 0,
            "anchors": 0,
            "byoc_operator_attestations": 0,
            "byoc_authority_dossiers": 0,
            "vendor_identity_receipts": 0,
            "identity_provider_attestations": 0,
            "identity_provider_sessions": 0,
            "identity_provider_lifecycle_operations": 0,
            "identity_provider_lifecycle_workers": 0,
            "identity_provider_authority_dossiers": 0,
            "ingest_events": 0,
            "mcp_tool_calls": 0,
            "mcp_proxy_captures": 0,
            "self_serve_onboarding_receipts": 0,
            "framework_adapter_matrices": 0,
            "framework_hook_releases": 0,
            "framework_hook_operations": 0,
            "framework_adapter_authority_dossiers": 0,
            "supervised_access_receipts": 0,
            "regulator_acceptances": 0,
            "review_portal_service_attestations": 0,
            "review_portal_authority_dossiers": 0,
            "standards_body_evidence": 0,
            "auditor_ecosystem_evidence": 0,
            "trust_network_evidence": 0,
            "provider_delivery_evidence": 0,
            "provider_operations_evidence": 0,
            "compliance_evidence": 0,
            "eval_runs": 0,
            "gate_decisions": 0,
            "human_approvals": 0,
            "promotion_demotions": 0,
            "promotion_rollbacks": 0,
            "soak_demotion_receipts": 0,
            "promotion_statuses": 0,
            "runtime_attestations": 0,
            "policy_decisions": 0,
            "policy_engine_receipts": 0,
            "policy_backend_evidence": 0,
            "incidents": 0,
            "roadmap_audits": 0,
            "external_evidence_collection_runs": 0,
            "external_evidence_manifests": 0,
            "authority_dossiers": 0,
            "phase_scoreboards": 0,
            "design_partner_dossiers": 0,
            "own_compliance_dossiers": 0,
            "product_scope_decisions": 0,
            "vertical_packs": 0,
            "reliability_reports": 0,
            "underwriting_quotes": 0,
            "insurer_partner_authority_dossiers": 0,
            "temporal_holdout_manifests": 0,
            "shadow_replays": 0,
            "soak_reports": 0,
            "traffic_holdout_exports": 0,
            "traffic_completeness_receipts": 0,
        }
        for entry in chain.entries:
            payload = entry.get("payload", {})
            contract_hash = _payload_contract_hash(entry)
            self.conn.execute(
                """
                INSERT OR REPLACE INTO chain_entries(
                    entry_id, idx, tenant_id, entry_type, timestamp,
                    contract_hash, payload_hash, body_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["entry_id"],
                    entry["index"],
                    entry["tenant_id"],
                    entry["entry_type"],
                    entry["timestamp"],
                    contract_hash,
                    entry["payload_hash"],
                    _json(entry),
                ),
            )
            counts["chain_entries"] += 1

            if entry.get("entry_type") == VENDOR_IDENTITY_ENTRY_TYPE:
                vendor = payload.get("vendor") if isinstance(payload.get("vendor"), dict) else {}
                proof_packs = payload.get("proof_packs") if isinstance(payload.get("proof_packs"), list) else []
                trust_network = payload.get("trust_network") if isinstance(payload.get("trust_network"), dict) else {}
                limitations = payload.get("limitations") if isinstance(payload.get("limitations"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO vendor_identity_receipts(
                        receipt_id, entry_id, receipt_hash, vendor_name, legal_name,
                        subject_ref, domain, identity_provider, identity_id,
                        proof_pack_count, trust_network_manifest_id,
                        trust_network_manifest_hash, issued_at, expires_at,
                        vendor_json, proof_packs_json, trust_network_json,
                        limitations_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("receipt_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("receipt_hash") or entry.get("payload_hash"),
                        vendor.get("name"),
                        vendor.get("legal_name"),
                        vendor.get("subject_ref"),
                        vendor.get("domain"),
                        vendor.get("identity_provider"),
                        vendor.get("identity_id"),
                        len(proof_packs),
                        trust_network.get("manifest_id"),
                        trust_network.get("manifest_hash"),
                        entry.get("timestamp"),
                        payload.get("expires_at"),
                        _json(vendor),
                        _json(proof_packs),
                        _json(trust_network),
                        _json(limitations),
                        _json(payload),
                    ),
                )
                counts["vendor_identity_receipts"] += 1

            if entry.get("entry_type") == IDENTITY_PROVIDER_ATTESTATION_ENTRY_TYPE:
                authentication = payload.get("authentication") if isinstance(payload.get("authentication"), dict) else {}
                subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
                agent = subject.get("agent") if isinstance(subject.get("agent"), dict) else {}
                vendor_binding = payload.get("vendor_binding") if isinstance(payload.get("vendor_binding"), dict) else {}
                source_artifacts = payload.get("source_artifacts") if isinstance(payload.get("source_artifacts"), list) else []
                limitations = payload.get("limitations") if isinstance(payload.get("limitations"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO identity_provider_attestations(
                        attestation_id, entry_id, attestation_hash, provider,
                        authentication_method, tenant_ref, observed_at, source,
                        subject_ref, identity_provider, identity_id,
                        identity_record_hash, agent_name, agent_version,
                        vendor_receipt_id, vendor_receipt_hash,
                        source_artifact_count, issued_at, authentication_json,
                        subject_json, vendor_binding_json, source_payload_json,
                        source_artifacts_json, limitations_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("attestation_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("attestation_hash") or entry.get("payload_hash"),
                        authentication.get("provider") or subject.get("identity_provider"),
                        authentication.get("method"),
                        authentication.get("tenant_ref"),
                        authentication.get("observed_at"),
                        authentication.get("source"),
                        subject.get("subject_ref"),
                        subject.get("identity_provider"),
                        subject.get("identity_id"),
                        subject.get("identity_record_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        vendor_binding.get("receipt_id"),
                        vendor_binding.get("receipt_hash"),
                        len(source_artifacts),
                        entry.get("timestamp"),
                        _json(authentication),
                        _json(subject),
                        _json(vendor_binding),
                        _json(payload.get("source_payload") if isinstance(payload.get("source_payload"), dict) else {}),
                        _json(source_artifacts),
                        _json(limitations),
                        _json(payload),
                    ),
                )
                counts["identity_provider_attestations"] += 1

            if entry.get("entry_type") == IDENTITY_PROVIDER_SESSION_ENTRY_TYPE:
                identity_attestation = payload.get("identity_attestation") if isinstance(payload.get("identity_attestation"), dict) else {}
                session = payload.get("session") if isinstance(payload.get("session"), dict) else {}
                authentication_context = payload.get("authentication_context") if isinstance(payload.get("authentication_context"), dict) else {}
                provider_evidence = payload.get("provider_evidence") if isinstance(payload.get("provider_evidence"), dict) else {}
                success = bool(provider_evidence.get("success"))
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO identity_provider_sessions(
                        session_id, entry_id, session_hash, provider, mode,
                        environment, attestation_id, attestation_hash,
                        session_ref, event_kind, provider_event_id,
                        identity_provider, identity_id, identity_record_hash,
                        decision, risk_level, response_status, success,
                        session_log_ref, session_log_root, audit_log_ref,
                        audit_log_root, recorded_at, identity_attestation_json,
                        session_json, authentication_context_json,
                        provider_evidence_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("session_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("session_hash") or entry.get("payload_hash"),
                        payload.get("provider") or session.get("identity_provider"),
                        payload.get("mode"),
                        payload.get("environment"),
                        identity_attestation.get("attestation_id"),
                        identity_attestation.get("attestation_hash"),
                        session.get("session_ref"),
                        session.get("event_kind"),
                        session.get("provider_event_id"),
                        session.get("identity_provider"),
                        session.get("identity_id"),
                        session.get("identity_record_hash"),
                        authentication_context.get("decision"),
                        authentication_context.get("risk_level"),
                        provider_evidence.get("response_status"),
                        1 if success else 0,
                        provider_evidence.get("session_log_ref"),
                        provider_evidence.get("session_log_root"),
                        provider_evidence.get("audit_log_ref"),
                        provider_evidence.get("audit_log_root"),
                        entry.get("timestamp"),
                        _json(identity_attestation),
                        _json(session),
                        _json(authentication_context),
                        _json(provider_evidence),
                        _json(payload),
                    ),
                )
                counts["identity_provider_sessions"] += 1

            if entry.get("entry_type") == IDENTITY_PROVIDER_LIFECYCLE_OPERATION_ENTRY_TYPE:
                identity_attestation = payload.get("identity_attestation") if isinstance(payload.get("identity_attestation"), dict) else {}
                source_session = payload.get("source_session") if isinstance(payload.get("source_session"), dict) else {}
                operation = payload.get("operation") if isinstance(payload.get("operation"), dict) else {}
                change_refs = payload.get("change_refs") if isinstance(payload.get("change_refs"), dict) else {}
                provider_evidence = payload.get("provider_evidence") if isinstance(payload.get("provider_evidence"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO identity_provider_lifecycle_operations(
                        operation_id, entry_id, operation_hash, provider, mode,
                        environment, attestation_id, attestation_hash,
                        source_session_id, source_session_hash, operation_kind,
                        operation_ref, provider_operation_id, identity_provider,
                        identity_id, identity_record_hash, target_state, outcome,
                        success, response_status, system_log_ref, system_log_root,
                        audit_log_ref, audit_log_root, recorded_at,
                        identity_attestation_json, source_session_json,
                        operation_json, change_refs_json, provider_evidence_json,
                        control_summary_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("operation_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("operation_hash") or entry.get("payload_hash"),
                        payload.get("provider") or operation.get("identity_provider"),
                        payload.get("mode"),
                        payload.get("environment"),
                        identity_attestation.get("attestation_id"),
                        identity_attestation.get("attestation_hash"),
                        source_session.get("session_id"),
                        source_session.get("session_hash"),
                        operation.get("kind"),
                        operation.get("operation_ref"),
                        operation.get("provider_operation_id"),
                        operation.get("identity_provider"),
                        operation.get("identity_id"),
                        operation.get("identity_record_hash"),
                        operation.get("target_state"),
                        operation.get("outcome"),
                        1 if provider_evidence.get("success") else 0,
                        provider_evidence.get("response_status"),
                        provider_evidence.get("system_log_ref"),
                        provider_evidence.get("system_log_root"),
                        provider_evidence.get("audit_log_ref"),
                        provider_evidence.get("audit_log_root"),
                        payload.get("recorded_at") or entry.get("timestamp"),
                        _json(identity_attestation),
                        _json(source_session),
                        _json(operation),
                        _json(change_refs),
                        _json(provider_evidence),
                        _json(control_summary),
                        _json(payload),
                    ),
                )
                counts["identity_provider_lifecycle_operations"] += 1

            if entry.get("entry_type") == IDENTITY_PROVIDER_LIFECYCLE_WORKER_ENTRY_TYPE:
                source_operation = payload.get("source_operation") if isinstance(payload.get("source_operation"), dict) else {}
                worker = payload.get("worker") if isinstance(payload.get("worker"), dict) else {}
                scheduler = payload.get("scheduler") if isinstance(payload.get("scheduler"), dict) else {}
                propagation = payload.get("propagation") if isinstance(payload.get("propagation"), dict) else {}
                observability = payload.get("observability") if isinstance(payload.get("observability"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO identity_provider_lifecycle_workers(
                        worker_operation_id, entry_id, worker_operation_hash,
                        provider, mode, environment, source_operation_id,
                        source_operation_hash, identity_id, identity_record_hash,
                        operation_kind, worker_ref, run_ref, worker_success,
                        schedule_ref, queue_ref, destination_ref, response_status,
                        propagation_log_ref, propagation_log_root, audit_log_ref,
                        audit_log_root, recorded_at, source_operation_json,
                        worker_json, scheduler_json, propagation_json,
                        observability_json, control_summary_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("worker_operation_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("worker_operation_hash") or entry.get("payload_hash"),
                        payload.get("provider") or source_operation.get("provider"),
                        payload.get("mode"),
                        payload.get("environment"),
                        source_operation.get("operation_id"),
                        source_operation.get("operation_hash"),
                        source_operation.get("identity_id"),
                        source_operation.get("identity_record_hash"),
                        source_operation.get("kind"),
                        worker.get("worker_ref"),
                        worker.get("run_ref"),
                        1 if worker.get("success") else 0,
                        scheduler.get("schedule_ref"),
                        scheduler.get("queue_ref"),
                        propagation.get("destination_ref"),
                        propagation.get("response_status"),
                        propagation.get("propagation_log_ref"),
                        propagation.get("propagation_log_root"),
                        observability.get("audit_log_ref"),
                        observability.get("audit_log_root"),
                        payload.get("recorded_at") or entry.get("timestamp"),
                        _json(source_operation),
                        _json(worker),
                        _json(scheduler),
                        _json(propagation),
                        _json(observability),
                        _json(control_summary),
                        _json(payload),
                    ),
                )
                counts["identity_provider_lifecycle_workers"] += 1

            if entry.get("entry_type") == IDENTITY_PROVIDER_AUTHORITY_ENTRY_TYPE:
                worker_binding = payload.get("worker_binding") if isinstance(payload.get("worker_binding"), dict) else {}
                summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                authority_evidence = payload.get("authority_evidence") if isinstance(payload.get("authority_evidence"), list) else []
                generated_at = payload.get("generated_at") or entry.get("timestamp")
                freshness = _authority_freshness_counts(authority_evidence, generated_at)
                missing_requirement_count = int(summary.get("missing_requirement_count") or len(summary.get("missing_requirement_ids") or []))
                production_claimed = payload.get("mode") == "production-dossier"
                production_ready = bool(production_claimed and missing_requirement_count == 0 and freshness["stale"] == 0 and freshness["missing"] == 0)
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO identity_provider_authority_dossiers(
                        dossier_id, entry_id, dossier_hash, mode, environment,
                        dossier_ref, authority_ref, producer_ref,
                        production_claimed, production_ready, worker_operation_id,
                        worker_receipt_hash, provider, identity_id,
                        identity_record_hash, operation_kind, worker_ref,
                        required_requirement_count, covered_requirement_count,
                        missing_requirement_count, authority_evidence_count,
                        fresh_evidence_count, stale_evidence_count,
                        missing_freshness_count, worker_binding_json,
                        summary_json, control_summary_json, authority_evidence_json,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("mode"),
                        payload.get("environment"),
                        payload.get("dossier_ref"),
                        payload.get("authority_ref"),
                        payload.get("producer_ref"),
                        1 if production_claimed else 0,
                        1 if production_ready else 0,
                        worker_binding.get("worker_operation_id"),
                        worker_binding.get("worker_receipt_hash"),
                        worker_binding.get("provider"),
                        worker_binding.get("identity_id"),
                        worker_binding.get("identity_record_hash"),
                        worker_binding.get("operation_kind"),
                        worker_binding.get("worker_ref"),
                        int(summary.get("required_requirement_count") or 0),
                        int(summary.get("covered_requirement_count") or 0),
                        missing_requirement_count,
                        int(summary.get("evidence_count") or len(authority_evidence)),
                        freshness["fresh"],
                        freshness["stale"],
                        freshness["missing"],
                        _json(worker_binding),
                        _json(summary),
                        _json(control_summary),
                        _json(authority_evidence),
                        generated_at,
                        _json(payload),
                    ),
                )
                counts["identity_provider_authority_dossiers"] += 1

            if entry.get("entry_type") == INGEST_ENTRY_TYPE:
                event = payload.get("event", {}) if isinstance(payload.get("event"), dict) else {}
                agent = event.get("agent", {}) if isinstance(event.get("agent"), dict) else {}
                attributes = event.get("attributes", {}) if isinstance(event.get("attributes"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO ingest_events(
                        entry_id, event_hash, contract_hash, trace_id, span_id,
                        parent_span_id, event_name, agent_name, agent_version,
                        risk_class, schema_url, observed_at, attributes_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("event_hash") or content_hash(event),
                        payload.get("contract_hash") or event.get("contract_hash"),
                        payload.get("trace_id") or event.get("trace_id"),
                        payload.get("span_id") or event.get("span_id"),
                        event.get("parent_span_id"),
                        event.get("event_name"),
                        agent.get("name"),
                        agent.get("version"),
                        event.get("risk_class"),
                        event.get("schema_url"),
                        event.get("timestamp") or entry.get("timestamp"),
                        _json(attributes),
                        _json(payload),
                    ),
                )
                counts["ingest_events"] += 1

            if entry.get("entry_type") == MCP_TOOL_CALL_ENTRY_TYPE:
                tool_call = payload.get("tool_call", {}) if isinstance(payload.get("tool_call"), dict) else {}
                agent = tool_call.get("agent", {}) if isinstance(tool_call.get("agent"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO mcp_tool_calls(
                        entry_id, session_id, request_id, tool_name,
                        contract_hash, agent_name, agent_version, risk_class,
                        request_hash, response_hash, tool_call_hash,
                        transcript_sequence, transcript_call_count,
                        previous_transcript_node_hash, transcript_node_hash,
                        transcript_root, observed_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("session_id") or tool_call.get("session_id"),
                        payload.get("request_id") or tool_call.get("request_id"),
                        payload.get("tool_name") or tool_call.get("tool_name"),
                        payload.get("contract_hash") or tool_call.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        tool_call.get("risk_class") or agent.get("risk_class"),
                        payload.get("request_hash"),
                        payload.get("response_hash"),
                        payload.get("tool_call_hash"),
                        int(payload.get("transcript_sequence") or 0),
                        int(payload.get("transcript_call_count") or 0),
                        payload.get("previous_transcript_node_hash"),
                        payload.get("transcript_node_hash"),
                        payload.get("transcript_root"),
                        tool_call.get("timestamp") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["mcp_tool_calls"] += 1

            if entry.get("entry_type") == MCP_PROXY_CAPTURE_ENTRY_TYPE:
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO mcp_proxy_captures(
                        capture_id, entry_id, proxy_ref, upstream_ref,
                        session_id, contract_hash, agent_name, agent_version,
                        risk_class, event_count, tool_call_count,
                        event_chain_root, transcript_root,
                        proxy_events_artifact_json, event_hashes_json,
                        tool_call_hashes_json, captured_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("capture_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("proxy_ref"),
                        payload.get("upstream_ref"),
                        payload.get("session_id"),
                        payload.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        agent.get("risk_class"),
                        int(payload.get("event_count") or 0),
                        int(payload.get("tool_call_count") or 0),
                        payload.get("event_chain_root"),
                        payload.get("transcript_root"),
                        _json(payload.get("proxy_events_artifact") or {}),
                        _json(payload.get("event_hashes") or []),
                        _json(payload.get("tool_call_hashes") or []),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["mcp_proxy_captures"] += 1

            if entry.get("entry_type") == SELF_SERVE_ONBOARDING_ENTRY_TYPE:
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO self_serve_onboarding_receipts(
                        receipt_id, entry_id, receipt_hash, onboarding_ref,
                        tenant_ref, agent_ref, requester_ref, environment,
                        sdk_scope, gateway_mode, source_artifact_count,
                        quickstart_step_count, quickstart_replay_count,
                        control_passed_count, control_not_applicable_count,
                        control_failed_count, generated_at, control_summary_json,
                        body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("receipt_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("receipt_hash") or entry.get("payload_hash"),
                        payload.get("onboarding_ref"),
                        payload.get("tenant_ref"),
                        payload.get("agent_ref"),
                        payload.get("requester_ref"),
                        payload.get("environment"),
                        payload.get("sdk_scope"),
                        payload.get("gateway_mode"),
                        int(payload.get("source_artifact_count") or 0),
                        int(payload.get("quickstart_step_count") or 0),
                        int(payload.get("quickstart_replay_count") or 0),
                        int(control_summary.get("passed") or 0),
                        int(control_summary.get("not-applicable") or 0),
                        int(control_summary.get("failed") or 0),
                        entry.get("timestamp"),
                        _json(control_summary),
                        _json(payload),
                    ),
                )
                counts["self_serve_onboarding_receipts"] += 1

            if entry.get("entry_type") == FRAMEWORK_ADAPTER_MATRIX_ENTRY_TYPE:
                summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
                by_status = summary.get("by_status", {}) if isinstance(summary.get("by_status"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO framework_adapter_matrices(
                        matrix_id, entry_id, matrix_hash, matrix_ref,
                        adapter_schema_url, adapter_package_version,
                        row_count, framework_count, production_certified_count,
                        total_fixture_events, summary_json, frameworks_json,
                        compatibility_hashes_json, issued_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("matrix_id"),
                        entry["entry_id"],
                        payload.get("matrix_hash") or entry.get("payload_hash"),
                        payload.get("matrix_ref"),
                        payload.get("adapter_schema_url"),
                        payload.get("adapter_package_version"),
                        int(summary.get("row_count") or 0),
                        int(summary.get("framework_count") or 0),
                        int(by_status.get("production-certified") or 0),
                        int(summary.get("total_fixture_events") or 0),
                        _json(summary),
                        _json(payload.get("frameworks") or []),
                        _json(payload.get("compatibility_hashes") or []),
                        payload.get("issued_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["framework_adapter_matrices"] += 1

            if entry.get("entry_type") == FRAMEWORK_HOOK_RELEASE_ENTRY_TYPE:
                adapter_matrix = payload.get("adapter_matrix") if isinstance(payload.get("adapter_matrix"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                frameworks = payload.get("frameworks") if isinstance(payload.get("frameworks"), list) else []
                production_certified_count = int(control_summary.get("production-certified") or 0)
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO framework_hook_releases(
                        release_id, entry_id, release_hash, release_ref,
                        matrix_id, matrix_hash, row_count, framework_count,
                        production_certified_count, adapter_matrix_json,
                        frameworks_json, hook_release_hashes_json,
                        control_summary_json, released_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("release_id"),
                        entry["entry_id"],
                        payload.get("release_hash") or entry.get("payload_hash"),
                        payload.get("release_ref"),
                        adapter_matrix.get("matrix_id"),
                        adapter_matrix.get("matrix_hash"),
                        len(frameworks),
                        len(set(str(item) for item in frameworks if item)),
                        production_certified_count,
                        _json(adapter_matrix),
                        _json(frameworks),
                        _json(payload.get("hook_release_hashes") or []),
                        _json(control_summary),
                        payload.get("released_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["framework_hook_releases"] += 1

            if entry.get("entry_type") == FRAMEWORK_HOOK_OPERATION_ENTRY_TYPE:
                runtime = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
                hook = payload.get("hook") if isinstance(payload.get("hook"), dict) else {}
                release_binding = payload.get("release_binding") if isinstance(payload.get("release_binding"), dict) else {}
                trace = payload.get("trace") if isinstance(payload.get("trace"), dict) else {}
                collector = payload.get("collector") if isinstance(payload.get("collector"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                agent = trace.get("agent") if isinstance(trace.get("agent"), dict) else {}
                contract_hashes = trace.get("contract_hashes") if isinstance(trace.get("contract_hashes"), list) else []
                operation_contract_hash = next((str(item) for item in contract_hashes if item), None)
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO framework_hook_operations(
                        operation_id, entry_id, operation_hash, mode,
                        environment, operation_ref, contract_hash, agent_name,
                        agent_version, risk_class, framework, runtime_package,
                        runtime_version, hook_package, hook_version,
                        collector_hook_ref, hook_release_hash, source_trace_id,
                        trace_id, event_count, event_root, runtime_json,
                        hook_json, release_binding_json, trace_json,
                        collector_json, control_summary_json, captured_at,
                        body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("operation_id"),
                        entry["entry_id"],
                        payload.get("operation_hash") or entry.get("payload_hash"),
                        payload.get("mode"),
                        payload.get("environment"),
                        payload.get("operation_ref"),
                        operation_contract_hash,
                        agent.get("name"),
                        agent.get("version"),
                        agent.get("risk_class"),
                        runtime.get("framework"),
                        runtime.get("package"),
                        runtime.get("version"),
                        hook.get("package"),
                        hook.get("version"),
                        hook.get("collector_hook_ref"),
                        hook.get("hook_release_hash"),
                        trace.get("source_trace_id"),
                        trace.get("trace_id"),
                        int(trace.get("event_count") or 0),
                        trace.get("event_root"),
                        _json(runtime),
                        _json(hook),
                        _json(release_binding),
                        _json(trace),
                        _json(collector),
                        _json(control_summary),
                        payload.get("captured_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["framework_hook_operations"] += 1

            if entry.get("entry_type") == FRAMEWORK_ADAPTER_AUTHORITY_ENTRY_TYPE:
                source_binding = payload.get("source_binding") if isinstance(payload.get("source_binding"), dict) else {}
                matrix_binding = source_binding.get("adapter_matrix") if isinstance(source_binding.get("adapter_matrix"), dict) else {}
                release_binding = source_binding.get("hook_release") if isinstance(source_binding.get("hook_release"), dict) else {}
                summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                authority_evidence = payload.get("authority_evidence") if isinstance(payload.get("authority_evidence"), list) else []
                missing_requirement_count = int(summary.get("missing_requirement_count") or 0)
                missing_freshness_count = int(summary.get("missing_freshness_count") or 0)
                production_claimed = payload.get("mode") == "production-dossier"
                production_ready = production_claimed and missing_requirement_count == 0 and missing_freshness_count == 0
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO framework_adapter_authority_dossiers(
                        dossier_id, entry_id, dossier_hash, dossier_ref,
                        mode, environment, authority_ref, producer_ref,
                        matrix_id, matrix_hash, release_id, release_hash,
                        production_claimed, production_ready,
                        required_requirement_count, covered_requirement_count,
                        missing_requirement_count, authority_evidence_count,
                        fresh_evidence_count, stale_evidence_count,
                        missing_freshness_count, source_binding_json,
                        summary_json, control_summary_json,
                        authority_evidence_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id"),
                        entry["entry_id"],
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("dossier_ref"),
                        payload.get("mode"),
                        payload.get("environment"),
                        payload.get("authority_ref"),
                        payload.get("producer_ref"),
                        matrix_binding.get("matrix_id"),
                        matrix_binding.get("matrix_hash"),
                        release_binding.get("release_id"),
                        release_binding.get("release_hash"),
                        1 if production_claimed else 0,
                        1 if production_ready else 0,
                        int(summary.get("required_requirement_count") or 0),
                        int(summary.get("covered_requirement_count") or 0),
                        missing_requirement_count,
                        int(summary.get("authority_evidence_count") or len(authority_evidence)),
                        int(summary.get("fresh_evidence_count") or 0),
                        int(summary.get("stale_evidence_count") or 0),
                        missing_freshness_count,
                        _json(source_binding),
                        _json(summary),
                        _json(control_summary),
                        _json(authority_evidence),
                        payload.get("generated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["framework_adapter_authority_dossiers"] += 1

            if entry.get("entry_type") == BYOC_OPERATOR_ENTRY_TYPE:
                deployment = payload.get("deployment") if isinstance(payload.get("deployment"), dict) else {}
                operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
                tenancy = payload.get("tenancy") if isinstance(payload.get("tenancy"), dict) else {}
                object_lock = payload.get("object_lock") if isinstance(payload.get("object_lock"), dict) else {}
                backup = payload.get("backup") if isinstance(payload.get("backup"), dict) else {}
                network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
                audit_log = payload.get("audit_log") if isinstance(payload.get("audit_log"), dict) else {}
                source_artifacts = payload.get("source_artifacts") if isinstance(payload.get("source_artifacts"), list) else []
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                legal_hold = object_lock.get("legal_hold") if isinstance(object_lock.get("legal_hold"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO byoc_operator_attestations(
                        attestation_id, entry_id, attestation_hash, mode,
                        environment, deployment_manifest_id,
                        deployment_manifest_hash, deployment_name,
                        deployment_mode, deployment_artifact_type,
                        operator_ref, operator_version, operator_image,
                        operator_image_digest, namespace, tenant_id,
                        customer_account_ref, data_plane_ref,
                        control_plane_ref, keyring_ref,
                        object_lock_provider, object_lock_bucket_ref,
                        object_lock_region, object_lock_enabled,
                        versioning_enabled, legal_hold_required,
                        legal_hold_active, backup_policy_ref,
                        restore_test_ref, private_endpoint, audit_log_ref,
                        audit_log_root, source_artifact_count,
                        control_summary_json, attested_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("attestation_id"),
                        entry["entry_id"],
                        payload.get("attestation_hash") or entry.get("payload_hash"),
                        payload.get("mode"),
                        payload.get("environment"),
                        deployment.get("manifest_id"),
                        deployment.get("manifest_hash"),
                        deployment.get("name"),
                        deployment.get("mode"),
                        deployment.get("artifact_type"),
                        operator.get("operator_ref"),
                        operator.get("version"),
                        operator.get("image"),
                        operator.get("image_digest"),
                        operator.get("namespace"),
                        tenancy.get("tenant_id"),
                        tenancy.get("customer_account_ref"),
                        tenancy.get("data_plane_ref"),
                        tenancy.get("control_plane_ref"),
                        tenancy.get("keyring_ref"),
                        object_lock.get("provider"),
                        object_lock.get("bucket_ref"),
                        object_lock.get("region"),
                        1 if object_lock.get("object_lock_enabled") else 0,
                        1 if object_lock.get("versioning_enabled") else 0,
                        1 if object_lock.get("legal_hold_required") else 0,
                        1 if legal_hold.get("legal_hold_id") else 0,
                        backup.get("backup_policy_ref"),
                        backup.get("restore_test_ref"),
                        1 if network.get("private_endpoint") else 0,
                        audit_log.get("audit_log_ref"),
                        audit_log.get("root"),
                        len(source_artifacts),
                        _json(control_summary),
                        payload.get("attested_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["byoc_operator_attestations"] += 1

            if entry.get("entry_type") == BYOC_AUTHORITY_ENTRY_TYPE:
                source_binding = payload.get("source_binding") if isinstance(payload.get("source_binding"), dict) else {}
                deployment = source_binding.get("deployment_manifest") if isinstance(source_binding.get("deployment_manifest"), dict) else {}
                operator = source_binding.get("byoc_operator") if isinstance(source_binding.get("byoc_operator"), dict) else {}
                object_lock = source_binding.get("object_lock") if isinstance(source_binding.get("object_lock"), dict) else {}
                tenancy = source_binding.get("tenancy") if isinstance(source_binding.get("tenancy"), dict) else {}
                summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
                artifact_summary = payload.get("artifact_summary") if isinstance(payload.get("artifact_summary"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                authority_evidence = payload.get("authority_evidence") if isinstance(payload.get("authority_evidence"), list) else []
                authority_artifacts = payload.get("authority_artifacts") if isinstance(payload.get("authority_artifacts"), list) else []
                generated_at = payload.get("generated_at") or entry.get("timestamp")
                freshness = _authority_freshness_counts(authority_evidence, generated_at)
                missing_requirement_count = int(summary.get("missing_requirement_count") or 0)
                production_claimed = payload.get("mode") == "production-dossier"
                production_ready = bool(
                    production_claimed
                    and missing_requirement_count == 0
                    and freshness["stale"] == 0
                    and freshness["missing"] == 0
                )
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO byoc_authority_dossiers(
                        dossier_id, entry_id, dossier_hash, mode,
                        environment, dossier_ref, authority_ref, producer_ref,
                        production_claimed, production_ready,
                        deployment_manifest_id, deployment_manifest_hash,
                        deployment_environment, byoc_operator_attestation_id,
                        operator_ref, operator_image_digest, namespace,
                        object_lock_bucket_ref, customer_account_ref,
                        data_plane_ref, required_requirement_count,
                        covered_requirement_count, missing_requirement_count,
                        authority_evidence_count, fresh_evidence_count,
                        stale_evidence_count, missing_freshness_count,
                        authority_artifact_count,
                        authority_artifact_requirement_count,
                        source_binding_json, summary_json,
                        artifact_summary_json, control_summary_json,
                        authority_evidence_json, authority_artifacts_json,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id"),
                        entry["entry_id"],
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("mode"),
                        payload.get("environment"),
                        payload.get("dossier_ref"),
                        payload.get("authority_ref"),
                        payload.get("producer_ref"),
                        1 if production_claimed else 0,
                        1 if production_ready else 0,
                        deployment.get("manifest_id"),
                        deployment.get("manifest_hash"),
                        deployment.get("environment"),
                        operator.get("attestation_id"),
                        operator.get("operator_ref"),
                        operator.get("image_digest"),
                        operator.get("namespace"),
                        object_lock.get("bucket_ref"),
                        tenancy.get("customer_account_ref"),
                        tenancy.get("data_plane_ref"),
                        int(summary.get("required_requirement_count") or 0),
                        int(summary.get("covered_requirement_count") or 0),
                        missing_requirement_count,
                        int(summary.get("authority_evidence_count") or len(authority_evidence)),
                        freshness["fresh"],
                        freshness["stale"],
                        freshness["missing"],
                        int(artifact_summary.get("artifact_count") or len(authority_artifacts)),
                        int(artifact_summary.get("requirement_count") or 0),
                        _json(source_binding),
                        _json(summary),
                        _json(artifact_summary),
                        _json(control_summary),
                        _json(authority_evidence),
                        _json(authority_artifacts),
                        generated_at,
                        _json(payload),
                    ),
                )
                counts["byoc_authority_dossiers"] += 1

            if entry.get("entry_type") == SUPERVISED_ACCESS_ENTRY_TYPE:
                audience = payload.get("audience") if isinstance(payload.get("audience"), dict) else {}
                reviewer = payload.get("reviewer") if isinstance(payload.get("reviewer"), dict) else {}
                artifact_refs = payload.get("artifact_refs") if isinstance(payload.get("artifact_refs"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO supervised_access_receipts(
                        receipt_id, entry_id, receipt_hash, session_id,
                        audience_type, audience_purpose, reviewer_subject_ref,
                        reviewer_organization, reviewer_role, artifact_count,
                        issued_at, expires_at, artifact_refs_json, limitations_json,
                        body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("receipt_id"),
                        entry["entry_id"],
                        payload.get("receipt_hash") or entry.get("payload_hash"),
                        payload.get("session_id"),
                        audience.get("type"),
                        audience.get("purpose"),
                        reviewer.get("subject_ref"),
                        reviewer.get("organization"),
                        reviewer.get("role"),
                        int(payload.get("artifact_count") or len(artifact_refs)),
                        entry.get("timestamp"),
                        payload.get("expires_at") or entry.get("timestamp"),
                        _json(artifact_refs),
                        _json(payload.get("limitations") or []),
                        _json(payload),
                    ),
                )
                counts["supervised_access_receipts"] += 1

            if entry.get("entry_type") == REGULATOR_ACCEPTANCE_ENTRY_TYPE:
                regulator = payload.get("regulator") if isinstance(payload.get("regulator"), dict) else {}
                decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
                review_scope = payload.get("review_scope") if isinstance(payload.get("review_scope"), dict) else {}
                source_refs = payload.get("source_refs") if isinstance(payload.get("source_refs"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO regulator_acceptances(
                        acceptance_id, entry_id, acceptance_hash, regulator_name,
                        authority_ref, reviewer_ref, outcome, accepted,
                        examination_ref, purpose, framework, source_ref_count,
                        source_refs_json, limitations_json, issued_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("acceptance_id"),
                        entry["entry_id"],
                        payload.get("acceptance_hash") or entry.get("payload_hash"),
                        regulator.get("name"),
                        regulator.get("authority_ref"),
                        regulator.get("reviewer_ref"),
                        decision.get("outcome"),
                        1 if decision.get("accepted") else 0,
                        decision.get("examination_ref"),
                        review_scope.get("purpose"),
                        review_scope.get("framework"),
                        len(source_refs),
                        _json(source_refs),
                        _json(payload.get("limitations") or []),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["regulator_acceptances"] += 1

            if entry.get("entry_type") == REVIEW_PORTAL_SERVICE_ENTRY_TYPE:
                service = payload.get("service") if isinstance(payload.get("service"), dict) else {}
                access = payload.get("access") if isinstance(payload.get("access"), dict) else {}
                source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
                control_summary = payload.get("control_status_summary") if isinstance(payload.get("control_status_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO review_portal_service_attestations(
                        attestation_id, entry_id, attestation_hash, mode,
                        environment, service_ref, service_version, portal_kind,
                        endpoint_url, service_image_digest, frontend_bundle_ref,
                        frontend_bundle_hash, api_ref, supervised_access_receipt_id,
                        session_id, audience_type, reviewer_subject_ref,
                        reviewer_organization, reviewer_role, artifact_count,
                        source_count, control_summary_json, attested_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("attestation_id"),
                        entry["entry_id"],
                        payload.get("attestation_hash") or entry.get("payload_hash"),
                        payload.get("mode"),
                        payload.get("environment"),
                        service.get("service_ref"),
                        service.get("version"),
                        service.get("portal_kind"),
                        service.get("endpoint_url"),
                        service.get("service_image_digest"),
                        service.get("frontend_bundle_ref"),
                        service.get("frontend_bundle_hash"),
                        service.get("api_ref"),
                        access.get("supervised_access_receipt_id"),
                        access.get("session_id"),
                        access.get("audience_type"),
                        access.get("reviewer_subject_ref"),
                        access.get("reviewer_organization"),
                        access.get("reviewer_role"),
                        int(access.get("artifact_count") or 0),
                        int(source.get("source_count") or 0),
                        _json(control_summary),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["review_portal_service_attestations"] += 1

            if entry.get("entry_type") == REVIEW_PORTAL_AUTHORITY_ENTRY_TYPE:
                binding = payload.get("service_attestation_binding") if isinstance(payload.get("service_attestation_binding"), dict) else {}
                summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                authority_evidence = payload.get("authority_evidence") if isinstance(payload.get("authority_evidence"), list) else []
                generated_at = payload.get("generated_at") or entry.get("timestamp")
                freshness = _authority_freshness_counts(authority_evidence, generated_at)
                missing_requirement_count = int(summary.get("missing_requirement_count") or 0)
                production_claimed = payload.get("mode") == "production-dossier"
                production_ready = bool(
                    production_claimed
                    and missing_requirement_count == 0
                    and freshness["stale"] == 0
                    and freshness["missing"] == 0
                )
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO review_portal_authority_dossiers(
                        dossier_id, entry_id, dossier_hash, mode,
                        environment, dossier_ref, authority_ref, producer_ref,
                        production_claimed, production_ready,
                        service_attestation_id, service_ref, portal_kind,
                        audience_type, reviewer_subject_ref,
                        required_requirement_count, covered_requirement_count,
                        missing_requirement_count, authority_evidence_count,
                        fresh_evidence_count, stale_evidence_count,
                        missing_freshness_count, service_attestation_binding_json,
                        summary_json, control_summary_json,
                        authority_evidence_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id"),
                        entry["entry_id"],
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("mode"),
                        payload.get("environment"),
                        payload.get("dossier_ref"),
                        payload.get("authority_ref"),
                        payload.get("producer_ref"),
                        1 if production_claimed else 0,
                        1 if production_ready else 0,
                        binding.get("attestation_id"),
                        binding.get("service_ref"),
                        binding.get("portal_kind"),
                        binding.get("audience_type"),
                        binding.get("reviewer_subject_ref"),
                        int(summary.get("required_requirement_count") or 0),
                        int(summary.get("covered_requirement_count") or 0),
                        missing_requirement_count,
                        int(summary.get("authority_evidence_count") or len(authority_evidence)),
                        freshness["fresh"],
                        freshness["stale"],
                        freshness["missing"],
                        _json(binding),
                        _json(summary),
                        _json(control_summary),
                        _json(authority_evidence),
                        generated_at,
                        _json(payload),
                    ),
                )
                counts["review_portal_authority_dossiers"] += 1

            if entry.get("entry_type") in STANDARDS_BODY_ENTRY_TYPES:
                record = _standards_body_record(entry, payload if isinstance(payload, dict) else {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO standards_body_evidence(
                        artifact_id, entry_id, entry_type, artifact_kind, artifact_hash,
                        artifact_ref, status, standards_body_name, program_ref,
                        target_track, actor_ref, source_artifact_count, control_count,
                        observed_at, source_artifacts_json, controls_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["artifact_id"],
                        record["entry_id"],
                        record["entry_type"],
                        record["artifact_kind"],
                        record["artifact_hash"],
                        record["artifact_ref"],
                        record["status"],
                        record["standards_body_name"],
                        record["program_ref"],
                        record["target_track"],
                        record["actor_ref"],
                        record["source_artifact_count"],
                        record["control_count"],
                        record["observed_at"],
                        _json(record["source_artifacts"]),
                        _json(record["controls"]),
                        _json(payload),
                    ),
                )
                counts["standards_body_evidence"] += 1

            if entry.get("entry_type") in AUDITOR_ECOSYSTEM_ENTRY_TYPES:
                record = _auditor_ecosystem_record(entry, payload if isinstance(payload, dict) else {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO auditor_ecosystem_evidence(
                        artifact_id, entry_id, entry_type, artifact_kind, artifact_hash,
                        artifact_ref, status, program_ref, auditor_ref,
                        auditor_organization, authority_ref, actor_ref,
                        source_artifact_count, control_count, observed_at,
                        source_artifacts_json, controls_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["artifact_id"],
                        record["entry_id"],
                        record["entry_type"],
                        record["artifact_kind"],
                        record["artifact_hash"],
                        record["artifact_ref"],
                        record["status"],
                        record["program_ref"],
                        record["auditor_ref"],
                        record["auditor_organization"],
                        record["authority_ref"],
                        record["actor_ref"],
                        record["source_artifact_count"],
                        record["control_count"],
                        record["observed_at"],
                        _json(record["source_artifacts"]),
                        _json(record["controls"]),
                        _json(payload),
                    ),
                )
                counts["auditor_ecosystem_evidence"] += 1


            if entry.get("entry_type") in TRUST_NETWORK_ENTRY_TYPES:
                record = _trust_network_record(entry, payload if isinstance(payload, dict) else {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO trust_network_evidence(
                        artifact_id, entry_id, entry_type, artifact_kind, artifact_hash,
                        artifact_ref, status, mode, environment, party_ref, service_ref,
                        registry_ref, marketplace_ref, source_artifact_count,
                        control_count, observed_at, source_artifacts_json,
                        controls_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["artifact_id"],
                        record["entry_id"],
                        record["entry_type"],
                        record["artifact_kind"],
                        record["artifact_hash"],
                        record["artifact_ref"],
                        record["status"],
                        record["mode"],
                        record["environment"],
                        record["party_ref"],
                        record["service_ref"],
                        record["registry_ref"],
                        record["marketplace_ref"],
                        record["source_artifact_count"],
                        record["control_count"],
                        record["observed_at"],
                        _json(record["source_artifacts"]),
                        _json(record["controls"]),
                        _json(payload),
                    ),
                )
                counts["trust_network_evidence"] += 1


            if entry.get("entry_type") in PROVIDER_DELIVERY_ENTRY_TYPES:
                record = _provider_delivery_record(entry, payload if isinstance(payload, dict) else {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO provider_delivery_evidence(
                        artifact_id, entry_id, entry_type, artifact_kind, artifact_hash,
                        artifact_ref, status, mode, environment, provider, service_ref,
                        worker_ref, bundle_ref, authority_ref, pack_id, contract_id,
                        contract_hash, target_ref, provider_endpoint, response_status,
                        success, source_artifact_count, control_count, observed_at,
                        source_artifacts_json, controls_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["artifact_id"],
                        record["entry_id"],
                        record["entry_type"],
                        record["artifact_kind"],
                        record["artifact_hash"],
                        record["artifact_ref"],
                        record["status"],
                        record["mode"],
                        record["environment"],
                        record["provider"],
                        record["service_ref"],
                        record["worker_ref"],
                        record["bundle_ref"],
                        record["authority_ref"],
                        record["pack_id"],
                        record["contract_id"],
                        record["contract_hash"],
                        record["target_ref"],
                        record["provider_endpoint"],
                        record["response_status"],
                        None if record["success"] is None else (1 if record["success"] else 0),
                        record["source_artifact_count"],
                        record["control_count"],
                        record["observed_at"],
                        _json(record["source_artifacts"]),
                        _json(record["controls"]),
                        _json(payload),
                    ),
                )
                counts["provider_delivery_evidence"] += 1

            if entry.get("entry_type") in PROVIDER_OPERATIONS_ENTRY_TYPES:
                record = _provider_operations_record(entry, payload if isinstance(payload, dict) else {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO provider_operations_evidence(
                        artifact_id, entry_id, entry_type, artifact_kind, artifact_hash,
                        artifact_ref, status, mode, environment, provider, operation_kind,
                        service_ref, installation_ref, webhook_ref, callback_ref, audit_ref,
                        credential_ref, authority_ref, target_ref, source_artifact_count,
                        control_count, observed_at, source_artifacts_json, controls_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["artifact_id"],
                        record["entry_id"],
                        record["entry_type"],
                        record["artifact_kind"],
                        record["artifact_hash"],
                        record["artifact_ref"],
                        record["status"],
                        record["mode"],
                        record["environment"],
                        record["provider"],
                        record["operation_kind"],
                        record["service_ref"],
                        record["installation_ref"],
                        record["webhook_ref"],
                        record["callback_ref"],
                        record["audit_ref"],
                        record["credential_ref"],
                        record["authority_ref"],
                        record["target_ref"],
                        record["source_artifact_count"],
                        record["control_count"],
                        record["observed_at"],
                        _json(record["source_artifacts"]),
                        _json(record["controls"]),
                        _json(payload),
                    ),
                )
                counts["provider_operations_evidence"] += 1

            if entry.get("entry_type") in POLICY_BACKEND_ENTRY_TYPES:
                record = _policy_backend_record(entry, payload if isinstance(payload, dict) else {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO policy_backend_evidence(
                        artifact_id, entry_id, entry_type, artifact_kind, artifact_hash,
                        artifact_ref, status, mode, environment, backend_ref, engine,
                        policy_ref, action_ref, decision_ref, service_ref, worker_ref,
                        provider_ref, bundle_ref, authority_ref, credential_ref, audit_ref,
                        response_status, allowed, source_artifact_count, control_count,
                        observed_at, source_artifacts_json, controls_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["artifact_id"],
                        record["entry_id"],
                        record["entry_type"],
                        record["artifact_kind"],
                        record["artifact_hash"],
                        record["artifact_ref"],
                        record["status"],
                        record["mode"],
                        record["environment"],
                        record["backend_ref"],
                        record["engine"],
                        record["policy_ref"],
                        record["action_ref"],
                        record["decision_ref"],
                        record["service_ref"],
                        record["worker_ref"],
                        record["provider_ref"],
                        record["bundle_ref"],
                        record["authority_ref"],
                        record["credential_ref"],
                        record["audit_ref"],
                        record["response_status"],
                        None if record["allowed"] is None else (1 if record["allowed"] else 0),
                        record["source_artifact_count"],
                        record["control_count"],
                        record["observed_at"],
                        _json(record["source_artifacts"]),
                        _json(record["controls"]),
                        _json(payload),
                    ),
                )
                counts["policy_backend_evidence"] += 1

            if entry.get("entry_type") in COMPLIANCE_EVIDENCE_ENTRY_TYPES:
                record = _compliance_record(entry, payload if isinstance(payload, dict) else {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO compliance_evidence(
                        artifact_id, entry_id, entry_type, artifact_kind, artifact_hash,
                        artifact_ref, status, mode, environment, dossier_ref,
                        authority_ref, producer_ref, document_id, pack_id, disclosure_id,
                        data_plane_ref, tenant_id, primary_region, kms_key_region, audit_ref,
                        required_requirement_count, covered_requirement_count,
                        missing_requirement_count, authority_evidence_count,
                        source_artifact_count, control_count, observed_at,
                        source_artifacts_json, source_binding_json, controls_json,
                        summary_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["artifact_id"],
                        record["entry_id"],
                        record["entry_type"],
                        record["artifact_kind"],
                        record["artifact_hash"],
                        record["artifact_ref"],
                        record["status"],
                        record["mode"],
                        record["environment"],
                        record["dossier_ref"],
                        record["authority_ref"],
                        record["producer_ref"],
                        record["document_id"],
                        record["pack_id"],
                        record["disclosure_id"],
                        record["data_plane_ref"],
                        record["tenant_id"],
                        record["primary_region"],
                        record["kms_key_region"],
                        record["audit_ref"],
                        record["required_requirement_count"],
                        record["covered_requirement_count"],
                        record["missing_requirement_count"],
                        record["authority_evidence_count"],
                        record["source_artifact_count"],
                        record["control_count"],
                        record["observed_at"],
                        _json(record["source_artifacts"]),
                        _json(record["source_binding"]),
                        _json(record["controls"]),
                        _json(record["summary"]),
                        _json(payload),
                    ),
                )
                counts["compliance_evidence"] += 1

            if entry.get("entry_type") == CONTRACT_ENTRY_TYPE:
                contract = payload.get("contract", {})
                agent = contract.get("agent", {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO contracts(
                        contract_hash, contract_id, version, agent_name,
                        agent_version, registered_entry_id, body_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["contract_hash"],
                        payload.get("contract_id"),
                        payload.get("contract_version"),
                        agent.get("name"),
                        agent.get("version"),
                        entry["entry_id"],
                        _json(contract),
                        entry["timestamp"],
                    ),
                )
                counts["contracts"] += 1

            if entry.get("entry_type") == EVAL_ENTRY_TYPE:
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
                results = payload.get("results", {}) if isinstance(payload.get("results"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO eval_runs(
                        entry_id, contract_id, contract_hash, agent_name,
                        agent_version, results_hash, evaluated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        payload.get("results_hash"),
                        results.get("evaluated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["eval_runs"] += 1

            if entry.get("entry_type") == GATE_ENTRY_TYPE:
                decision = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else decision.get("agent", {})
                if not isinstance(agent, dict):
                    agent = {}
                checks = decision.get("checks", []) if isinstance(decision.get("checks"), list) else []
                failed_checks = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
                holdout = decision.get("holdout", {}) if isinstance(decision.get("holdout"), dict) else {}
                approvals = decision.get("approvals", {}) if isinstance(decision.get("approvals"), dict) else {}
                holdout_passed = holdout.get("passed")
                approvals_passed = approvals.get("passed")
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO gate_decisions(
                        entry_id, contract_id, contract_hash, agent_name,
                        agent_version, outcome, passed, eval_entry_id,
                        contract_entry_id, results_hash, check_count,
                        failed_check_count, holdout_passed, approvals_passed,
                        evaluated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("contract_id") or decision.get("contract_id"),
                        payload.get("contract_hash") or decision.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        decision.get("outcome"),
                        1 if decision.get("passed") else 0,
                        decision.get("eval_entry_id"),
                        decision.get("contract_entry_id"),
                        decision.get("results_hash"),
                        len(checks),
                        len(failed_checks),
                        None if holdout_passed is None else (1 if holdout_passed else 0),
                        None if approvals_passed is None else (1 if approvals_passed else 0),
                        decision.get("evaluated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["gate_decisions"] += 1

            if entry.get("entry_type") == APPROVAL_ENTRY_TYPE:
                approval = payload.get("approval", {}) if isinstance(payload.get("approval"), dict) else {}
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
                metadata = approval.get("metadata", {}) if isinstance(approval.get("metadata"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO human_approvals(
                        entry_id, approval_hash, contract_id, contract_hash,
                        agent_name, agent_version, role, approver, source,
                        external_ref, approved_at, metadata_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("approval_hash") or content_hash(approval),
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        approval.get("role"),
                        approval.get("approver"),
                        approval.get("source"),
                        approval.get("external_ref"),
                        approval.get("approved_at") or entry.get("timestamp"),
                        _json(metadata),
                        _json(payload),
                    ),
                )
                counts["human_approvals"] += 1

            if entry.get("entry_type") == DEMOTION_ENTRY_TYPE:
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO promotion_demotions(
                        entry_id, contract_id, contract_hash, agent_name,
                        agent_version, from_environment, to_environment,
                        reason, triggering_entry_id, trigger_json,
                        decided_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        payload.get("from_environment"),
                        payload.get("to_environment"),
                        payload.get("reason"),
                        payload.get("triggering_entry_id"),
                        _json(payload.get("trigger") or {}),
                        payload.get("decided_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["promotion_demotions"] += 1

            if entry.get("entry_type") == ROLLBACK_ENTRY_TYPE:
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO promotion_rollbacks(
                        entry_id, contract_id, contract_hash, agent_name,
                        agent_version, target_agent_version, reason,
                        triggering_entry_id, decided_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        payload.get("target_agent_version"),
                        payload.get("reason"),
                        payload.get("triggering_entry_id"),
                        payload.get("decided_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["promotion_rollbacks"] += 1

            if entry.get("entry_type") == SOAK_DEMOTION_ENTRY_TYPE:
                contract_binding = payload.get("contract", {}) if isinstance(payload.get("contract"), dict) else {}
                agent = contract_binding.get("agent", {}) if isinstance(contract_binding.get("agent"), dict) else {}
                soak_report = payload.get("soak_report", {}) if isinstance(payload.get("soak_report"), dict) else {}
                demotion = payload.get("demotion", {}) if isinstance(payload.get("demotion"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO soak_demotion_receipts(
                        receipt_id, entry_id, receipt_hash, contract_id,
                        contract_hash, agent_name, agent_version,
                        soak_report_entry_id, demotion_entry_id, source_json,
                        violation_count, passed, attested_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("receipt_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("receipt_hash") or content_hash(payload),
                        contract_binding.get("contract_id"),
                        contract_binding.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        soak_report.get("entry_id"),
                        demotion.get("entry_id"),
                        _json(payload.get("source") or {}),
                        int(payload.get("violation_count") or 0),
                        1 if payload.get("passed") else 0,
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["soak_demotion_receipts"] += 1

            if entry.get("entry_type") == AGENT_INVENTORY_ENTRY_TYPE:
                agent = payload.get("agent", {})
                agent_hash = payload.get("agent_hash") or content_hash(agent)
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO agents(
                        agent_hash, name, version, owner, risk_class, governed,
                        source, observed_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        agent_hash,
                        agent.get("name"),
                        agent.get("version"),
                        agent.get("owner"),
                        agent.get("risk_class"),
                        1 if agent.get("governed") else 0,
                        payload.get("source"),
                        payload.get("observed_at"),
                        _json(agent),
                    ),
                )
                counts["agents"] += 1

            if entry.get("entry_type") == DELEGATION_ENTRY_TYPE:
                delegation = payload.get("delegation") if isinstance(payload.get("delegation"), dict) else {}
                parent = delegation.get("parent_agent") if isinstance(delegation.get("parent_agent"), dict) else {}
                child = delegation.get("child_agent") if isinstance(delegation.get("child_agent"), dict) else {}
                parent_ref = (
                    f"{parent.get('name')}@{parent.get('version')}"
                    if parent.get("name") and parent.get("version")
                    else None
                )
                child_ref = (
                    f"{child.get('name')}@{child.get('version')}"
                    if child.get("name") and child.get("version")
                    else None
                )
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO agent_delegations(
                        entry_id, delegation_hash, contract_hash,
                        parent_agent_name, parent_agent_version, parent_agent_ref,
                        child_agent_name, child_agent_version, child_agent_ref,
                        reason, scope_json, delegated_at, delegation_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("delegation_hash") or content_hash(delegation),
                        payload.get("contract_hash") or delegation.get("contract_hash"),
                        parent.get("name"),
                        parent.get("version"),
                        parent_ref,
                        child.get("name"),
                        child.get("version"),
                        child_ref,
                        delegation.get("reason"),
                        _json(delegation.get("scope") if isinstance(delegation.get("scope"), dict) else {}),
                        delegation.get("timestamp") or entry.get("timestamp"),
                        _json(delegation),
                        _json(payload),
                    ),
                )
                counts["agent_delegations"] += 1

            if entry.get("entry_type") == DELEGATION_GRAPH_ENTRY_TYPE:
                graph = payload.get("delegation_graph") if isinstance(payload.get("delegation_graph"), dict) else {}
                summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
                filters = payload.get("filters") if isinstance(payload.get("filters"), dict) else {}
                source_chain = payload.get("source_chain") if isinstance(payload.get("source_chain"), dict) else {}
                nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
                agent_refs = sorted(
                    {str(node.get("agent_ref")) for node in nodes if isinstance(node, dict) and node.get("agent_ref")}
                )
                contract_hashes = summary.get("contract_hashes") if isinstance(summary.get("contract_hashes"), list) else []
                contract_hash_filter = filters.get("contract_hash")
                graph_contract_hash = contract_hash_filter or (contract_hashes[0] if len(contract_hashes) == 1 else None)
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO agent_delegation_graphs(
                        delegation_graph_id, entry_id, delegation_graph_hash,
                        contract_hash, contract_hash_filter, root_agent_filter,
                        source_chain_tenant_id, source_chain_entry_count,
                        node_count, edge_count, max_depth, cycle_detected,
                        root_agents_json, leaf_agents_json, missing_inventory_json,
                        contract_hashes_json, agent_refs_json, node_root, edge_root,
                        filters_json, source_chain_json, summary_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("delegation_graph_id"),
                        entry["entry_id"],
                        payload.get("delegation_graph_hash") or content_hash(graph),
                        graph_contract_hash,
                        contract_hash_filter,
                        filters.get("root_agent"),
                        source_chain.get("tenant_id"),
                        int(source_chain.get("entry_count") or 0),
                        int(summary.get("node_count") or 0),
                        int(summary.get("edge_count") or 0),
                        summary.get("max_depth"),
                        1 if summary.get("cycle_detected") else 0,
                        _json(summary.get("root_agents") if isinstance(summary.get("root_agents"), list) else []),
                        _json(summary.get("leaf_agents") if isinstance(summary.get("leaf_agents"), list) else []),
                        _json(summary.get("missing_inventory") if isinstance(summary.get("missing_inventory"), list) else []),
                        _json(contract_hashes),
                        _json(agent_refs),
                        summary.get("node_root"),
                        summary.get("edge_root"),
                        _json(filters),
                        _json(source_chain),
                        _json(summary),
                        payload.get("generated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["agent_delegation_graphs"] += 1

            if entry.get("entry_type") == "chain.anchor.published":
                anchor = payload
                tree = anchor.get("tree", {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO anchors(
                        anchor_id, entry_id, tree_root, tree_size, tenant_id,
                        published_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        anchor.get("anchor_id"),
                        entry["entry_id"],
                        tree.get("root"),
                        tree.get("size"),
                        anchor.get("tenant_id") or entry.get("tenant_id"),
                        anchor.get("published_at"),
                        _json(anchor),
                    ),
                )
                counts["anchors"] += 1
            if entry.get("entry_type") == PROMOTION_STATUS_ENTRY_TYPE:
                proof_pack = payload.get("proof_pack", {}) if isinstance(payload.get("proof_pack"), dict) else {}
                gate_decision = payload.get("gate_decision", {}) if isinstance(payload.get("gate_decision"), dict) else {}
                agent = gate_decision.get("agent", {}) if isinstance(gate_decision.get("agent"), dict) else {}
                provider_status = payload.get("provider_status", {}) if isinstance(payload.get("provider_status"), dict) else {}
                provider_payload = payload.get("provider_payload", {}) if isinstance(payload.get("provider_payload"), dict) else {}
                target_ref = provider_payload.get("target_ref", {}) if isinstance(provider_payload.get("target_ref"), dict) else {}
                provider_success = provider_status.get("success")
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO promotion_statuses(
                        receipt_id, entry_id, provider, pack_id, contract_id,
                        contract_hash, agent_name, agent_version, gate_outcome,
                        passed, provider_status_kind, provider_status_success,
                        target_ref_json, violation_count, attested_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("receipt_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("provider"),
                        proof_pack.get("pack_id"),
                        gate_decision.get("contract_id"),
                        gate_decision.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        gate_decision.get("outcome"),
                        1 if payload.get("passed") else 0,
                        provider_status.get("kind"),
                        None if provider_success is None else (1 if provider_success else 0),
                        _json(target_ref),
                        int(payload.get("violation_count") or 0),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["promotion_statuses"] += 1

            if entry.get("entry_type") == RUNTIME_ENTRY_TYPE:
                action = payload.get("action", {}) if isinstance(payload.get("action"), dict) else {}
                checks = payload.get("checks", []) if isinstance(payload.get("checks"), list) else []
                failed_checks = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO runtime_attestations(
                        entry_id, contract_id, contract_hash, action_hash,
                        action_id, action_type, risk_class, passed, outcome,
                        check_count, failed_check_count, attested_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        payload.get("action_hash"),
                        action.get("action_id") or action.get("id"),
                        action.get("type"),
                        action.get("risk_class"),
                        1 if payload.get("passed") else 0,
                        payload.get("outcome"),
                        len(checks),
                        len(failed_checks),
                        payload.get("timestamp") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["runtime_attestations"] += 1

            if entry.get("entry_type") == POLICY_DECISION_ENTRY_TYPE:
                checks = payload.get("checks", []) if isinstance(payload.get("checks"), list) else []
                failed_checks = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
                matched_rules = payload.get("matched_rules", []) if isinstance(payload.get("matched_rules"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO policy_decisions(
                        entry_id, policy_pack_id, policy_pack_version, policy_pack_hash,
                        contract_hash, action_hash, passed, outcome, matched_rule_count,
                        check_count, failed_check_count, evaluated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("policy_pack_id"),
                        payload.get("policy_pack_version"),
                        payload.get("policy_pack_hash"),
                        payload.get("contract_hash"),
                        payload.get("action_hash"),
                        1 if payload.get("passed") else 0,
                        payload.get("outcome"),
                        len(matched_rules),
                        len(checks),
                        len(failed_checks),
                        payload.get("evaluated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["policy_decisions"] += 1

            if entry.get("entry_type") == POLICY_ENGINE_ENTRY_TYPE:
                engine = payload.get("engine", {}) if isinstance(payload.get("engine"), dict) else {}
                policy = payload.get("policy", {}) if isinstance(payload.get("policy"), dict) else {}
                action = payload.get("action", {}) if isinstance(payload.get("action"), dict) else {}
                proof_pack = payload.get("proof_pack", {}) if isinstance(payload.get("proof_pack"), dict) else {}
                decision = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
                decision_passed = decision.get("passed")
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO policy_engine_receipts(
                        receipt_id, entry_id, engine_name, engine_mode,
                        policy_pack_id, policy_pack_version, policy_pack_hash,
                        action_hash, action_id, action_type, risk_class,
                        pack_id, contract_id, contract_hash, decision_entry_id,
                        decision_outcome, decision_passed, evaluated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("receipt_id") or entry["entry_id"],
                        entry["entry_id"],
                        engine.get("name"),
                        engine.get("mode"),
                        policy.get("id"),
                        policy.get("version"),
                        policy.get("hash"),
                        action.get("hash"),
                        action.get("id"),
                        action.get("type"),
                        action.get("risk_class"),
                        proof_pack.get("pack_id"),
                        proof_pack.get("contract_id"),
                        proof_pack.get("contract_hash"),
                        decision.get("entry_id"),
                        decision.get("outcome"),
                        None if decision_passed is None else (1 if decision_passed else 0),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["policy_engine_receipts"] += 1

            if entry.get("entry_type") == INCIDENT_ENTRY_TYPE:
                incident = payload.get("incident", {}) if isinstance(payload.get("incident"), dict) else {}
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else incident.get("agent", {})
                if not isinstance(agent, dict):
                    agent = {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO incidents(
                        incident_id, entry_id, contract_hash, agent_name, agent_version,
                        severity, summary, detected_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.get("id") or payload.get("incident_hash") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("contract_hash") or incident.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        incident.get("severity"),
                        incident.get("summary"),
                        incident.get("detected_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["incidents"] += 1

            if entry.get("entry_type") == ROADMAP_AUDIT_ENTRY_TYPE:
                source = payload.get("source", {}) if isinstance(payload.get("source"), dict) else {}
                limitations = payload.get("limitations", []) if isinstance(payload.get("limitations"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO roadmap_audits(
                        audit_id, entry_id, audit_hash, completion_position,
                        requirement_count, implemented_local_count,
                        reference_attested_count, missing_local_evidence_count,
                        deferred_external_count, source_json, limitations_json,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("audit_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("audit_hash") or entry.get("payload_hash"),
                        payload.get("completion_position"),
                        int(payload.get("requirement_count") or 0),
                        int(payload.get("implemented_local_count") or 0),
                        int(payload.get("reference_attested_count") or 0),
                        int(payload.get("missing_local_evidence_count") or 0),
                        int(payload.get("deferred_external_count") or 0),
                        _json(source),
                        _json(limitations),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["roadmap_audits"] += 1

            if entry.get("entry_type") == EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE:
                source_plan = payload.get("source_plan", {}) if isinstance(payload.get("source_plan"), dict) else {}
                source_manifest = payload.get("source_manifest", {}) if isinstance(payload.get("source_manifest"), dict) else {}
                source_audit = payload.get("source_roadmap_audit", {}) if isinstance(payload.get("source_roadmap_audit"), dict) else {}
                collected_tasks = payload.get("collected_tasks", []) if isinstance(payload.get("collected_tasks"), list) else []
                snapshot_ids = payload.get("snapshot_ids", []) if isinstance(payload.get("snapshot_ids"), list) else []
                intake_ids = payload.get("intake_ids", []) if isinstance(payload.get("intake_ids"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO external_evidence_collection_runs(
                        run_id, entry_id, run_hash, source_map_hash, manifest_id,
                        manifest_ref, manifest_hash, audit_id, audit_hash,
                        require_fresh, require_live_source_uris,
                        require_source_snapshot_artifacts,
                        require_fresh_source_snapshot_artifacts, collected_count,
                        task_count, collected_tasks_json, snapshot_ids_json,
                        intake_ids_json, source_plan_json, source_manifest_json,
                        source_roadmap_audit_json, freshness_checked_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("run_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("run_hash") or entry.get("payload_hash"),
                        payload.get("source_map_hash"),
                        source_manifest.get("manifest_id"),
                        source_manifest.get("manifest_ref"),
                        source_manifest.get("manifest_hash"),
                        source_audit.get("audit_id"),
                        source_audit.get("audit_hash"),
                        1 if payload.get("require_fresh") else 0,
                        1 if payload.get("require_live_source_uris") else 0,
                        1 if payload.get("require_source_snapshot_artifacts") else 0,
                        1 if payload.get("require_fresh_source_snapshot_artifacts") else 0,
                        int(payload.get("collected_count") or 0),
                        int(payload.get("task_count") or 0),
                        _json(collected_tasks),
                        _json(snapshot_ids),
                        _json(intake_ids),
                        _json(source_plan),
                        _json(source_manifest),
                        _json(source_audit),
                        payload.get("freshness_checked_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["external_evidence_collection_runs"] += 1

            if entry.get("entry_type") == EXTERNAL_EVIDENCE_ENTRY_TYPE:
                source_audit = payload.get("source_roadmap_audit", {}) if isinstance(payload.get("source_roadmap_audit"), dict) else {}
                missing_ids = payload.get("missing_requirement_ids", []) if isinstance(payload.get("missing_requirement_ids"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO external_evidence_manifests(
                        manifest_id, entry_id, manifest_ref, manifest_hash, status,
                        require_complete, require_fresh, require_live_source_uris,
                        required_requirement_count, covered_requirement_count,
                        missing_requirement_count, required_authority_kind_count,
                        covered_authority_kind_count, missing_authority_kind_count,
                        evidence_count, fresh_evidence_count, stale_evidence_count,
                        missing_freshness_count, source_roadmap_audit_json,
                        missing_requirement_ids_json, freshness_checked_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("manifest_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("manifest_ref"),
                        payload.get("manifest_hash") or entry.get("payload_hash"),
                        payload.get("status"),
                        1 if payload.get("require_complete") else 0,
                        1 if payload.get("require_fresh") else 0,
                        1 if payload.get("require_live_source_uris") else 0,
                        int(payload.get("required_requirement_count") or 0),
                        int(payload.get("covered_requirement_count") or 0),
                        int(payload.get("missing_requirement_count") or 0),
                        int(payload.get("required_authority_kind_count") or 0),
                        int(payload.get("covered_authority_kind_count") or 0),
                        int(payload.get("missing_authority_kind_count") or 0),
                        int(payload.get("evidence_count") or 0),
                        int(payload.get("fresh_evidence_count") or 0),
                        int(payload.get("stale_evidence_count") or 0),
                        int(payload.get("missing_freshness_count") or 0),
                        _json(source_audit),
                        _json(missing_ids),
                        payload.get("freshness_checked_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["external_evidence_manifests"] += 1

            if entry.get("entry_type") == PHASE_SCOREBOARD_ENTRY_TYPE:
                phase_counts = payload.get("phase_counts") if isinstance(payload.get("phase_counts"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO phase_scoreboards(
                        scoreboard_id, entry_id, scoreboard_hash, scoreboard_ref,
                        mode, environment, milestone_count, phase_counts_json,
                        control_summary_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("scoreboard_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("scoreboard_hash") or entry.get("payload_hash"),
                        payload.get("scoreboard_ref"),
                        payload.get("mode"),
                        payload.get("environment"),
                        int(payload.get("milestone_count") or 0),
                        _json(phase_counts),
                        _json(control_summary),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["phase_scoreboards"] += 1

            if entry.get("entry_type") == DESIGN_PARTNER_ENTRY_TYPE:
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO design_partner_dossiers(
                        dossier_id, entry_id, dossier_hash, dossier_ref,
                        mode, environment, partner_count, signed_partner_count,
                        signed_pilot_value_usd, external_scrutiny_survival_count,
                        source_artifact_count, control_summary_json,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("dossier_ref"),
                        payload.get("mode"),
                        payload.get("environment"),
                        int(payload.get("partner_count") or 0),
                        int(payload.get("signed_partner_count") or 0),
                        int(payload.get("signed_pilot_value_usd") or 0),
                        int(payload.get("external_scrutiny_survival_count") or 0),
                        int(payload.get("source_artifact_count") or 0),
                        _json(control_summary),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["design_partner_dossiers"] += 1

            if entry.get("entry_type") == OWN_COMPLIANCE_ENTRY_TYPE:
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO own_compliance_dossiers(
                        dossier_id, entry_id, dossier_hash, dossier_ref,
                        scope_ref, mode, environment, evidence_count,
                        required_certification_evidence_count, source_artifact_count,
                        control_summary_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("dossier_ref"),
                        payload.get("scope_ref"),
                        payload.get("mode"),
                        payload.get("environment"),
                        int(payload.get("evidence_count") or 0),
                        int(payload.get("required_certification_evidence_count") or 0),
                        int(payload.get("source_artifact_count") or 0),
                        _json(control_summary),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["own_compliance_dossiers"] += 1

            if entry.get("entry_type") == PRODUCT_SCOPE_ENTRY_TYPE:
                proof_impacts = payload.get("proof_impacts") if isinstance(payload.get("proof_impacts"), list) else []
                anti_focus_flags = payload.get("anti_focus_flags") if isinstance(payload.get("anti_focus_flags"), list) else []
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO product_scope_decisions(
                        decision_id, entry_id, decision_hash, decision_ref,
                        decision, feature_title, proof_impacts_json,
                        anti_focus_flags_json, control_summary_json,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("decision_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("decision_hash") or entry.get("payload_hash"),
                        payload.get("decision_ref"),
                        payload.get("decision"),
                        payload.get("feature_title"),
                        _json(proof_impacts),
                        _json(anti_focus_flags),
                        _json(control_summary),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["product_scope_decisions"] += 1

            if entry.get("entry_type") == VERTICAL_PACK_ENTRY_TYPE:
                risk_classes = payload.get("risk_classes") if isinstance(payload.get("risk_classes"), list) else []
                frameworks = payload.get("frameworks") if isinstance(payload.get("frameworks"), list) else []
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO vertical_packs(
                        pack_id, entry_id, pack_hash, pack_ref, vertical,
                        title, producer_ref, reviewer_ref, environment,
                        risk_classes_json, frameworks_json, source_artifact_count,
                        external_requirement_count, control_summary_json,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("pack_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("pack_hash") or entry.get("payload_hash"),
                        payload.get("pack_ref"),
                        payload.get("vertical"),
                        payload.get("title"),
                        payload.get("producer_ref"),
                        payload.get("reviewer_ref"),
                        payload.get("environment"),
                        _json(risk_classes),
                        _json(frameworks),
                        int(payload.get("source_artifact_count") or 0),
                        int(payload.get("external_requirement_count") or 0),
                        _json(control_summary),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["vertical_packs"] += 1

            if entry.get("entry_type") == RELIABILITY_REPORT_ENTRY_TYPE:
                reporting_period = payload.get("reporting_period") if isinstance(payload.get("reporting_period"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO reliability_reports(
                        report_id, entry_id, report_hash, report_ref, mode,
                        reporting_period_json, cohort_count, source_product_count,
                        incident_rate_per_100k_actions, gate_pass_rate_bps,
                        control_summary_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("report_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("report_hash") or entry.get("payload_hash"),
                        payload.get("report_ref"),
                        payload.get("mode"),
                        _json(reporting_period),
                        int(payload.get("cohort_count") or 0),
                        int(payload.get("source_product_count") or 0),
                        payload.get("incident_rate_per_100k_actions"),
                        payload.get("gate_pass_rate_bps"),
                        _json(control_summary),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["reliability_reports"] += 1

            if entry.get("entry_type") == UNDERWRITING_QUOTE_ENTRY_TYPE:
                underwriter = payload.get("underwriter") if isinstance(payload.get("underwriter"), dict) else {}
                applicant_risk = payload.get("applicant_risk") if isinstance(payload.get("applicant_risk"), dict) else {}
                quote = payload.get("quote") if isinstance(payload.get("quote"), dict) else {}
                risk_evidence = payload.get("risk_evidence") if isinstance(payload.get("risk_evidence"), dict) else {}
                limitations = payload.get("limitations") if isinstance(payload.get("limitations"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO underwriting_quotes(
                        quote_id, entry_id, quote_hash, underwriter_name,
                        underwriter_mode, product, quote_ref, status, currency,
                        coverage_limit_usd, base_premium_usd,
                        discount_percent, quoted_premium_usd,
                        term_start, term_end, consent_id, consent_active,
                        pack_id, contract_id, chain_root, risk_score,
                        risk_tier, gate_outcome, issued_at,
                        applicant_risk_json, quote_json, risk_evidence_json,
                        limitations_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("quote_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("quote_hash") or entry.get("payload_hash"),
                        underwriter.get("name"),
                        underwriter.get("mode"),
                        quote.get("product"),
                        quote.get("quote_ref"),
                        quote.get("status"),
                        quote.get("currency"),
                        quote.get("coverage_limit_usd"),
                        quote.get("base_premium_usd"),
                        quote.get("discount_percent"),
                        quote.get("quoted_premium_usd"),
                        quote.get("term_start"),
                        quote.get("term_end"),
                        risk_evidence.get("consent_id"),
                        1 if risk_evidence.get("consent_active") else 0,
                        risk_evidence.get("pack_id") or applicant_risk.get("pack_id"),
                        risk_evidence.get("contract_id") or applicant_risk.get("contract_id"),
                        risk_evidence.get("chain_root"),
                        applicant_risk.get("risk_score"),
                        applicant_risk.get("risk_tier"),
                        applicant_risk.get("gate_outcome"),
                        entry.get("timestamp"),
                        _json(applicant_risk),
                        _json(quote),
                        _json(risk_evidence),
                        _json(limitations),
                        _json(payload),
                    ),
                )
                counts["underwriting_quotes"] += 1

            if entry.get("entry_type") == INSURER_PARTNER_AUTHORITY_ENTRY_TYPE:
                service_binding = payload.get("service_attestation_binding") if isinstance(payload.get("service_attestation_binding"), dict) else {}
                worker_bindings = payload.get("worker_receipt_bindings") if isinstance(payload.get("worker_receipt_bindings"), list) else []
                worker_bundle_bindings = payload.get("worker_bundle_bindings") if isinstance(payload.get("worker_bundle_bindings"), list) else []
                summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                authority_evidence = payload.get("authority_evidence") if isinstance(payload.get("authority_evidence"), list) else []
                generated_at = payload.get("generated_at") or entry.get("timestamp")
                freshness = _authority_freshness_counts(authority_evidence, generated_at)
                missing_requirement_count = int(summary.get("missing_requirement_count") or 0)
                production_claimed = payload.get("mode") == "production-dossier"
                production_ready = bool(
                    production_claimed
                    and missing_requirement_count == 0
                    and freshness["stale"] == 0
                    and freshness["missing"] == 0
                )
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO insurer_partner_authority_dossiers(
                        dossier_id, entry_id, dossier_hash, mode, environment,
                        dossier_ref, authority_ref, producer_ref,
                        production_claimed, production_ready,
                        service_attestation_id, service_attestation_hash,
                        service_ref, partner_api_endpoint, underwriter,
                        quote_id, quote_ref, telemetry_hash, consent_id,
                        risk_tier, worker_receipt_count,
                        worker_bundle_count, required_requirement_count,
                        covered_requirement_count, missing_requirement_count,
                        authority_evidence_count, fresh_evidence_count,
                        stale_evidence_count, missing_freshness_count,
                        service_binding_json, worker_receipt_bindings_json,
                        worker_bundle_bindings_json, summary_json,
                        control_summary_json, authority_evidence_json,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("mode"),
                        payload.get("environment"),
                        payload.get("dossier_ref"),
                        payload.get("authority_ref"),
                        payload.get("producer_ref"),
                        1 if production_claimed else 0,
                        1 if production_ready else 0,
                        service_binding.get("attestation_id"),
                        service_binding.get("attestation_hash"),
                        service_binding.get("service_ref"),
                        service_binding.get("partner_api_endpoint"),
                        service_binding.get("underwriter"),
                        service_binding.get("quote_id"),
                        service_binding.get("quote_ref"),
                        service_binding.get("telemetry_hash"),
                        service_binding.get("consent_id"),
                        service_binding.get("risk_tier"),
                        len(worker_bindings),
                        len(worker_bundle_bindings),
                        int(summary.get("required_requirement_count") or 0),
                        int(summary.get("covered_requirement_count") or 0),
                        missing_requirement_count,
                        int(summary.get("evidence_count") or len(authority_evidence)),
                        freshness["fresh"],
                        freshness["stale"],
                        freshness["missing"],
                        _json(service_binding),
                        _json(worker_bindings),
                        _json(worker_bundle_bindings),
                        _json(summary),
                        _json(control_summary),
                        _json(authority_evidence),
                        generated_at,
                        _json(payload),
                    ),
                )
                counts["insurer_partner_authority_dossiers"] += 1

            if entry.get("entry_type") == TEMPORAL_HOLDOUT_ENTRY_TYPE:
                contract = payload.get("contract") if isinstance(payload.get("contract"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO temporal_holdout_manifests(
                        manifest_id, entry_id, manifest_hash, run_id, dataset_id,
                        contract_id, contract_hash, candidate_version, record_count,
                        violation_count, passed, records_root,
                        earliest_record_timestamp, latest_record_timestamp,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("manifest_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("manifest_hash") or entry.get("payload_hash"),
                        payload.get("run_id"),
                        payload.get("dataset_id"),
                        contract.get("id"),
                        contract.get("hash"),
                        payload.get("candidate_version"),
                        int(payload.get("record_count") or 0),
                        int(payload.get("violation_count") or 0),
                        1 if payload.get("passed") else 0,
                        payload.get("records_root"),
                        payload.get("earliest_record_timestamp"),
                        payload.get("latest_record_timestamp"),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["temporal_holdout_manifests"] += 1

            if entry.get("entry_type") == SHADOW_REPLAY_ENTRY_TYPE:
                checks = payload.get("checks") if isinstance(payload.get("checks"), list) else []
                failed_checks = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
                holdout = payload.get("holdout") if isinstance(payload.get("holdout"), dict) else {}
                holdout_errors = holdout.get("errors") if isinstance(holdout.get("errors"), list) else []
                temporal_holdout = payload.get("temporal_holdout") if isinstance(payload.get("temporal_holdout"), dict) else {}
                metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
                holdout_passed = holdout.get("passed")
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO shadow_replays(
                        entry_id, run_id, contract_id, contract_hash,
                        candidate_version, replay_hash, records_checked,
                        passed, outcome, holdout_passed, holdout_error_count,
                        check_count, failed_check_count,
                        temporal_holdout_manifest_id,
                        temporal_holdout_manifest_hash, evaluated_at,
                        metrics_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("run_id"),
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        payload.get("candidate_version"),
                        payload.get("replay_hash"),
                        int(payload.get("records_checked") or 0),
                        1 if payload.get("passed") else 0,
                        payload.get("outcome"),
                        None if holdout_passed is None else (1 if holdout_passed else 0),
                        len(holdout_errors),
                        len(checks),
                        len(failed_checks),
                        temporal_holdout.get("manifest_id"),
                        temporal_holdout.get("manifest_hash"),
                        payload.get("evaluated_at") or entry.get("timestamp"),
                        _json(metrics),
                        _json(payload),
                    ),
                )
                counts["shadow_replays"] += 1

            if entry.get("entry_type") == SOAK_REPORT_ENTRY_TYPE:
                checks = payload.get("checks") if isinstance(payload.get("checks"), list) else []
                failed_checks = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
                incidents = payload.get("incidents") if isinstance(payload.get("incidents"), list) else []
                drift_alarms = payload.get("drift_alarms") if isinstance(payload.get("drift_alarms"), list) else []
                blocking_drift = [
                    alarm
                    for alarm in drift_alarms
                    if isinstance(alarm, dict) and str(alarm.get("severity") or "").lower() in {"high", "critical", "blocking"}
                ]
                soak = payload.get("soak") if isinstance(payload.get("soak"), dict) else {}
                metrics = {
                    str(check.get("name")): check.get("actual")
                    for check in checks
                    if isinstance(check, dict) and check.get("name")
                }
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO soak_reports(
                        entry_id, report_id, contract_id, contract_hash,
                        candidate_version, soak_hash, window_count,
                        incident_count, drift_alarm_count,
                        blocking_drift_alarm_count, passed, outcome,
                        check_count, failed_check_count, evaluated_at,
                        metrics_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("report_id"),
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        soak.get("candidate_version"),
                        payload.get("soak_hash"),
                        int(payload.get("window_count") or 0),
                        len(incidents),
                        len(drift_alarms),
                        len(blocking_drift),
                        1 if payload.get("passed") else 0,
                        payload.get("outcome"),
                        len(checks),
                        len(failed_checks),
                        payload.get("evaluated_at") or entry.get("timestamp"),
                        _json(metrics),
                        _json(payload),
                    ),
                )
                counts["soak_reports"] += 1
            if entry.get("entry_type") == TRAFFIC_HOLDOUT_EXPORT_ENTRY_TYPE:
                contract = payload.get("contract") if isinstance(payload.get("contract"), dict) else {}
                replay = payload.get("replay") if isinstance(payload.get("replay"), dict) else {}
                extraction_window = payload.get("extraction_window") if isinstance(payload.get("extraction_window"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO traffic_holdout_exports(
                        export_id, entry_id, export_hash, export_ref,
                        source_ref, exporter_ref, contract_id, contract_hash,
                        candidate_version, record_count, violation_count,
                        passed, extraction_window_json, records_root,
                        earliest_record_timestamp, latest_record_timestamp,
                        produced_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("export_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("export_hash") or entry.get("payload_hash"),
                        payload.get("export_ref"),
                        payload.get("source_ref"),
                        payload.get("exporter_ref"),
                        contract.get("id"),
                        contract.get("hash"),
                        replay.get("candidate_version"),
                        int(payload.get("record_count") or 0),
                        int(payload.get("violation_count") or 0),
                        1 if payload.get("passed") else 0,
                        _json(extraction_window),
                        payload.get("records_root"),
                        payload.get("earliest_record_timestamp"),
                        payload.get("latest_record_timestamp"),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["traffic_holdout_exports"] += 1

            if entry.get("entry_type") == TRAFFIC_COMPLETENESS_ENTRY_TYPE:
                traffic_export = payload.get("traffic_export") if isinstance(payload.get("traffic_export"), dict) else {}
                contract = traffic_export.get("contract") if isinstance(traffic_export.get("contract"), dict) else {}
                replay = traffic_export.get("replay") if isinstance(traffic_export.get("replay"), dict) else {}
                source_completeness = payload.get("source_completeness") if isinstance(payload.get("source_completeness"), dict) else {}
                provider_exchange = payload.get("provider_exchange") if isinstance(payload.get("provider_exchange"), dict) else {}
                record_count = int(traffic_export.get("record_count") or source_completeness.get("traffic_record_count") or 0)
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO traffic_completeness_receipts(
                        completeness_id, entry_id, completeness_hash, mode,
                        authority_ref, export_id, export_hash, contract_id,
                        contract_hash, candidate_version, record_count,
                        violation_count, passed, source_completeness_json,
                        provider_exchange_json, produced_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("completeness_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("completeness_hash") or entry.get("payload_hash"),
                        payload.get("mode"),
                        payload.get("authority_ref"),
                        traffic_export.get("export_id"),
                        traffic_export.get("export_hash"),
                        contract.get("id"),
                        contract.get("hash"),
                        replay.get("candidate_version"),
                        record_count,
                        int(payload.get("violation_count") or 0),
                        1 if payload.get("passed") else 0,
                        _json(source_completeness),
                        _json(provider_exchange),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["traffic_completeness_receipts"] += 1
            if _is_authority_dossier_payload(entry, payload):
                summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
                evidence_items = (
                    payload.get("authority_evidence") if isinstance(payload.get("authority_evidence"), list) else []
                )
                control_summary = (
                    payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                )
                covered_ids = (
                    summary.get("covered_requirement_ids")
                    if isinstance(summary.get("covered_requirement_ids"), list)
                    else []
                )
                missing_ids = (
                    summary.get("missing_requirement_ids")
                    if isinstance(summary.get("missing_requirement_ids"), list)
                    else []
                )
                evidence_count = int(summary.get("authority_evidence_count") or len(evidence_items))
                freshness_window_count = int(
                    summary.get("freshness_window_count") or _authority_freshness_window_count(evidence_items)
                )
                missing_freshness_count = int(
                    summary.get("missing_freshness_count") or max(evidence_count - freshness_window_count, 0)
                )
                missing_requirement_count = int(summary.get("missing_requirement_count") or 0)
                production_claimed = payload.get("mode") == "production-dossier"
                production_ready = production_claimed and missing_requirement_count == 0 and missing_freshness_count == 0
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO authority_dossiers(
                        dossier_id, entry_id, entry_type, dossier_hash, dossier_ref,
                        mode, environment, authority_ref, producer_ref,
                        production_claimed, production_ready,
                        required_requirement_count, covered_requirement_count,
                        missing_requirement_count, authority_evidence_count,
                        freshness_window_count, missing_freshness_count,
                        control_summary_json, covered_requirement_ids_json,
                        missing_requirement_ids_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id"),
                        entry["entry_id"],
                        entry.get("entry_type"),
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("dossier_ref"),
                        payload.get("mode"),
                        payload.get("environment"),
                        payload.get("authority_ref"),
                        payload.get("producer_ref"),
                        1 if production_claimed else 0,
                        1 if production_ready else 0,
                        int(summary.get("required_requirement_count") or 0),
                        int(summary.get("covered_requirement_count") or 0),
                        missing_requirement_count,
                        evidence_count,
                        freshness_window_count,
                        missing_freshness_count,
                        _json(control_summary),
                        _json(covered_ids),
                        _json(missing_ids),
                        payload.get("generated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["authority_dossiers"] += 1
        self.conn.commit()
        return counts

    def index_proof_pack(self, proof_pack: dict[str, Any], path: str | Path | None = None) -> None:
        if proof_pack.get("spec_version") != PROOF_PACK_SPEC_VERSION:
            raise ValueError(f"unsupported proof pack: {proof_pack.get('spec_version')}")
        decision = proof_pack.get("gate_decision", {})
        agent = decision.get("agent", {})
        self.conn.execute(
            """
            INSERT OR REPLACE INTO proof_packs(
                pack_id, spec_version, contract_hash, contract_id, agent_name,
                agent_version, outcome, issued_at, path, body_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proof_pack["pack_id"],
                proof_pack["spec_version"],
                proof_pack.get("contract", {}).get("hash"),
                decision.get("contract_id"),
                agent.get("name"),
                agent.get("version"),
                decision.get("outcome"),
                proof_pack.get("issued_at"),
                str(path) if path else None,
                _json(proof_pack),
            ),
        )
        self.conn.commit()

    def summary(self) -> dict[str, Any]:
        counts = {
            table: self.conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
            for table in INDEX_TABLES
        }
        latest_anchor = self.conn.execute(
            "SELECT anchor_id, tree_root, tree_size, published_at FROM anchors ORDER BY published_at DESC LIMIT 1"
        ).fetchone()
        latest_pack = self.conn.execute(
            "SELECT pack_id, contract_id, outcome, issued_at FROM proof_packs ORDER BY issued_at DESC LIMIT 1"
        ).fetchone()
        latest_eval_run = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name, agent_version,
                   results_hash, evaluated_at
            FROM eval_runs
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_gate_decision = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name, agent_version,
                   outcome, passed, failed_check_count, holdout_passed,
                   approvals_passed, evaluated_at
            FROM gate_decisions
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_gate_decision_dict = dict(latest_gate_decision) if latest_gate_decision else None
        if latest_gate_decision_dict is not None:
            latest_gate_decision_dict["passed"] = bool(latest_gate_decision_dict["passed"])
            if latest_gate_decision_dict.get("holdout_passed") is not None:
                latest_gate_decision_dict["holdout_passed"] = bool(latest_gate_decision_dict["holdout_passed"])
            if latest_gate_decision_dict.get("approvals_passed") is not None:
                latest_gate_decision_dict["approvals_passed"] = bool(latest_gate_decision_dict["approvals_passed"])
        latest_human_approval = self.conn.execute(
            """
            SELECT entry_id, approval_hash, contract_id, contract_hash,
                   agent_name, agent_version, role, approver, source,
                   external_ref, approved_at
            FROM human_approvals
            ORDER BY approved_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_demotion = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, from_environment, to_environment,
                   reason, triggering_entry_id, decided_at
            FROM promotion_demotions
            ORDER BY decided_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_rollback = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, target_agent_version, reason,
                   triggering_entry_id, decided_at
            FROM promotion_rollbacks
            ORDER BY decided_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_soak_demotion = self.conn.execute(
            """
            SELECT receipt_id, entry_id, contract_id, contract_hash,
                   agent_name, agent_version, soak_report_entry_id,
                   demotion_entry_id, violation_count, passed, attested_at
            FROM soak_demotion_receipts
            ORDER BY attested_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_soak_demotion_dict = dict(latest_soak_demotion) if latest_soak_demotion else None
        if latest_soak_demotion_dict is not None:
            _bool_fields(latest_soak_demotion_dict, "passed")
        latest_delegation = self.conn.execute(
            """
            SELECT entry_id, delegation_hash, contract_hash, parent_agent_ref,
                   child_agent_ref, reason, delegated_at
            FROM agent_delegations
            ORDER BY delegated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_delegation_graph = self.conn.execute(
            """
            SELECT delegation_graph_id, entry_id, delegation_graph_hash,
                   contract_hash, contract_hash_filter, root_agent_filter,
                   node_count, edge_count, max_depth, cycle_detected,
                   root_agents_json, leaf_agents_json, missing_inventory_json,
                   contract_hashes_json, agent_refs_json, generated_at
            FROM agent_delegation_graphs
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_delegation_graph_dict = dict(latest_delegation_graph) if latest_delegation_graph else None
        if latest_delegation_graph_dict is not None:
            _bool_fields(latest_delegation_graph_dict, "cycle_detected")
            latest_delegation_graph_dict["root_agents"] = _decode_json_array(latest_delegation_graph_dict.pop("root_agents_json", None))
            latest_delegation_graph_dict["leaf_agents"] = _decode_json_array(latest_delegation_graph_dict.pop("leaf_agents_json", None))
            latest_delegation_graph_dict["missing_inventory"] = _decode_json_array(latest_delegation_graph_dict.pop("missing_inventory_json", None))
            latest_delegation_graph_dict["contract_hashes"] = _decode_json_array(latest_delegation_graph_dict.pop("contract_hashes_json", None))
            latest_delegation_graph_dict["agent_refs"] = _decode_json_array(latest_delegation_graph_dict.pop("agent_refs_json", None))
        latest_ingest_event = self.conn.execute(
            """
            SELECT entry_id, event_hash, contract_hash, trace_id, span_id,
                   event_name, agent_name, agent_version, risk_class, observed_at
            FROM ingest_events
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_mcp_tool_call = self.conn.execute(
            """
            SELECT entry_id, session_id, request_id, tool_name,
                   contract_hash, agent_name, agent_version, risk_class,
                   transcript_sequence, transcript_call_count,
                   transcript_root, observed_at
            FROM mcp_tool_calls
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_mcp_proxy_capture = self.conn.execute(
            """
            SELECT capture_id, entry_id, proxy_ref, upstream_ref, session_id,
                   contract_hash, agent_name, agent_version, risk_class,
                   event_count, tool_call_count, event_chain_root,
                   transcript_root, captured_at
            FROM mcp_proxy_captures
            ORDER BY captured_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_self_serve_onboarding = self.conn.execute(
            """
            SELECT receipt_id, entry_id, receipt_hash, onboarding_ref,
                   tenant_ref, agent_ref, requester_ref, environment,
                   sdk_scope, gateway_mode, source_artifact_count,
                   quickstart_step_count, quickstart_replay_count,
                   control_passed_count, control_not_applicable_count,
                   control_failed_count, generated_at, control_summary_json
            FROM self_serve_onboarding_receipts
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_self_serve_onboarding_dict = dict(latest_self_serve_onboarding) if latest_self_serve_onboarding else None
        if latest_self_serve_onboarding_dict is not None:
            latest_self_serve_onboarding_dict["control_summary"] = _decode_json_object(
                latest_self_serve_onboarding_dict.pop("control_summary_json", None)
            )
        latest_framework_matrix = self.conn.execute(
            """
            SELECT matrix_id, entry_id, matrix_hash, matrix_ref,
                   adapter_package_version, row_count, framework_count,
                   production_certified_count, total_fixture_events, issued_at
            FROM framework_adapter_matrices
            ORDER BY issued_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_framework_release = self.conn.execute(
            """
            SELECT release_id, entry_id, release_hash, release_ref,
                   matrix_id, matrix_hash, row_count, framework_count,
                   production_certified_count, released_at
            FROM framework_hook_releases
            ORDER BY released_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_framework_operation = self.conn.execute(
            """
            SELECT operation_id, entry_id, mode, environment, contract_hash,
                   agent_name, agent_version, risk_class, framework,
                   runtime_package, runtime_version, source_trace_id,
                   event_count, captured_at
            FROM framework_hook_operations
            ORDER BY captured_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_framework_authority = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, dossier_ref, mode,
                   environment, authority_ref, producer_ref, matrix_id,
                   release_id, production_claimed, production_ready,
                   covered_requirement_count, required_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   missing_freshness_count, generated_at
            FROM framework_adapter_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_framework_authority_dict = dict(latest_framework_authority) if latest_framework_authority else None
        if latest_framework_authority_dict is not None:
            _bool_fields(latest_framework_authority_dict, "production_claimed", "production_ready")
        latest_supervised_access = self.conn.execute(
            """
            SELECT receipt_id, entry_id, receipt_hash, session_id,
                   audience_type, audience_purpose, reviewer_subject_ref,
                   reviewer_organization, reviewer_role, artifact_count,
                   issued_at, expires_at
            FROM supervised_access_receipts
            ORDER BY issued_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_regulator_acceptance = self.conn.execute(
            """
            SELECT acceptance_id, entry_id, acceptance_hash, regulator_name,
                   authority_ref, reviewer_ref, outcome, accepted,
                   examination_ref, purpose, framework, source_ref_count,
                   issued_at
            FROM regulator_acceptances
            ORDER BY issued_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_regulator_acceptance_dict = dict(latest_regulator_acceptance) if latest_regulator_acceptance else None
        if latest_regulator_acceptance_dict is not None:
            _bool_fields(latest_regulator_acceptance_dict, "accepted")
        latest_review_portal_service = self.conn.execute(
            """
            SELECT attestation_id, entry_id, attestation_hash, mode,
                   environment, service_ref, service_version, portal_kind,
                   endpoint_url, supervised_access_receipt_id, session_id,
                   audience_type, reviewer_subject_ref, reviewer_organization,
                   reviewer_role, artifact_count, source_count, attested_at
            FROM review_portal_service_attestations
            ORDER BY attested_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_review_portal_authority = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, dossier_ref, mode,
                   environment, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   service_attestation_id, service_ref, portal_kind,
                   audience_type, reviewer_subject_ref,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, generated_at
            FROM review_portal_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_review_portal_authority_dict = dict(latest_review_portal_authority) if latest_review_portal_authority else None
        if latest_review_portal_authority_dict is not None:
            _bool_fields(latest_review_portal_authority_dict, "production_claimed", "production_ready")
        latest_standards_body_evidence = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, standards_body_name,
                   program_ref, target_track, actor_ref,
                   source_artifact_count, control_count, observed_at
            FROM standards_body_evidence
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_auditor_ecosystem_evidence = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, program_ref,
                   auditor_ref, auditor_organization, authority_ref, actor_ref,
                   source_artifact_count, control_count, observed_at
            FROM auditor_ecosystem_evidence
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()

        latest_trust_network_evidence = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   party_ref, service_ref, registry_ref, marketplace_ref,
                   source_artifact_count, control_count, observed_at
            FROM trust_network_evidence
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()


        latest_provider_delivery_evidence = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   provider, service_ref, worker_ref, bundle_ref, authority_ref,
                   pack_id, contract_id, contract_hash, target_ref, provider_endpoint,
                   response_status, success, source_artifact_count, control_count,
                   observed_at
            FROM provider_delivery_evidence
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_provider_delivery_dict = dict(latest_provider_delivery_evidence) if latest_provider_delivery_evidence else None
        if latest_provider_delivery_dict:
            _bool_fields(latest_provider_delivery_dict, "success")
        latest_provider_operations_evidence = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   provider, operation_kind, service_ref, installation_ref,
                   webhook_ref, callback_ref, audit_ref, credential_ref,
                   authority_ref, target_ref, source_artifact_count,
                   control_count, observed_at
            FROM provider_operations_evidence
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_provider_operations_dict = dict(latest_provider_operations_evidence) if latest_provider_operations_evidence else None
        latest_policy_backend_evidence = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   backend_ref, engine, policy_ref, action_ref, decision_ref,
                   service_ref, worker_ref, provider_ref, bundle_ref, authority_ref,
                   credential_ref, audit_ref, response_status, allowed,
                   source_artifact_count, control_count, observed_at
            FROM policy_backend_evidence
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_policy_backend_dict = dict(latest_policy_backend_evidence) if latest_policy_backend_evidence else None
        if latest_policy_backend_dict is not None:
            _bool_fields(latest_policy_backend_dict, "allowed")
        latest_compliance_evidence = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   dossier_ref, authority_ref, producer_ref, document_id,
                   pack_id, disclosure_id, data_plane_ref, tenant_id,
                   primary_region, kms_key_region, audit_ref,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   source_artifact_count, control_count, observed_at
            FROM compliance_evidence
            ORDER BY observed_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_compliance_dict = dict(latest_compliance_evidence) if latest_compliance_evidence else None
        latest_status = self.conn.execute(
            """
            SELECT receipt_id, provider, pack_id, contract_id, gate_outcome,
                   passed, violation_count, attested_at
            FROM promotion_statuses
            ORDER BY attested_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_status_dict = dict(latest_status) if latest_status else None
        if latest_status_dict is not None:
            latest_status_dict["passed"] = bool(latest_status_dict["passed"])
        latest_runtime = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, action_id, risk_class,
                   passed, outcome, failed_check_count, attested_at
            FROM runtime_attestations
            ORDER BY attested_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_runtime_dict = dict(latest_runtime) if latest_runtime else None
        if latest_runtime_dict is not None:
            latest_runtime_dict["passed"] = bool(latest_runtime_dict["passed"])
        latest_policy_decision = self.conn.execute(
            """
            SELECT entry_id, policy_pack_id, contract_hash, passed, outcome,
                   failed_check_count, evaluated_at
            FROM policy_decisions
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_policy_decision_dict = dict(latest_policy_decision) if latest_policy_decision else None
        if latest_policy_decision_dict is not None:
            latest_policy_decision_dict["passed"] = bool(latest_policy_decision_dict["passed"])
        latest_policy_engine = self.conn.execute(
            """
            SELECT receipt_id, engine_name, engine_mode, policy_pack_id,
                   decision_outcome, decision_passed, evaluated_at
            FROM policy_engine_receipts
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_policy_engine_dict = dict(latest_policy_engine) if latest_policy_engine else None
        if latest_policy_engine_dict is not None and latest_policy_engine_dict.get("decision_passed") is not None:
            latest_policy_engine_dict["decision_passed"] = bool(latest_policy_engine_dict["decision_passed"])
        latest_incident = self.conn.execute(
            """
            SELECT incident_id, contract_hash, agent_name, severity, summary, detected_at
            FROM incidents
            ORDER BY detected_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_roadmap_audit = self.conn.execute(
            """
            SELECT audit_id, audit_hash, completion_position, requirement_count,
                   implemented_local_count, reference_attested_count,
                   missing_local_evidence_count, deferred_external_count,
                   generated_at
            FROM roadmap_audits
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_collection_run = self.conn.execute(
            """
            SELECT run_id, run_hash, source_map_hash, manifest_ref,
                   manifest_hash, audit_id, audit_hash, require_fresh,
                   require_live_source_uris, require_source_snapshot_artifacts,
                   require_fresh_source_snapshot_artifacts, collected_count,
                   task_count, freshness_checked_at
            FROM external_evidence_collection_runs
            ORDER BY freshness_checked_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_collection_run_dict = dict(latest_collection_run) if latest_collection_run else None
        if latest_collection_run_dict is not None:
            _bool_fields(
                latest_collection_run_dict,
                "require_fresh",
                "require_live_source_uris",
                "require_source_snapshot_artifacts",
                "require_fresh_source_snapshot_artifacts",
            )
        latest_external_evidence = self.conn.execute(
            """
            SELECT manifest_id, manifest_ref, status, require_complete,
                   require_fresh, require_live_source_uris,
                   covered_requirement_count, required_requirement_count,
                   missing_requirement_count, covered_authority_kind_count,
                   required_authority_kind_count, missing_authority_kind_count,
                   freshness_checked_at
            FROM external_evidence_manifests
            ORDER BY freshness_checked_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_external_evidence_dict = dict(latest_external_evidence) if latest_external_evidence else None
        if latest_external_evidence_dict is not None:
            _bool_fields(latest_external_evidence_dict, "require_complete", "require_fresh", "require_live_source_uris")
        latest_authority_dossier = self.conn.execute(
            """
            SELECT dossier_id, entry_type, dossier_ref, mode, environment,
                   authority_ref, producer_ref, production_claimed,
                   production_ready, covered_requirement_count,
                   required_requirement_count, missing_requirement_count,
                   authority_evidence_count, freshness_window_count,
                   missing_freshness_count, generated_at
            FROM authority_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_authority_dossier_dict = dict(latest_authority_dossier) if latest_authority_dossier else None
        if latest_authority_dossier_dict is not None:
            _bool_fields(latest_authority_dossier_dict, "production_claimed", "production_ready")
        latest_byoc_operator = self.conn.execute(
            """
            SELECT attestation_id, entry_id, attestation_hash, mode,
                   environment, deployment_manifest_id, deployment_name,
                   operator_ref, operator_version, operator_image_digest,
                   namespace, tenant_id, customer_account_ref, data_plane_ref,
                   object_lock_bucket_ref, object_lock_enabled,
                   versioning_enabled, legal_hold_required, legal_hold_active,
                   backup_policy_ref, restore_test_ref, private_endpoint,
                   audit_log_ref, source_artifact_count, control_summary_json,
                   attested_at
            FROM byoc_operator_attestations
            ORDER BY attested_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_byoc_operator_dict = dict(latest_byoc_operator) if latest_byoc_operator else None
        if latest_byoc_operator_dict is not None:
            _bool_fields(
                latest_byoc_operator_dict,
                "object_lock_enabled",
                "versioning_enabled",
                "legal_hold_required",
                "legal_hold_active",
                "private_endpoint",
            )
            latest_byoc_operator_dict["control_summary"] = _decode_json_object(
                latest_byoc_operator_dict.pop("control_summary_json", None)
            )
        latest_byoc_authority = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, mode, environment,
                   dossier_ref, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   deployment_manifest_id, deployment_environment,
                   byoc_operator_attestation_id, operator_ref,
                   operator_image_digest, namespace, object_lock_bucket_ref,
                   customer_account_ref, data_plane_ref,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, authority_artifact_count,
                   authority_artifact_requirement_count, control_summary_json,
                   generated_at
            FROM byoc_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_byoc_authority_dict = dict(latest_byoc_authority) if latest_byoc_authority else None
        if latest_byoc_authority_dict is not None:
            _bool_fields(latest_byoc_authority_dict, "production_claimed", "production_ready")
            latest_byoc_authority_dict["control_summary"] = _decode_json_object(
                latest_byoc_authority_dict.pop("control_summary_json", None)
            )
        latest_phase_scoreboard = self.conn.execute(
            """
            SELECT scoreboard_id, scoreboard_hash, scoreboard_ref, mode,
                   environment, milestone_count, phase_counts_json,
                   control_summary_json, generated_at
            FROM phase_scoreboards
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_phase_scoreboard_dict = dict(latest_phase_scoreboard) if latest_phase_scoreboard else None
        if latest_phase_scoreboard_dict is not None:
            latest_phase_scoreboard_dict["phase_counts"] = _decode_json_object(latest_phase_scoreboard_dict.pop("phase_counts_json", None))
            latest_phase_scoreboard_dict["control_summary"] = _decode_json_object(latest_phase_scoreboard_dict.pop("control_summary_json", None))
        latest_design_partner_dossier = self.conn.execute(
            """
            SELECT dossier_id, dossier_hash, dossier_ref, mode, environment,
                   partner_count, signed_partner_count, signed_pilot_value_usd,
                   external_scrutiny_survival_count, source_artifact_count,
                   control_summary_json, generated_at
            FROM design_partner_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_design_partner_dossier_dict = dict(latest_design_partner_dossier) if latest_design_partner_dossier else None
        if latest_design_partner_dossier_dict is not None:
            latest_design_partner_dossier_dict["control_summary"] = _decode_json_object(latest_design_partner_dossier_dict.pop("control_summary_json", None))
        latest_own_compliance_dossier = self.conn.execute(
            """
            SELECT dossier_id, dossier_hash, dossier_ref, scope_ref, mode,
                   environment, evidence_count,
                   required_certification_evidence_count, source_artifact_count,
                   control_summary_json, generated_at
            FROM own_compliance_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_own_compliance_dossier_dict = dict(latest_own_compliance_dossier) if latest_own_compliance_dossier else None
        if latest_own_compliance_dossier_dict is not None:
            latest_own_compliance_dossier_dict["control_summary"] = _decode_json_object(latest_own_compliance_dossier_dict.pop("control_summary_json", None))
        latest_product_scope_decision = self.conn.execute(
            """
            SELECT decision_id, entry_id, decision_hash, decision_ref,
                   decision, feature_title, proof_impacts_json,
                   anti_focus_flags_json, control_summary_json, generated_at
            FROM product_scope_decisions
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_product_scope_decision_dict = dict(latest_product_scope_decision) if latest_product_scope_decision else None
        if latest_product_scope_decision_dict is not None:
            latest_product_scope_decision_dict["proof_impacts"] = _decode_json_array(latest_product_scope_decision_dict.pop("proof_impacts_json", None))
            latest_product_scope_decision_dict["anti_focus_flags"] = _decode_json_array(latest_product_scope_decision_dict.pop("anti_focus_flags_json", None))
            latest_product_scope_decision_dict["control_summary"] = _decode_json_object(latest_product_scope_decision_dict.pop("control_summary_json", None))
        latest_vertical_pack = self.conn.execute(
            """
            SELECT pack_id, entry_id, pack_hash, pack_ref, vertical, title,
                   producer_ref, reviewer_ref, environment, risk_classes_json,
                   frameworks_json, source_artifact_count,
                   external_requirement_count, control_summary_json, generated_at
            FROM vertical_packs
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_vertical_pack_dict = dict(latest_vertical_pack) if latest_vertical_pack else None
        if latest_vertical_pack_dict is not None:
            latest_vertical_pack_dict["risk_classes"] = _decode_json_array(latest_vertical_pack_dict.pop("risk_classes_json", None))
            latest_vertical_pack_dict["frameworks"] = _decode_json_array(latest_vertical_pack_dict.pop("frameworks_json", None))
            latest_vertical_pack_dict["control_summary"] = _decode_json_object(latest_vertical_pack_dict.pop("control_summary_json", None))
        latest_reliability_report = self.conn.execute(
            """
            SELECT report_id, entry_id, report_hash, report_ref, mode,
                   reporting_period_json, cohort_count, source_product_count,
                   incident_rate_per_100k_actions, gate_pass_rate_bps,
                   control_summary_json, generated_at
            FROM reliability_reports
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_reliability_report_dict = dict(latest_reliability_report) if latest_reliability_report else None
        if latest_reliability_report_dict is not None:
            latest_reliability_report_dict["reporting_period"] = _decode_json_object(latest_reliability_report_dict.pop("reporting_period_json", None))
            latest_reliability_report_dict["control_summary"] = _decode_json_object(latest_reliability_report_dict.pop("control_summary_json", None))
        latest_underwriting_quote = self.conn.execute(
            """
            SELECT quote_id, entry_id, quote_hash, underwriter_name,
                   underwriter_mode, product, quote_ref, status, currency,
                   coverage_limit_usd, base_premium_usd, discount_percent,
                   quoted_premium_usd, term_start, term_end, consent_id,
                   consent_active, pack_id, contract_id, chain_root,
                   risk_score, risk_tier, gate_outcome, issued_at
            FROM underwriting_quotes
            ORDER BY issued_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_underwriting_quote_dict = dict(latest_underwriting_quote) if latest_underwriting_quote else None
        if latest_underwriting_quote_dict is not None:
            _bool_fields(latest_underwriting_quote_dict, "consent_active")
        latest_insurer_authority = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, mode, environment,
                   dossier_ref, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   service_attestation_id, service_ref, partner_api_endpoint,
                   underwriter, quote_id, quote_ref, consent_id, risk_tier,
                   worker_receipt_count, worker_bundle_count,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, control_summary_json,
                   generated_at
            FROM insurer_partner_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_insurer_authority_dict = dict(latest_insurer_authority) if latest_insurer_authority else None
        if latest_insurer_authority_dict is not None:
            _bool_fields(latest_insurer_authority_dict, "production_claimed", "production_ready")
            latest_insurer_authority_dict["control_summary"] = _decode_json_object(
                latest_insurer_authority_dict.pop("control_summary_json", None)
            )
        latest_vendor_identity = self.conn.execute(
            """
            SELECT receipt_id, entry_id, receipt_hash, vendor_name, legal_name,
                   subject_ref, domain, identity_provider, identity_id,
                   proof_pack_count, trust_network_manifest_id, issued_at,
                   expires_at
            FROM vendor_identity_receipts
            ORDER BY issued_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_identity_attestation = self.conn.execute(
            """
            SELECT attestation_id, entry_id, attestation_hash, provider,
                   authentication_method, tenant_ref, observed_at, source,
                   subject_ref, identity_provider, identity_id,
                   identity_record_hash, agent_name, agent_version,
                   vendor_receipt_id, source_artifact_count, issued_at
            FROM identity_provider_attestations
            ORDER BY issued_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_identity_session = self.conn.execute(
            """
            SELECT session_id, entry_id, session_hash, provider, mode,
                   environment, attestation_id, session_ref, event_kind,
                   provider_event_id, identity_provider, identity_id,
                   decision, risk_level, response_status, success,
                   session_log_ref, audit_log_ref, recorded_at
            FROM identity_provider_sessions
            ORDER BY recorded_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_identity_session_dict = dict(latest_identity_session) if latest_identity_session else None
        if latest_identity_session_dict is not None:
            _bool_fields(latest_identity_session_dict, "success")
        latest_identity_operation = self.conn.execute(
            """
            SELECT operation_id, entry_id, operation_hash, provider, mode,
                   environment, attestation_id, source_session_id,
                   operation_kind, operation_ref, provider_operation_id,
                   identity_provider, identity_id, target_state, outcome,
                   success, response_status, system_log_ref, audit_log_ref,
                   recorded_at, control_summary_json
            FROM identity_provider_lifecycle_operations
            ORDER BY recorded_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_identity_operation_dict = dict(latest_identity_operation) if latest_identity_operation else None
        if latest_identity_operation_dict is not None:
            _bool_fields(latest_identity_operation_dict, "success")
            latest_identity_operation_dict["control_summary"] = _decode_json_object(latest_identity_operation_dict.pop("control_summary_json", None))
        latest_identity_worker = self.conn.execute(
            """
            SELECT worker_operation_id, entry_id, worker_operation_hash,
                   provider, mode, environment, source_operation_id,
                   source_operation_hash, identity_id, operation_kind,
                   worker_ref, run_ref, worker_success, schedule_ref,
                   queue_ref, destination_ref, response_status,
                   propagation_log_ref, audit_log_ref, recorded_at,
                   control_summary_json
            FROM identity_provider_lifecycle_workers
            ORDER BY recorded_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_identity_worker_dict = dict(latest_identity_worker) if latest_identity_worker else None
        if latest_identity_worker_dict is not None:
            _bool_fields(latest_identity_worker_dict, "worker_success")
            latest_identity_worker_dict["control_summary"] = _decode_json_object(latest_identity_worker_dict.pop("control_summary_json", None))
        latest_identity_authority = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, mode, environment,
                   dossier_ref, authority_ref, producer_ref,
                   production_claimed, production_ready, worker_operation_id,
                   provider, identity_id, operation_kind, worker_ref,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, generated_at,
                   control_summary_json
            FROM identity_provider_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_identity_authority_dict = dict(latest_identity_authority) if latest_identity_authority else None
        if latest_identity_authority_dict is not None:
            _bool_fields(latest_identity_authority_dict, "production_claimed", "production_ready")
            latest_identity_authority_dict["control_summary"] = _decode_json_object(latest_identity_authority_dict.pop("control_summary_json", None))
        latest_temporal_holdout_manifest = self.conn.execute(
            """
            SELECT manifest_id, entry_id, run_id, dataset_id, contract_id,
                   contract_hash, candidate_version, record_count,
                   violation_count, passed, earliest_record_timestamp,
                   latest_record_timestamp, generated_at
            FROM temporal_holdout_manifests
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_temporal_holdout_manifest_dict = dict(latest_temporal_holdout_manifest) if latest_temporal_holdout_manifest else None
        if latest_temporal_holdout_manifest_dict is not None:
            _bool_fields(latest_temporal_holdout_manifest_dict, "passed")
        latest_shadow_replay = self.conn.execute(
            """
            SELECT entry_id, run_id, contract_id, contract_hash,
                   candidate_version, records_checked, passed, outcome,
                   holdout_passed, holdout_error_count, failed_check_count,
                   temporal_holdout_manifest_id, evaluated_at
            FROM shadow_replays
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_shadow_replay_dict = dict(latest_shadow_replay) if latest_shadow_replay else None
        if latest_shadow_replay_dict is not None:
            _bool_fields(latest_shadow_replay_dict, "passed", "holdout_passed")
        latest_soak_report = self.conn.execute(
            """
            SELECT entry_id, report_id, contract_id, contract_hash,
                   candidate_version, window_count, incident_count,
                   drift_alarm_count, blocking_drift_alarm_count, passed,
                   outcome, failed_check_count, evaluated_at
            FROM soak_reports
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_soak_report_dict = dict(latest_soak_report) if latest_soak_report else None
        if latest_soak_report_dict is not None:
            _bool_fields(latest_soak_report_dict, "passed")
        latest_traffic_holdout_export = self.conn.execute(
            """
            SELECT export_id, entry_id, export_ref, source_ref, exporter_ref,
                   contract_id, contract_hash, candidate_version,
                   record_count, violation_count, passed,
                   earliest_record_timestamp, latest_record_timestamp,
                   produced_at
            FROM traffic_holdout_exports
            ORDER BY produced_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_traffic_holdout_export_dict = dict(latest_traffic_holdout_export) if latest_traffic_holdout_export else None
        if latest_traffic_holdout_export_dict is not None:
            _bool_fields(latest_traffic_holdout_export_dict, "passed")
        latest_traffic_completeness_receipt = self.conn.execute(
            """
            SELECT completeness_id, entry_id, mode, authority_ref, export_id,
                   contract_id, contract_hash, candidate_version,
                   record_count, violation_count, passed, produced_at
            FROM traffic_completeness_receipts
            ORDER BY produced_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_traffic_completeness_receipt_dict = dict(latest_traffic_completeness_receipt) if latest_traffic_completeness_receipt else None
        if latest_traffic_completeness_receipt_dict is not None:
            _bool_fields(latest_traffic_completeness_receipt_dict, "passed")
        return {
            "schema_version": SCHEMA_VERSION,
            "database": str(self.path),
            "locking_mode": "nolock" if self.uses_nolock else "normal",
            "indexed_at": utc_now(),
            "counts": counts,
            "latest_anchor": dict(latest_anchor) if latest_anchor else None,
            "latest_proof_pack": dict(latest_pack) if latest_pack else None,
            "latest_eval_run": dict(latest_eval_run) if latest_eval_run else None,
            "latest_gate_decision": latest_gate_decision_dict,
            "latest_human_approval": dict(latest_human_approval) if latest_human_approval else None,
            "latest_promotion_demotion": dict(latest_demotion) if latest_demotion else None,
            "latest_promotion_rollback": dict(latest_rollback) if latest_rollback else None,
            "latest_soak_demotion_receipt": latest_soak_demotion_dict,
            "latest_agent_delegation": dict(latest_delegation) if latest_delegation else None,
            "latest_agent_delegation_graph": latest_delegation_graph_dict,
            "latest_ingest_event": dict(latest_ingest_event) if latest_ingest_event else None,
            "latest_mcp_tool_call": dict(latest_mcp_tool_call) if latest_mcp_tool_call else None,
            "latest_mcp_proxy_capture": dict(latest_mcp_proxy_capture) if latest_mcp_proxy_capture else None,
            "latest_self_serve_onboarding_receipt": latest_self_serve_onboarding_dict,
            "latest_framework_adapter_matrix": dict(latest_framework_matrix) if latest_framework_matrix else None,
            "latest_framework_hook_release": dict(latest_framework_release) if latest_framework_release else None,
            "latest_framework_hook_operation": dict(latest_framework_operation) if latest_framework_operation else None,
            "latest_framework_adapter_authority_dossier": latest_framework_authority_dict,
            "latest_supervised_access_receipt": dict(latest_supervised_access) if latest_supervised_access else None,
            "latest_regulator_acceptance": latest_regulator_acceptance_dict,
            "latest_review_portal_service_attestation": dict(latest_review_portal_service) if latest_review_portal_service else None,
            "latest_review_portal_authority_dossier": latest_review_portal_authority_dict,
            "latest_standards_body_evidence": dict(latest_standards_body_evidence) if latest_standards_body_evidence else None,
            "latest_auditor_ecosystem_evidence": dict(latest_auditor_ecosystem_evidence) if latest_auditor_ecosystem_evidence else None,
            "latest_trust_network_evidence": dict(latest_trust_network_evidence) if latest_trust_network_evidence else None,
            "latest_provider_delivery_evidence": latest_provider_delivery_dict,
            "latest_provider_operations_evidence": latest_provider_operations_dict,
            "latest_policy_backend_evidence": latest_policy_backend_dict,
            "latest_compliance_evidence": latest_compliance_dict,
            "latest_promotion_status": latest_status_dict,
            "latest_runtime_attestation": latest_runtime_dict,
            "latest_policy_decision": latest_policy_decision_dict,
            "latest_policy_engine_receipt": latest_policy_engine_dict,
            "latest_incident": dict(latest_incident) if latest_incident else None,
            "latest_roadmap_audit": dict(latest_roadmap_audit) if latest_roadmap_audit else None,
            "latest_external_evidence_collection_run": latest_collection_run_dict,
            "latest_external_evidence_manifest": latest_external_evidence_dict,
            "latest_authority_dossier": latest_authority_dossier_dict,
            "latest_byoc_operator_attestation": latest_byoc_operator_dict,
            "latest_byoc_authority_dossier": latest_byoc_authority_dict,
            "latest_vendor_identity_receipt": dict(latest_vendor_identity) if latest_vendor_identity else None,
            "latest_identity_provider_attestation": dict(latest_identity_attestation) if latest_identity_attestation else None,
            "latest_identity_provider_session": latest_identity_session_dict,
            "latest_identity_provider_lifecycle_operation": latest_identity_operation_dict,
            "latest_identity_provider_lifecycle_worker": latest_identity_worker_dict,
            "latest_identity_provider_authority_dossier": latest_identity_authority_dict,
            "latest_phase_scoreboard": latest_phase_scoreboard_dict,
            "latest_design_partner_dossier": latest_design_partner_dossier_dict,
            "latest_own_compliance_dossier": latest_own_compliance_dossier_dict,
            "latest_product_scope_decision": latest_product_scope_decision_dict,
            "latest_vertical_pack": latest_vertical_pack_dict,
            "latest_reliability_report": latest_reliability_report_dict,
            "latest_underwriting_quote": latest_underwriting_quote_dict,
            "latest_insurer_partner_authority_dossier": latest_insurer_authority_dict,
            "latest_temporal_holdout_manifest": latest_temporal_holdout_manifest_dict,
            "latest_shadow_replay": latest_shadow_replay_dict,
            "latest_soak_report": latest_soak_report_dict,
            "latest_traffic_holdout_export": latest_traffic_holdout_export_dict,
            "latest_traffic_completeness_receipt": latest_traffic_completeness_receipt_dict,
        }

    def contracts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT contract_hash, contract_id, version, agent_name, agent_version,
                   registered_entry_id, created_at
            FROM contracts
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_eval_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name, agent_version,
                   results_hash, evaluated_at
            FROM eval_runs
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_gate_decisions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name, agent_version,
                   outcome, passed, eval_entry_id, contract_entry_id, results_hash,
                   check_count, failed_check_count, holdout_passed, approvals_passed,
                   evaluated_at
            FROM gate_decisions
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        decisions = []
        for row in rows:
            item = dict(row)
            item["passed"] = bool(item["passed"])
            if item.get("holdout_passed") is not None:
                item["holdout_passed"] = bool(item["holdout_passed"])
            if item.get("approvals_passed") is not None:
                item["approvals_passed"] = bool(item["approvals_passed"])
            decisions.append(item)
        return decisions

    def recent_human_approvals(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, approval_hash, contract_id, contract_hash,
                   agent_name, agent_version, role, approver, source,
                   external_ref, approved_at, metadata_json
            FROM human_approvals
            ORDER BY approved_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["metadata"] = _decode_json_object(item.pop("metadata_json", None))
            items.append(item)
        return items

    def recent_promotion_demotions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, from_environment, to_environment,
                   reason, triggering_entry_id, trigger_json, decided_at
            FROM promotion_demotions
            ORDER BY decided_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["trigger"] = _decode_json_object(item.pop("trigger_json", None))
            items.append(item)
        return items

    def recent_promotion_rollbacks(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, target_agent_version, reason,
                   triggering_entry_id, decided_at
            FROM promotion_rollbacks
            ORDER BY decided_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_soak_demotion_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT receipt_id, entry_id, receipt_hash, contract_id,
                   contract_hash, agent_name, agent_version,
                   soak_report_entry_id, demotion_entry_id,
                   source_json, violation_count, passed, attested_at
            FROM soak_demotion_receipts
            ORDER BY attested_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "passed")
            item["source"] = _decode_json_object(item.pop("source_json", None))
            items.append(item)
        return items

    def recent_proof_packs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT pack_id, contract_id, agent_name, agent_version, outcome, issued_at, path
            FROM proof_packs
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_agent_delegations(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, delegation_hash, contract_hash,
                   parent_agent_name, parent_agent_version, parent_agent_ref,
                   child_agent_name, child_agent_version, child_agent_ref,
                   reason, scope_json, delegated_at, delegation_json
            FROM agent_delegations
            ORDER BY delegated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["scope"] = _decode_json_object(item.pop("scope_json", None))
            item["delegation"] = _decode_json_object(item.pop("delegation_json", None))
            items.append(item)
        return items

    def recent_agent_delegation_graphs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT delegation_graph_id, entry_id, delegation_graph_hash,
                   contract_hash, contract_hash_filter, root_agent_filter,
                   source_chain_tenant_id, source_chain_entry_count,
                   node_count, edge_count, max_depth, cycle_detected,
                   root_agents_json, leaf_agents_json, missing_inventory_json,
                   contract_hashes_json, agent_refs_json, node_root, edge_root,
                   filters_json, source_chain_json, summary_json, generated_at
            FROM agent_delegation_graphs
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "cycle_detected")
            item["root_agents"] = _decode_json_array(item.pop("root_agents_json", None))
            item["leaf_agents"] = _decode_json_array(item.pop("leaf_agents_json", None))
            item["missing_inventory"] = _decode_json_array(item.pop("missing_inventory_json", None))
            item["contract_hashes"] = _decode_json_array(item.pop("contract_hashes_json", None))
            item["agent_refs"] = _decode_json_array(item.pop("agent_refs_json", None))
            item["filters"] = _decode_json_object(item.pop("filters_json", None))
            item["source_chain"] = _decode_json_object(item.pop("source_chain_json", None))
            item["summary"] = _decode_json_object(item.pop("summary_json", None))
            items.append(item)
        return items

    def recent_ingest_events(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, event_hash, contract_hash, trace_id, span_id,
                   parent_span_id, event_name, agent_name, agent_version,
                   risk_class, schema_url, observed_at, attributes_json
            FROM ingest_events
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["attributes"] = _decode_json_object(item.pop("attributes_json", None))
            items.append(item)
        return items

    def recent_mcp_tool_calls(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, session_id, request_id, tool_name,
                   contract_hash, agent_name, agent_version, risk_class,
                   request_hash, response_hash, tool_call_hash,
                   transcript_sequence, transcript_call_count,
                   previous_transcript_node_hash, transcript_node_hash,
                   transcript_root, observed_at
            FROM mcp_tool_calls
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_mcp_proxy_captures(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT capture_id, entry_id, proxy_ref, upstream_ref, session_id,
                   contract_hash, agent_name, agent_version, risk_class,
                   event_count, tool_call_count, event_chain_root,
                   transcript_root, proxy_events_artifact_json,
                   event_hashes_json, tool_call_hashes_json, captured_at
            FROM mcp_proxy_captures
            ORDER BY captured_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["proxy_events_artifact"] = _decode_json_object(item.pop("proxy_events_artifact_json", None))
            item["event_hashes"] = _decode_json_array(item.pop("event_hashes_json", None))
            item["tool_call_hashes"] = _decode_json_array(item.pop("tool_call_hashes_json", None))
            items.append(item)
        return items

    def recent_self_serve_onboarding_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT receipt_id, entry_id, receipt_hash, onboarding_ref,
                   tenant_ref, agent_ref, requester_ref, environment,
                   sdk_scope, gateway_mode, source_artifact_count,
                   quickstart_step_count, quickstart_replay_count,
                   control_passed_count, control_not_applicable_count,
                   control_failed_count, generated_at, control_summary_json,
                   body_json
            FROM self_serve_onboarding_receipts
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["body"] = _decode_json_object(item.pop("body_json", None))
            items.append(item)
        return items
    def recent_promotion_statuses(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT receipt_id, provider, pack_id, contract_id, contract_hash,
                   agent_name, agent_version, gate_outcome, passed,
                   provider_status_kind, provider_status_success,
                   target_ref_json, violation_count, attested_at
            FROM promotion_statuses
            ORDER BY attested_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        statuses = []
        for row in rows:
            item = dict(row)
            item["passed"] = bool(item["passed"])
            if item.get("provider_status_success") is not None:
                item["provider_status_success"] = bool(item["provider_status_success"])
            item["target_ref"] = _decode_json_object(item.pop("target_ref_json", None))
            statuses.append(item)
        return statuses

    def recent_runtime_attestations(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, action_hash, action_id,
                   action_type, risk_class, passed, outcome, check_count,
                   failed_check_count, attested_at
            FROM runtime_attestations
            ORDER BY attested_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["passed"] = bool(item["passed"])
            items.append(item)
        return items

    def recent_policy_decisions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, policy_pack_id, policy_pack_version, policy_pack_hash,
                   contract_hash, action_hash, passed, outcome, matched_rule_count,
                   check_count, failed_check_count, evaluated_at
            FROM policy_decisions
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["passed"] = bool(item["passed"])
            items.append(item)
        return items

    def recent_policy_engine_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT receipt_id, entry_id, engine_name, engine_mode, policy_pack_id,
                   policy_pack_version, policy_pack_hash, action_hash, action_id,
                   action_type, risk_class, pack_id, contract_id, contract_hash,
                   decision_entry_id, decision_outcome, decision_passed, evaluated_at
            FROM policy_engine_receipts
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            if item.get("decision_passed") is not None:
                item["decision_passed"] = bool(item["decision_passed"])
            items.append(item)
        return items

    def recent_incidents(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT incident_id, entry_id, contract_hash, agent_name, agent_version,
                   severity, summary, detected_at
            FROM incidents
            ORDER BY detected_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_roadmap_audits(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT audit_id, entry_id, audit_hash, completion_position,
                   requirement_count, implemented_local_count,
                   reference_attested_count, missing_local_evidence_count,
                   deferred_external_count, source_json, limitations_json,
                   generated_at
            FROM roadmap_audits
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["source"] = _decode_json_object(item.pop("source_json", None))
            item["limitations"] = _decode_json_array(item.pop("limitations_json", None))
            items.append(item)
        return items

    def recent_external_evidence_collection_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT run_id, entry_id, run_hash, source_map_hash, manifest_id,
                   manifest_ref, manifest_hash, audit_id, audit_hash,
                   require_fresh, require_live_source_uris,
                   require_source_snapshot_artifacts,
                   require_fresh_source_snapshot_artifacts, collected_count,
                   task_count, collected_tasks_json, snapshot_ids_json,
                   intake_ids_json, source_plan_json, source_manifest_json,
                   source_roadmap_audit_json, freshness_checked_at
            FROM external_evidence_collection_runs
            ORDER BY freshness_checked_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(
                item,
                "require_fresh",
                "require_live_source_uris",
                "require_source_snapshot_artifacts",
                "require_fresh_source_snapshot_artifacts",
            )
            item["collected_tasks"] = _decode_json_array(item.pop("collected_tasks_json", None))
            item["snapshot_ids"] = _decode_json_array(item.pop("snapshot_ids_json", None))
            item["intake_ids"] = _decode_json_array(item.pop("intake_ids_json", None))
            item["source_plan"] = _decode_json_object(item.pop("source_plan_json", None))
            item["source_manifest"] = _decode_json_object(item.pop("source_manifest_json", None))
            item["source_roadmap_audit"] = _decode_json_object(item.pop("source_roadmap_audit_json", None))
            items.append(item)
        return items

    def recent_external_evidence_manifests(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT manifest_id, entry_id, manifest_ref, manifest_hash, status,
                   require_complete, require_fresh, require_live_source_uris,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, required_authority_kind_count,
                   covered_authority_kind_count, missing_authority_kind_count,
                   evidence_count, fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, source_roadmap_audit_json,
                   missing_requirement_ids_json, freshness_checked_at, body_json
            FROM external_evidence_manifests
            ORDER BY freshness_checked_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "require_complete", "require_fresh", "require_live_source_uris")
            item["source_roadmap_audit"] = _decode_json_object(item.pop("source_roadmap_audit_json", None))
            roadmap_requirements = _roadmap_requirement_index(item["source_roadmap_audit"])
            try:
                missing_ids = json.loads(item.pop("missing_requirement_ids_json", "[]"))
            except (TypeError, json.JSONDecodeError):
                missing_ids = []
            item["missing_requirement_ids"] = missing_ids if isinstance(missing_ids, list) else []
            payload = _decode_json_object(item.pop("body_json", None))
            covered_authority_kinds = _decode_string_list_map(payload.get("covered_authority_kinds_by_requirement"))
            missing_authority_kinds = _decode_string_list_map(payload.get("missing_authority_kinds_by_requirement"))
            missing_units = _authority_gap_units(missing_authority_kinds, roadmap_requirements)
            item["covered_authority_kinds_by_requirement"] = covered_authority_kinds
            item["missing_authority_kinds_by_requirement"] = missing_authority_kinds
            item["missing_authority_units"] = missing_units
            item["external_authority_gap_summary"] = _external_authority_gap_summary(missing_units)
            items.append(item)
        return items

    def external_authority_gaps(
        self,
        *,
        authority_kind: str | None = None,
        requirement_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        if limit is not None and limit < 1:
            raise ValueError("limit must be a positive integer")
        manifests = self.recent_external_evidence_manifests(1)
        if not manifests:
            units: list[dict[str, Any]] = []
            selected_units: list[dict[str, Any]] = []
            returned_units: list[dict[str, Any]] = []
            latest_manifest = None
        else:
            latest_manifest = manifests[0]
            units = list(latest_manifest.get("missing_authority_units") or [])
            selected_units = [
                unit
                for unit in units
                if (authority_kind is None or unit.get("authority_kind") == authority_kind)
                and (requirement_id is None or unit.get("requirement_id") == requirement_id)
            ]
            returned_units = selected_units[:limit] if limit is not None else selected_units
        return {
            "schema_version": SCHEMA_VERSION,
            "filters": {
                "authority_kind": authority_kind,
                "requirement_id": requirement_id,
                "limit": limit,
            },
            "latest_external_evidence_manifest": latest_manifest,
            "summary": {
                "total_missing_authority_unit_count": len(units),
                "selected_missing_authority_unit_count": len(selected_units),
                "returned_missing_authority_unit_count": len(returned_units),
                "gap_count_by_authority_kind": _count_items_by(selected_units, "authority_kind"),
                "gap_count_by_collection_priority": _count_items_by(selected_units, "collection_priority"),
                "gap_count_by_requirement": _count_items_by(selected_units, "requirement_id"),
                "gap_count_by_requirement_phase": _count_items_by(selected_units, "requirement_phase"),
                "gap_count_by_requirement_priority": _count_items_by(selected_units, "requirement_priority"),
            },
            "missing_authority_units": returned_units,
        }

    def recent_phase_scoreboards(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT scoreboard_id, entry_id, scoreboard_hash, scoreboard_ref,
                   mode, environment, milestone_count, phase_counts_json,
                   control_summary_json, generated_at
            FROM phase_scoreboards
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["phase_counts"] = _decode_json_object(item.pop("phase_counts_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_design_partner_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, dossier_ref,
                   mode, environment, partner_count, signed_partner_count,
                   signed_pilot_value_usd, external_scrutiny_survival_count,
                   source_artifact_count, control_summary_json, generated_at
            FROM design_partner_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_own_compliance_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, dossier_ref, scope_ref,
                   mode, environment, evidence_count,
                   required_certification_evidence_count, source_artifact_count,
                   control_summary_json, generated_at
            FROM own_compliance_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_product_scope_decisions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT decision_id, entry_id, decision_hash, decision_ref,
                   decision, feature_title, proof_impacts_json,
                   anti_focus_flags_json, control_summary_json, generated_at
            FROM product_scope_decisions
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["proof_impacts"] = _decode_json_array(item.pop("proof_impacts_json", None))
            item["anti_focus_flags"] = _decode_json_array(item.pop("anti_focus_flags_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_vertical_packs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT pack_id, entry_id, pack_hash, pack_ref, vertical, title,
                   producer_ref, reviewer_ref, environment, risk_classes_json,
                   frameworks_json, source_artifact_count,
                   external_requirement_count, control_summary_json, generated_at
            FROM vertical_packs
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["risk_classes"] = _decode_json_array(item.pop("risk_classes_json", None))
            item["frameworks"] = _decode_json_array(item.pop("frameworks_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_reliability_reports(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT report_id, entry_id, report_hash, report_ref, mode,
                   reporting_period_json, cohort_count, source_product_count,
                   incident_rate_per_100k_actions, gate_pass_rate_bps,
                   control_summary_json, generated_at
            FROM reliability_reports
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["reporting_period"] = _decode_json_object(item.pop("reporting_period_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_underwriting_quotes(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT quote_id, entry_id, quote_hash, underwriter_name,
                   underwriter_mode, product, quote_ref, status, currency,
                   coverage_limit_usd, base_premium_usd, discount_percent,
                   quoted_premium_usd, term_start, term_end, consent_id,
                   consent_active, pack_id, contract_id, chain_root,
                   risk_score, risk_tier, gate_outcome, issued_at,
                   applicant_risk_json, quote_json, risk_evidence_json,
                   limitations_json
            FROM underwriting_quotes
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "consent_active")
            item["applicant_risk"] = _decode_json_object(item.pop("applicant_risk_json", None))
            item["quote"] = _decode_json_object(item.pop("quote_json", None))
            item["risk_evidence"] = _decode_json_object(item.pop("risk_evidence_json", None))
            item["limitations"] = _decode_json_array(item.pop("limitations_json", None))
            items.append(item)
        return items

    def recent_insurer_partner_authority_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, mode, environment,
                   dossier_ref, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   service_attestation_id, service_attestation_hash,
                   service_ref, partner_api_endpoint, underwriter,
                   quote_id, quote_ref, telemetry_hash, consent_id,
                   risk_tier, worker_receipt_count, worker_bundle_count,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, service_binding_json,
                   worker_receipt_bindings_json, worker_bundle_bindings_json,
                   summary_json, control_summary_json,
                   authority_evidence_json, generated_at
            FROM insurer_partner_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "production_claimed", "production_ready")
            item["service_binding"] = _decode_json_object(item.pop("service_binding_json", None))
            item["worker_receipt_bindings"] = _decode_json_array(item.pop("worker_receipt_bindings_json", None))
            item["worker_bundle_bindings"] = _decode_json_array(item.pop("worker_bundle_bindings_json", None))
            item["summary"] = _decode_json_object(item.pop("summary_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["authority_evidence"] = _decode_json_array(item.pop("authority_evidence_json", None))
            items.append(item)
        return items

    def recent_temporal_holdout_manifests(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT manifest_id, entry_id, manifest_hash, run_id, dataset_id,
                   contract_id, contract_hash, candidate_version, record_count,
                   violation_count, passed, records_root,
                   earliest_record_timestamp, latest_record_timestamp, generated_at
            FROM temporal_holdout_manifests
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [_bool_fields(dict(row), "passed") for row in rows]

    def recent_shadow_replays(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, run_id, contract_id, contract_hash,
                   candidate_version, replay_hash, records_checked, passed,
                   outcome, holdout_passed, holdout_error_count, check_count,
                   failed_check_count, temporal_holdout_manifest_id,
                   temporal_holdout_manifest_hash, evaluated_at, metrics_json
            FROM shadow_replays
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "passed", "holdout_passed")
            item["metrics"] = _decode_json_object(item.pop("metrics_json", None))
            items.append(item)
        return items

    def recent_soak_reports(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, report_id, contract_id, contract_hash,
                   candidate_version, soak_hash, window_count, incident_count,
                   drift_alarm_count, blocking_drift_alarm_count, passed,
                   outcome, check_count, failed_check_count, evaluated_at,
                   metrics_json
            FROM soak_reports
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "passed")
            item["metrics"] = _decode_json_object(item.pop("metrics_json", None))
            items.append(item)
        return items

    def recent_traffic_holdout_exports(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT export_id, entry_id, export_hash, export_ref, source_ref,
                   exporter_ref, contract_id, contract_hash, candidate_version,
                   record_count, violation_count, passed,
                   extraction_window_json, records_root,
                   earliest_record_timestamp, latest_record_timestamp,
                   produced_at
            FROM traffic_holdout_exports
            ORDER BY produced_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "passed")
            item["extraction_window"] = _decode_json_object(item.pop("extraction_window_json", None))
            items.append(item)
        return items

    def recent_traffic_completeness_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT completeness_id, entry_id, completeness_hash, mode,
                   authority_ref, export_id, export_hash, contract_id,
                   contract_hash, candidate_version, record_count,
                   violation_count, passed, source_completeness_json,
                   provider_exchange_json, produced_at
            FROM traffic_completeness_receipts
            ORDER BY produced_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "passed")
            item["source_completeness"] = _decode_json_object(item.pop("source_completeness_json", None))
            item["provider_exchange"] = _decode_json_object(item.pop("provider_exchange_json", None))
            items.append(item)
        return items

    def recent_framework_adapter_matrices(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT matrix_id, entry_id, matrix_hash, matrix_ref,
                   adapter_schema_url, adapter_package_version,
                   row_count, framework_count, production_certified_count,
                   total_fixture_events, summary_json, frameworks_json,
                   compatibility_hashes_json, issued_at
            FROM framework_adapter_matrices
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["summary"] = _decode_json_object(item.pop("summary_json", None))
            item["frameworks"] = _decode_json_array(item.pop("frameworks_json", None))
            item["compatibility_hashes"] = _decode_json_array(item.pop("compatibility_hashes_json", None))
            items.append(item)
        return items

    def recent_framework_hook_releases(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT release_id, entry_id, release_hash, release_ref,
                   matrix_id, matrix_hash, row_count, framework_count,
                   production_certified_count, adapter_matrix_json,
                   frameworks_json, hook_release_hashes_json,
                   control_summary_json, released_at
            FROM framework_hook_releases
            ORDER BY released_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["adapter_matrix"] = _decode_json_object(item.pop("adapter_matrix_json", None))
            item["frameworks"] = _decode_json_array(item.pop("frameworks_json", None))
            item["hook_release_hashes"] = _decode_json_array(item.pop("hook_release_hashes_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_framework_hook_operations(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT operation_id, entry_id, operation_hash, mode, environment,
                   operation_ref, contract_hash, agent_name, agent_version,
                   risk_class, framework, runtime_package, runtime_version,
                   hook_package, hook_version, collector_hook_ref,
                   hook_release_hash, source_trace_id, trace_id, event_count,
                   event_root, runtime_json, hook_json, release_binding_json,
                   trace_json, collector_json, control_summary_json,
                   captured_at
            FROM framework_hook_operations
            ORDER BY captured_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["runtime"] = _decode_json_object(item.pop("runtime_json", None))
            item["hook"] = _decode_json_object(item.pop("hook_json", None))
            item["release_binding"] = _decode_json_object(item.pop("release_binding_json", None))
            item["trace"] = _decode_json_object(item.pop("trace_json", None))
            item["collector"] = _decode_json_object(item.pop("collector_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_byoc_operator_attestations(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT attestation_id, entry_id, attestation_hash, mode,
                   environment, deployment_manifest_id, deployment_manifest_hash,
                   deployment_name, deployment_mode, deployment_artifact_type,
                   operator_ref, operator_version, operator_image,
                   operator_image_digest, namespace, tenant_id,
                   customer_account_ref, data_plane_ref, control_plane_ref,
                   keyring_ref, object_lock_provider, object_lock_bucket_ref,
                   object_lock_region, object_lock_enabled, versioning_enabled,
                   legal_hold_required, legal_hold_active, backup_policy_ref,
                   restore_test_ref, private_endpoint, audit_log_ref,
                   audit_log_root, source_artifact_count, control_summary_json,
                   attested_at
            FROM byoc_operator_attestations
            ORDER BY attested_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(
                item,
                "object_lock_enabled",
                "versioning_enabled",
                "legal_hold_required",
                "legal_hold_active",
                "private_endpoint",
            )
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_byoc_authority_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, mode, environment,
                   dossier_ref, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   deployment_manifest_id, deployment_manifest_hash,
                   deployment_environment, byoc_operator_attestation_id,
                   operator_ref, operator_image_digest, namespace,
                   object_lock_bucket_ref, customer_account_ref, data_plane_ref,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, authority_artifact_count,
                   authority_artifact_requirement_count, source_binding_json,
                   summary_json, artifact_summary_json, control_summary_json,
                   authority_evidence_json, authority_artifacts_json, generated_at
            FROM byoc_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "production_claimed", "production_ready")
            item["source_binding"] = _decode_json_object(item.pop("source_binding_json", None))
            item["summary"] = _decode_json_object(item.pop("summary_json", None))
            item["artifact_summary"] = _decode_json_object(item.pop("artifact_summary_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["authority_evidence"] = _decode_json_array(item.pop("authority_evidence_json", None))
            item["authority_artifacts"] = _decode_json_array(item.pop("authority_artifacts_json", None))
            items.append(item)
        return items

    def recent_framework_adapter_authority_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, dossier_ref, mode,
                   environment, authority_ref, producer_ref, matrix_id,
                   matrix_hash, release_id, release_hash,
                   production_claimed, production_ready,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, source_binding_json,
                   summary_json, control_summary_json,
                   authority_evidence_json, generated_at
            FROM framework_adapter_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "production_claimed", "production_ready")
            item["source_binding"] = _decode_json_object(item.pop("source_binding_json", None))
            item["summary"] = _decode_json_object(item.pop("summary_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["authority_evidence"] = _decode_json_array(item.pop("authority_evidence_json", None))
            items.append(item)
        return items

    def recent_supervised_access_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT receipt_id, entry_id, receipt_hash, session_id,
                   audience_type, audience_purpose, reviewer_subject_ref,
                   reviewer_organization, reviewer_role, artifact_count,
                   issued_at, expires_at, artifact_refs_json,
                   limitations_json
            FROM supervised_access_receipts
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["artifact_refs"] = _decode_json_array(item.pop("artifact_refs_json", None))
            item["limitations"] = _decode_json_array(item.pop("limitations_json", None))
            items.append(item)
        return items

    def recent_regulator_acceptances(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT acceptance_id, entry_id, acceptance_hash, regulator_name,
                   authority_ref, reviewer_ref, outcome, accepted,
                   examination_ref, purpose, framework, source_ref_count,
                   source_refs_json, limitations_json, issued_at
            FROM regulator_acceptances
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "accepted")
            item["source_refs"] = _decode_json_array(item.pop("source_refs_json", None))
            item["limitations"] = _decode_json_array(item.pop("limitations_json", None))
            items.append(item)
        return items

    def recent_review_portal_service_attestations(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT attestation_id, entry_id, attestation_hash, mode,
                   environment, service_ref, service_version, portal_kind,
                   endpoint_url, service_image_digest, frontend_bundle_ref,
                   frontend_bundle_hash, api_ref,
                   supervised_access_receipt_id, session_id, audience_type,
                   reviewer_subject_ref, reviewer_organization, reviewer_role,
                   artifact_count, source_count, control_summary_json,
                   attested_at
            FROM review_portal_service_attestations
            ORDER BY attested_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_review_portal_authority_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, dossier_ref, mode,
                   environment, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   service_attestation_id, service_ref, portal_kind,
                   audience_type, reviewer_subject_ref,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, service_attestation_binding_json,
                   summary_json, control_summary_json,
                   authority_evidence_json, generated_at
            FROM review_portal_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = _bool_fields(dict(row), "production_claimed", "production_ready")
            item["service_attestation_binding"] = _decode_json_object(
                item.pop("service_attestation_binding_json", None)
            )
            item["summary"] = _decode_json_object(item.pop("summary_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["authority_evidence"] = _decode_json_array(item.pop("authority_evidence_json", None))
            items.append(item)
        return items

    def recent_authority_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, entry_type, dossier_hash, dossier_ref,
                   mode, environment, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   freshness_window_count, missing_freshness_count,
                   control_summary_json, covered_requirement_ids_json,
                   missing_requirement_ids_json, generated_at
            FROM authority_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "production_claimed", "production_ready")
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["covered_requirement_ids"] = _decode_json_array(item.pop("covered_requirement_ids_json", None))
            item["missing_requirement_ids"] = _decode_json_array(item.pop("missing_requirement_ids_json", None))
            items.append(item)
        return items

    def recent_shadow_authority_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, entry_type, dossier_hash, dossier_ref,
                   mode, environment, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   freshness_window_count, missing_freshness_count,
                   control_summary_json, covered_requirement_ids_json,
                   missing_requirement_ids_json, generated_at
            FROM authority_dossiers
            WHERE entry_type = ?
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (SHADOW_AUTHORITY_ENTRY_TYPE, limit),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "production_claimed", "production_ready")
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["covered_requirement_ids"] = _decode_json_array(item.pop("covered_requirement_ids_json", None))
            item["missing_requirement_ids"] = _decode_json_array(item.pop("missing_requirement_ids_json", None))
            items.append(item)
        return items

    def recent_vendor_identity_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT receipt_id, entry_id, receipt_hash, vendor_name, legal_name,
                   subject_ref, domain, identity_provider, identity_id,
                   proof_pack_count, trust_network_manifest_id,
                   trust_network_manifest_hash, issued_at, expires_at,
                   vendor_json, proof_packs_json, trust_network_json,
                   limitations_json
            FROM vendor_identity_receipts
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["vendor"] = _decode_json_object(item.pop("vendor_json", None))
            item["proof_packs"] = _decode_json_array(item.pop("proof_packs_json", None))
            item["trust_network"] = _decode_json_object(item.pop("trust_network_json", None))
            item["limitations"] = _decode_json_array(item.pop("limitations_json", None))
            items.append(item)
        return items

    def recent_identity_provider_attestations(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT attestation_id, entry_id, attestation_hash, provider,
                   authentication_method, tenant_ref, observed_at, source,
                   subject_ref, identity_provider, identity_id,
                   identity_record_hash, agent_name, agent_version,
                   vendor_receipt_id, vendor_receipt_hash,
                   source_artifact_count, issued_at, authentication_json,
                   subject_json, vendor_binding_json, source_payload_json,
                   source_artifacts_json, limitations_json
            FROM identity_provider_attestations
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["authentication"] = _decode_json_object(item.pop("authentication_json", None))
            item["subject"] = _decode_json_object(item.pop("subject_json", None))
            item["vendor_binding"] = _decode_json_object(item.pop("vendor_binding_json", None))
            item["source_payload"] = _decode_json_object(item.pop("source_payload_json", None))
            item["source_artifacts"] = _decode_json_array(item.pop("source_artifacts_json", None))
            item["limitations"] = _decode_json_array(item.pop("limitations_json", None))
            items.append(item)
        return items

    def recent_identity_provider_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT session_id, entry_id, session_hash, provider, mode,
                   environment, attestation_id, attestation_hash,
                   session_ref, event_kind, provider_event_id,
                   identity_provider, identity_id, identity_record_hash,
                   decision, risk_level, response_status, success,
                   session_log_ref, session_log_root, audit_log_ref,
                   audit_log_root, recorded_at, identity_attestation_json,
                   session_json, authentication_context_json,
                   provider_evidence_json
            FROM identity_provider_sessions
            ORDER BY recorded_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "success")
            item["identity_attestation"] = _decode_json_object(item.pop("identity_attestation_json", None))
            item["session"] = _decode_json_object(item.pop("session_json", None))
            item["authentication_context"] = _decode_json_object(item.pop("authentication_context_json", None))
            item["provider_evidence"] = _decode_json_object(item.pop("provider_evidence_json", None))
            items.append(item)
        return items

    def recent_identity_provider_lifecycle_operations(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT operation_id, entry_id, operation_hash, provider, mode,
                   environment, attestation_id, attestation_hash,
                   source_session_id, source_session_hash, operation_kind,
                   operation_ref, provider_operation_id, identity_provider,
                   identity_id, identity_record_hash, target_state, outcome,
                   success, response_status, system_log_ref, system_log_root,
                   audit_log_ref, audit_log_root, recorded_at,
                   identity_attestation_json, source_session_json,
                   operation_json, change_refs_json, provider_evidence_json,
                   control_summary_json
            FROM identity_provider_lifecycle_operations
            ORDER BY recorded_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "success")
            item["identity_attestation"] = _decode_json_object(item.pop("identity_attestation_json", None))
            item["source_session"] = _decode_json_object(item.pop("source_session_json", None))
            item["operation"] = _decode_json_object(item.pop("operation_json", None))
            item["change_refs"] = _decode_json_object(item.pop("change_refs_json", None))
            item["provider_evidence"] = _decode_json_object(item.pop("provider_evidence_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_identity_provider_lifecycle_workers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT worker_operation_id, entry_id, worker_operation_hash,
                   provider, mode, environment, source_operation_id,
                   source_operation_hash, identity_id, identity_record_hash,
                   operation_kind, worker_ref, run_ref, worker_success,
                   schedule_ref, queue_ref, destination_ref, response_status,
                   propagation_log_ref, propagation_log_root, audit_log_ref,
                   audit_log_root, recorded_at, source_operation_json,
                   worker_json, scheduler_json, propagation_json,
                   observability_json, control_summary_json
            FROM identity_provider_lifecycle_workers
            ORDER BY recorded_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "worker_success")
            item["source_operation"] = _decode_json_object(item.pop("source_operation_json", None))
            item["worker"] = _decode_json_object(item.pop("worker_json", None))
            item["scheduler"] = _decode_json_object(item.pop("scheduler_json", None))
            item["propagation"] = _decode_json_object(item.pop("propagation_json", None))
            item["observability"] = _decode_json_object(item.pop("observability_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_identity_provider_authority_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, dossier_hash, mode, environment,
                   dossier_ref, authority_ref, producer_ref,
                   production_claimed, production_ready, worker_operation_id,
                   worker_receipt_hash, provider, identity_id,
                   identity_record_hash, operation_kind, worker_ref,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, worker_binding_json,
                   summary_json, control_summary_json, authority_evidence_json,
                   generated_at
            FROM identity_provider_authority_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "production_claimed", "production_ready")
            item["worker_binding"] = _decode_json_object(item.pop("worker_binding_json", None))
            item["summary"] = _decode_json_object(item.pop("summary_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["authority_evidence"] = _decode_json_array(item.pop("authority_evidence_json", None))
            items.append(item)
        return items

    def recent_standards_body_evidence(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, standards_body_name,
                   program_ref, target_track, actor_ref,
                   source_artifact_count, control_count, observed_at,
                   source_artifacts_json, controls_json, body_json
            FROM standards_body_evidence
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["source_artifacts"] = _decode_json_array(item.pop("source_artifacts_json", None))
            controls_json = item.pop("controls_json", None)
            item["controls"] = _decode_json_array(controls_json) or _decode_json_object(controls_json)
            item["body"] = _decode_json_object(item.pop("body_json", None))
            items.append(item)
        return items

    def recent_auditor_ecosystem_evidence(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, program_ref,
                   auditor_ref, auditor_organization, authority_ref, actor_ref,
                   source_artifact_count, control_count, observed_at,
                   source_artifacts_json, controls_json, body_json
            FROM auditor_ecosystem_evidence
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["source_artifacts"] = _decode_json_array(item.pop("source_artifacts_json", None))
            controls_json = item.pop("controls_json", None)
            item["controls"] = _decode_json_array(controls_json) or _decode_json_object(controls_json)
            item["body"] = _decode_json_object(item.pop("body_json", None))
            items.append(item)
        return items


    def recent_trust_network_evidence(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   party_ref, service_ref, registry_ref, marketplace_ref,
                   source_artifact_count, control_count, observed_at,
                   source_artifacts_json, controls_json, body_json
            FROM trust_network_evidence
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["source_artifacts"] = _decode_json_array(item.pop("source_artifacts_json", None))
            controls_json = item.pop("controls_json", None)
            item["controls"] = _decode_json_array(controls_json) or _decode_json_object(controls_json)
            item["body"] = _decode_json_object(item.pop("body_json", None))
            items.append(item)
        return items


    def recent_provider_delivery_evidence(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   provider, service_ref, worker_ref, bundle_ref, authority_ref,
                   pack_id, contract_id, contract_hash, target_ref,
                   provider_endpoint, response_status, success,
                   source_artifact_count, control_count, observed_at,
                   source_artifacts_json, controls_json, body_json
            FROM provider_delivery_evidence
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "success")
            item["source_artifacts"] = _decode_json_array(item.pop("source_artifacts_json", None))
            controls_json = item.pop("controls_json", None)
            item["controls"] = _decode_json_array(controls_json) or _decode_json_object(controls_json)
            item["body"] = _decode_json_object(item.pop("body_json", None))
            items.append(item)
        return items

    def recent_provider_operations_evidence(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   provider, operation_kind, service_ref, installation_ref,
                   webhook_ref, callback_ref, audit_ref, credential_ref,
                   authority_ref, target_ref, source_artifact_count,
                   control_count, observed_at, source_artifacts_json,
                   controls_json, body_json
            FROM provider_operations_evidence
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["source_artifacts"] = _decode_json_array(item.pop("source_artifacts_json", None))
            controls_json = item.pop("controls_json", None)
            item["controls"] = _decode_json_array(controls_json) or _decode_json_object(controls_json)
            item["body"] = _decode_json_object(item.pop("body_json", None))
            items.append(item)
        return items

    def roadmap_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "roadmap_audits": self.recent_roadmap_audits(limit),
            "external_evidence_collection_runs": self.recent_external_evidence_collection_runs(limit),
            "external_evidence_manifests": self.recent_external_evidence_manifests(limit),
            "authority_dossiers": self.recent_authority_dossiers(limit),
            "phase_scoreboards": self.recent_phase_scoreboards(limit),
            "design_partner_dossiers": self.recent_design_partner_dossiers(limit),
            "own_compliance_dossiers": self.recent_own_compliance_dossiers(limit),
            "product_scope_decisions": self.recent_product_scope_decisions(limit),
            "vertical_packs": self.recent_vertical_packs(limit),
            "reliability_reports": self.recent_reliability_reports(limit),
            "insurer_evidence": self.insurer_evidence(limit),
            "multi_agent_evidence": self.multi_agent_evidence(limit),
            "holdout_evidence": self.holdout_evidence(limit),
            "mcp_evidence": self.mcp_evidence(limit),
            "onboarding_evidence": self.onboarding_evidence(limit),
            "promotion_lifecycle_evidence": self.promotion_lifecycle_evidence(limit),
            "byoc_evidence": self.byoc_evidence(limit),
            "identity_provider_evidence": self.identity_provider_evidence(limit),
            "framework_adapter_evidence": self.framework_adapter_evidence(limit),
            "review_portal_evidence": self.review_portal_evidence(limit),
            "standards_auditor_evidence": self.standards_auditor_evidence(limit),
            "trust_network_evidence": self.trust_network_evidence(limit),
            "provider_delivery_evidence": self.provider_delivery_evidence(limit),
            "provider_operations_evidence": self.provider_operations_evidence(limit),
            "compliance_evidence": self.compliance_evidence(limit),
            "policy_backend_evidence": self.policy_backend_evidence(limit),
        }

    def standards_auditor_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "standards_body_evidence": self.recent_standards_body_evidence(limit),
            "auditor_ecosystem_evidence": self.recent_auditor_ecosystem_evidence(limit),
        }

    def trust_network_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {"trust_network_evidence": self.recent_trust_network_evidence(limit)}

    def provider_delivery_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {"provider_delivery_evidence": self.recent_provider_delivery_evidence(limit)}

    def provider_operations_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {"provider_operations_evidence": self.recent_provider_operations_evidence(limit)}

    def recent_compliance_evidence(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   dossier_ref, authority_ref, producer_ref, document_id,
                   pack_id, disclosure_id, data_plane_ref, tenant_id,
                   primary_region, kms_key_region, audit_ref,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   source_artifact_count, control_count, observed_at,
                   source_artifacts_json, source_binding_json, controls_json,
                   summary_json, body_json
            FROM compliance_evidence
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["source_artifacts"] = _decode_json_array(item.pop("source_artifacts_json", None))
            item["source_binding"] = _decode_json_object(item.pop("source_binding_json", None))
            controls_json = item.pop("controls_json", None)
            item["controls"] = _decode_json_array(controls_json) or _decode_json_object(controls_json)
            item["summary"] = _decode_json_object(item.pop("summary_json", None))
            item["body"] = _decode_json_object(item.pop("body_json", None))
            items.append(item)
        return items

    def compliance_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {"compliance_evidence": self.recent_compliance_evidence(limit)}
    def recent_policy_backend_evidence(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT artifact_id, entry_id, entry_type, artifact_kind,
                   artifact_hash, artifact_ref, status, mode, environment,
                   backend_ref, engine, policy_ref, action_ref, decision_ref,
                   service_ref, worker_ref, provider_ref, bundle_ref, authority_ref,
                   credential_ref, audit_ref, response_status, allowed,
                   source_artifact_count, control_count, observed_at,
                   source_artifacts_json, controls_json, body_json
            FROM policy_backend_evidence
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "allowed")
            item["source_artifacts"] = _decode_json_array(item.pop("source_artifacts_json", None))
            controls_json = item.pop("controls_json", None)
            item["controls"] = _decode_json_array(controls_json) or _decode_json_object(controls_json)
            item["body"] = _decode_json_object(item.pop("body_json", None))
            items.append(item)
        return items

    def policy_backend_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {"policy_backend_evidence": self.recent_policy_backend_evidence(limit)}

    def insurer_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "underwriting_quotes": self.recent_underwriting_quotes(limit),
            "insurer_partner_authority_dossiers": self.recent_insurer_partner_authority_dossiers(limit),
        }

    def multi_agent_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "agent_delegations": self.recent_agent_delegations(limit),
            "agent_delegation_graphs": self.recent_agent_delegation_graphs(limit),
        }

    def byoc_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "byoc_operator_attestations": self.recent_byoc_operator_attestations(limit),
            "byoc_authority_dossiers": self.recent_byoc_authority_dossiers(limit),
        }

    def identity_provider_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "vendor_identity_receipts": self.recent_vendor_identity_receipts(limit),
            "identity_provider_attestations": self.recent_identity_provider_attestations(limit),
            "identity_provider_sessions": self.recent_identity_provider_sessions(limit),
            "identity_provider_lifecycle_operations": self.recent_identity_provider_lifecycle_operations(limit),
            "identity_provider_lifecycle_workers": self.recent_identity_provider_lifecycle_workers(limit),
            "identity_provider_authority_dossiers": self.recent_identity_provider_authority_dossiers(limit),
        }

    def framework_adapter_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "framework_adapter_matrices": self.recent_framework_adapter_matrices(limit),
            "framework_hook_releases": self.recent_framework_hook_releases(limit),
            "framework_hook_operations": self.recent_framework_hook_operations(limit),
            "framework_adapter_authority_dossiers": self.recent_framework_adapter_authority_dossiers(limit),
        }

    def review_portal_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "supervised_access_receipts": self.recent_supervised_access_receipts(limit),
            "regulator_acceptances": self.recent_regulator_acceptances(limit),
            "review_portal_service_attestations": self.recent_review_portal_service_attestations(limit),
            "review_portal_authority_dossiers": self.recent_review_portal_authority_dossiers(limit),
        }

    def mcp_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "mcp_tool_calls": self.recent_mcp_tool_calls(limit),
            "mcp_proxy_captures": self.recent_mcp_proxy_captures(limit),
        }

    def onboarding_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {"self_serve_onboarding_receipts": self.recent_self_serve_onboarding_receipts(limit)}

    def promotion_lifecycle_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "human_approvals": self.recent_human_approvals(limit),
            "promotion_demotions": self.recent_promotion_demotions(limit),
            "promotion_rollbacks": self.recent_promotion_rollbacks(limit),
            "soak_demotion_receipts": self.recent_soak_demotion_receipts(limit),
        }

    def holdout_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "temporal_holdout_manifests": self.recent_temporal_holdout_manifests(limit),
            "shadow_replays": self.recent_shadow_replays(limit),
            "soak_reports": self.recent_soak_reports(limit),
            "traffic_holdout_exports": self.recent_traffic_holdout_exports(limit),
            "traffic_completeness_receipts": self.recent_traffic_completeness_receipts(limit),
            "shadow_authority_dossiers": self.recent_shadow_authority_dossiers(limit),
        }

    def readiness(self) -> dict[str, Any]:
        summary = self.summary()
        blockers: list[str] = []

        latest_roadmap_audit = summary.get("latest_roadmap_audit")
        missing_local = int((latest_roadmap_audit or {}).get("missing_local_evidence_count") or 0)
        deferred_external = int((latest_roadmap_audit or {}).get("deferred_external_count") or 0)
        local_reference_complete = latest_roadmap_audit is not None and missing_local == 0
        if latest_roadmap_audit is None:
            blockers.append("no roadmap audit indexed")
        elif missing_local:
            blockers.append(f"local roadmap evidence incomplete: {missing_local} requirement(s) missing local evidence")

        latest_external_manifest = summary.get("latest_external_evidence_manifest")
        latest_external_manifest_details = self.recent_external_evidence_manifests(1)
        if latest_external_manifest_details:
            latest_external_manifest = latest_external_manifest_details[0]
        external_gap_summary = (latest_external_manifest or {}).get("external_authority_gap_summary") or _external_authority_gap_summary([])
        external_missing_requirements = int((latest_external_manifest or {}).get("missing_requirement_count") or 0)
        external_missing_authority_kinds = int((latest_external_manifest or {}).get("missing_authority_kind_count") or 0)
        external_missing_freshness = int((latest_external_manifest or {}).get("missing_freshness_count") or 0)
        external_manifest_strict = bool(
            latest_external_manifest
            and latest_external_manifest.get("require_complete")
            and latest_external_manifest.get("require_fresh")
            and latest_external_manifest.get("require_live_source_uris")
        )
        external_authority_complete = bool(
            latest_external_manifest
            and latest_external_manifest.get("status") == "complete"
            and external_missing_requirements == 0
            and external_missing_authority_kinds == 0
            and external_missing_freshness == 0
            and external_manifest_strict
        )
        if latest_external_manifest is None:
            blockers.append("no external-evidence manifest indexed")
        else:
            if external_missing_requirements or external_missing_authority_kinds or external_missing_freshness:
                blockers.append(
                    "external authority evidence incomplete: "
                    f"{external_missing_requirements} requirement(s), "
                    f"{external_gap_summary['missing_authority_unit_count']} authority unit(s), "
                    f"{external_missing_freshness} freshness window(s) missing"
                )
            if not external_manifest_strict:
                blockers.append("latest external-evidence manifest was not generated with strict complete, fresh, live-source URI requirements")

        latest_collection_run = summary.get("latest_external_evidence_collection_run")
        collection_run_present = latest_collection_run is not None
        collection_collected = int((latest_collection_run or {}).get("collected_count") or 0)
        collection_tasks = int((latest_collection_run or {}).get("task_count") or 0)
        collection_run_strict = bool(
            latest_collection_run
            and latest_collection_run.get("require_fresh")
            and latest_collection_run.get("require_live_source_uris")
            and latest_collection_run.get("require_source_snapshot_artifacts")
            and latest_collection_run.get("require_fresh_source_snapshot_artifacts")
        )
        collection_run_complete = bool(
            collection_run_present
            and collection_run_strict
            and collection_tasks > 0
            and collection_collected >= collection_tasks
        )
        if latest_collection_run is None:
            blockers.append("no retained external-evidence collection run indexed")
        else:
            if collection_collected < collection_tasks:
                blockers.append(
                    "latest external-evidence collection run incomplete: "
                    f"{collection_collected}/{collection_tasks} task(s) collected"
                )
            if not collection_run_strict:
                blockers.append("latest external-evidence collection run was not collected with strict source snapshot and freshness checks")

        latest_phase_scoreboard = summary.get("latest_phase_scoreboard")
        phase_control_summary = (latest_phase_scoreboard or {}).get("control_summary") or {}
        phase_external_required = int(phase_control_summary.get("external-required") or 0)
        phase_scoreboard_present = latest_phase_scoreboard is not None
        phase_scoreboard_ready = bool(
            latest_phase_scoreboard
            and latest_phase_scoreboard.get("mode") == "external-evidence"
            and phase_external_required == 0
        )
        phase_scoreboard_summary = {
            "present": phase_scoreboard_present,
            "mode": (latest_phase_scoreboard or {}).get("mode"),
            "milestone_count": int((latest_phase_scoreboard or {}).get("milestone_count") or 0),
            "phase_counts": (latest_phase_scoreboard or {}).get("phase_counts") or {},
            "control_summary": phase_control_summary,
            "external_required_control_count": phase_external_required,
        }
        if latest_phase_scoreboard is None:
            blockers.append("no roadmap phase scoreboard indexed")
        elif not phase_scoreboard_ready:
            blockers.append(
                "roadmap phase scoreboard milestones incomplete: "
                f"mode={latest_phase_scoreboard.get('mode')}, "
                f"external-required control(s)={phase_external_required}"
            )

        latest_design_partner_dossier = summary.get("latest_design_partner_dossier")
        design_partner_control_summary = (latest_design_partner_dossier or {}).get("control_summary") or {}
        design_partner_external_required = int(design_partner_control_summary.get("external-required") or 0)
        design_partner_ready = bool(
            latest_design_partner_dossier
            and latest_design_partner_dossier.get("mode") == "external-evidence"
            and int(latest_design_partner_dossier.get("partner_count") or 0) >= P1_PARTNER_TARGET
            and int(latest_design_partner_dossier.get("signed_pilot_value_usd") or 0) >= P1_SIGNED_VALUE_TARGET_USD
            and int(latest_design_partner_dossier.get("external_scrutiny_survival_count") or 0) >= 1
            and design_partner_external_required == 0
        )
        design_partner_summary = {
            "present": latest_design_partner_dossier is not None,
            "mode": (latest_design_partner_dossier or {}).get("mode"),
            "partner_count": int((latest_design_partner_dossier or {}).get("partner_count") or 0),
            "signed_partner_count": int((latest_design_partner_dossier or {}).get("signed_partner_count") or 0),
            "signed_pilot_value_usd": int((latest_design_partner_dossier or {}).get("signed_pilot_value_usd") or 0),
            "external_scrutiny_survival_count": int((latest_design_partner_dossier or {}).get("external_scrutiny_survival_count") or 0),
            "control_summary": design_partner_control_summary,
            "external_required_control_count": design_partner_external_required,
        }
        if latest_design_partner_dossier is None:
            blockers.append("no design-partner pilot dossier indexed")
        elif not design_partner_ready:
            blockers.append(
                "design-partner pilot milestones incomplete: "
                f"mode={latest_design_partner_dossier.get('mode')}, "
                f"partners={design_partner_summary['partner_count']}/{P1_PARTNER_TARGET}, "
                f"signed-value-usd={design_partner_summary['signed_pilot_value_usd']}/{P1_SIGNED_VALUE_TARGET_USD}, "
                f"external-scrutiny-survival(s)={design_partner_summary['external_scrutiny_survival_count']}/1, "
                f"external-required control(s)={design_partner_external_required}"
            )

        latest_own_compliance_dossier = summary.get("latest_own_compliance_dossier")
        own_compliance_control_summary = (latest_own_compliance_dossier or {}).get("control_summary") or {}
        own_compliance_external_required = int(own_compliance_control_summary.get("external-required") or 0)
        own_compliance_target_count = len(REQUIRED_CERTIFICATION_KINDS)
        own_compliance_ready = bool(
            latest_own_compliance_dossier
            and latest_own_compliance_dossier.get("mode") == "external-certification"
            and int(latest_own_compliance_dossier.get("required_certification_evidence_count") or 0) >= own_compliance_target_count
            and own_compliance_external_required == 0
        )
        own_compliance_summary = {
            "present": latest_own_compliance_dossier is not None,
            "mode": (latest_own_compliance_dossier or {}).get("mode"),
            "evidence_count": int((latest_own_compliance_dossier or {}).get("evidence_count") or 0),
            "required_certification_evidence_count": int((latest_own_compliance_dossier or {}).get("required_certification_evidence_count") or 0),
            "required_certification_target_count": own_compliance_target_count,
            "control_summary": own_compliance_control_summary,
            "external_required_control_count": own_compliance_external_required,
        }
        if latest_own_compliance_dossier is None:
            blockers.append("no TrustAI own-compliance dossier indexed")
        elif not own_compliance_ready:
            blockers.append(
                "TrustAI own-compliance certifications incomplete: "
                f"mode={latest_own_compliance_dossier.get('mode')}, "
                f"required-certification-evidence="
                f"{own_compliance_summary['required_certification_evidence_count']}/{own_compliance_target_count}, "
                f"external-required control(s)={own_compliance_external_required}"
            )

        latest_product_scope_decision = summary.get("latest_product_scope_decision")
        product_scope_control_summary = (latest_product_scope_decision or {}).get("control_summary") or {}
        product_scope_failed = int(product_scope_control_summary.get("failed") or 0)
        product_scope_ready = bool(latest_product_scope_decision and product_scope_failed == 0)
        product_scope_summary = {
            "present": latest_product_scope_decision is not None,
            "decision": (latest_product_scope_decision or {}).get("decision"),
            "proof_impact_count": len((latest_product_scope_decision or {}).get("proof_impacts") or []),
            "anti_focus_flag_count": len((latest_product_scope_decision or {}).get("anti_focus_flags") or []),
            "control_summary": product_scope_control_summary,
            "failed_control_count": product_scope_failed,
        }
        if latest_product_scope_decision is None:
            blockers.append("no product-scope decision indexed")
        elif not product_scope_ready:
            blockers.append(
                "product-scope discipline controls failed: "
                f"failed control(s)={product_scope_failed}"
            )

        latest_vertical_pack = summary.get("latest_vertical_pack")
        vertical_pack_control_summary = (latest_vertical_pack or {}).get("control_summary") or {}
        vertical_pack_external_required = int(vertical_pack_control_summary.get("external-required") or 0)
        vertical_pack_failed = int(vertical_pack_control_summary.get("failed") or 0)
        vertical_pack_ready = bool(
            latest_vertical_pack
            and vertical_pack_external_required == 0
            and vertical_pack_failed == 0
        )
        vertical_pack_summary = {
            "present": latest_vertical_pack is not None,
            "vertical": (latest_vertical_pack or {}).get("vertical"),
            "environment": (latest_vertical_pack or {}).get("environment"),
            "external_requirement_count": int((latest_vertical_pack or {}).get("external_requirement_count") or 0),
            "control_summary": vertical_pack_control_summary,
            "external_required_control_count": vertical_pack_external_required,
            "failed_control_count": vertical_pack_failed,
        }
        if latest_vertical_pack is None:
            blockers.append("no vertical pack indexed")
        elif not vertical_pack_ready:
            blockers.append(
                "vertical-pack production acceptance incomplete: "
                f"vertical={latest_vertical_pack.get('vertical')}, "
                f"external-required control(s)={vertical_pack_external_required}, "
                f"failed control(s)={vertical_pack_failed}"
            )

        latest_reliability_report = summary.get("latest_reliability_report")
        reliability_report_control_summary = (latest_reliability_report or {}).get("control_summary") or {}
        reliability_report_external_required = int(reliability_report_control_summary.get("external-required") or 0)
        reliability_report_failed = int(reliability_report_control_summary.get("failed") or 0)
        reliability_report_source_products = int((latest_reliability_report or {}).get("source_product_count") or 0)
        reliability_report_ready = bool(
            latest_reliability_report
            and latest_reliability_report.get("mode") == "published-evidence"
            and reliability_report_source_products > 0
            and reliability_report_external_required == 0
            and reliability_report_failed == 0
        )
        reliability_report_summary = {
            "present": latest_reliability_report is not None,
            "mode": (latest_reliability_report or {}).get("mode"),
            "cohort_count": int((latest_reliability_report or {}).get("cohort_count") or 0),
            "source_product_count": reliability_report_source_products,
            "control_summary": reliability_report_control_summary,
            "external_required_control_count": reliability_report_external_required,
            "failed_control_count": reliability_report_failed,
            "incident_rate_per_100k_actions": (latest_reliability_report or {}).get("incident_rate_per_100k_actions"),
            "gate_pass_rate_bps": (latest_reliability_report or {}).get("gate_pass_rate_bps"),
        }
        if latest_reliability_report is None:
            blockers.append("no State of Agent Reliability report indexed")
        elif not reliability_report_ready:
            blockers.append(
                "State of Agent Reliability publication incomplete: "
                f"mode={latest_reliability_report.get('mode')}, "
                f"source-products={reliability_report_source_products}, "
                f"external-required control(s)={reliability_report_external_required}, "
                f"failed control(s)={reliability_report_failed}"
            )

        authority_row = self.conn.execute(
            """
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN production_claimed THEN 1 ELSE 0 END), 0) AS production_claimed,
                   COALESCE(SUM(CASE WHEN production_ready THEN 1 ELSE 0 END), 0) AS production_ready,
                   COALESCE(SUM(CASE WHEN production_ready THEN 0 ELSE 1 END), 0) AS not_ready,
                   COALESCE(SUM(missing_requirement_count), 0) AS missing_requirement_count,
                   COALESCE(SUM(missing_freshness_count), 0) AS missing_freshness_count
            FROM authority_dossiers
            """
        ).fetchone()
        authority_dossier_summary = {
            "total": int(authority_row["total"] or 0),
            "production_claimed": int(authority_row["production_claimed"] or 0),
            "production_ready": int(authority_row["production_ready"] or 0),
            "not_ready": int(authority_row["not_ready"] or 0),
            "missing_requirement_count": int(authority_row["missing_requirement_count"] or 0),
            "missing_freshness_count": int(authority_row["missing_freshness_count"] or 0),
        }
        production_authority_ready = bool(
            authority_dossier_summary["total"] > 0 and authority_dossier_summary["not_ready"] == 0
        )
        if authority_dossier_summary["total"] == 0:
            blockers.append("no production authority dossiers indexed")
        elif authority_dossier_summary["not_ready"]:
            blockers.append(
                "production authority dossiers are not ready: "
                f"{authority_dossier_summary['not_ready']}/{authority_dossier_summary['total']} dossier(s) incomplete"
            )

        latest_gate_decision = summary.get("latest_gate_decision")
        promotion_gate_ready = bool(latest_gate_decision and latest_gate_decision.get("passed"))
        if not promotion_gate_ready:
            blockers.append("no passed promotion gate decision indexed")

        latest_proof_pack = summary.get("latest_proof_pack")
        proof_pack_ready = bool(latest_proof_pack and latest_proof_pack.get("outcome") == "passed")
        if not proof_pack_ready:
            blockers.append("no passed proof pack indexed")

        latest_runtime_attestation = summary.get("latest_runtime_attestation")
        latest_policy_decision = summary.get("latest_policy_decision")
        latest_policy_engine_receipt = summary.get("latest_policy_engine_receipt")
        runtime_policy_ready = bool(
            latest_runtime_attestation
            and latest_runtime_attestation.get("passed")
            and latest_policy_decision
            and latest_policy_decision.get("passed")
            and latest_policy_engine_receipt
            and latest_policy_engine_receipt.get("decision_passed")
        )
        if not runtime_policy_ready:
            blockers.append("runtime attestation and policy-engine evidence are not both passing")

        ready = all(
            [
                local_reference_complete,
                external_authority_complete,
                collection_run_complete,
                production_authority_ready,
                phase_scoreboard_ready,
                design_partner_ready,
                own_compliance_ready,
                product_scope_ready,
                vertical_pack_ready,
                reliability_report_ready,
                promotion_gate_ready,
                proof_pack_ready,
                runtime_policy_ready,
            ]
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "ready" if ready else "not_ready",
            "local_reference_complete": local_reference_complete,
            "external_authority_complete": external_authority_complete,
            "collection_run_present": collection_run_present,
            "collection_run_complete": collection_run_complete,
            "production_authority_ready": production_authority_ready,
            "roadmap_phase_scoreboard_ready": phase_scoreboard_ready,
            "design_partner_ready": design_partner_ready,
            "own_compliance_ready": own_compliance_ready,
            "product_scope_ready": product_scope_ready,
            "vertical_pack_ready": vertical_pack_ready,
            "reliability_report_ready": reliability_report_ready,
            "promotion_gate_ready": promotion_gate_ready,
            "proof_pack_ready": proof_pack_ready,
            "runtime_policy_ready": runtime_policy_ready,
            "counts": summary["counts"],
            "latest_roadmap_audit": latest_roadmap_audit,
            "latest_external_evidence_manifest": latest_external_manifest,
            "latest_external_evidence_collection_run": latest_collection_run,
            "latest_authority_dossier": summary.get("latest_authority_dossier"),
            "latest_phase_scoreboard": latest_phase_scoreboard,
            "latest_design_partner_dossier": latest_design_partner_dossier,
            "latest_own_compliance_dossier": latest_own_compliance_dossier,
            "latest_product_scope_decision": latest_product_scope_decision,
            "latest_vertical_pack": latest_vertical_pack,
            "latest_reliability_report": latest_reliability_report,
            "phase_scoreboard_summary": phase_scoreboard_summary,
            "design_partner_summary": design_partner_summary,
            "own_compliance_summary": own_compliance_summary,
            "product_scope_summary": product_scope_summary,
            "vertical_pack_summary": vertical_pack_summary,
            "reliability_report_summary": reliability_report_summary,
            "authority_dossier_summary": authority_dossier_summary,
            "external_authority_gap_summary": external_gap_summary,
            "remaining_external_evidence_count": deferred_external,
            "blockers": blockers,
        }

    def runtime_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "runtime_attestations": self.recent_runtime_attestations(limit),
            "policy_decisions": self.recent_policy_decisions(limit),
            "policy_engine_receipts": self.recent_policy_engine_receipts(limit),
            "policy_backend_evidence": self.recent_policy_backend_evidence(limit),
            "incidents": self.recent_incidents(limit),
        }

    def _resolve_contract_scope(
        self,
        contract_id: str | None,
        contract_hash: str | None,
    ) -> tuple[dict[str, Any] | None, str | None, str | None]:
        if not contract_id and not contract_hash:
            raise ValueError("contract_id or contract_hash is required")
        clauses = []
        params: list[str] = []
        if contract_id:
            clauses.append("contract_id = ?")
            params.append(contract_id)
        if contract_hash:
            clauses.append("contract_hash = ?")
            params.append(contract_hash)
        row = self.conn.execute(
            f"""
            SELECT contract_hash, contract_id, version, agent_name, agent_version,
                   registered_entry_id, created_at
            FROM contracts
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC
            LIMIT 1
            """,
            params,
        ).fetchone()
        contract = dict(row) if row else None
        return (
            contract,
            contract_id or (contract.get("contract_id") if contract else None),
            contract_hash or (contract.get("contract_hash") if contract else None),
        )

    def _contract_scope_clause(
        self,
        contract_id: str | None,
        contract_hash: str | None,
        *,
        id_column: str | None = "contract_id",
        hash_column: str | None = "contract_hash",
    ) -> tuple[str, list[str]]:
        clauses = []
        params: list[str] = []
        if id_column and contract_id:
            clauses.append(f"{id_column} = ?")
            params.append(contract_id)
        if hash_column and contract_hash:
            clauses.append(f"{hash_column} = ?")
            params.append(contract_hash)
        if not clauses:
            return "1 = 0", []
        return "(" + " OR ".join(clauses) + ")", params

    def _scoped_rows(
        self,
        *,
        table: str,
        select_sql: str,
        order_sql: str,
        contract_id: str | None,
        contract_hash: str | None,
        limit: int,
        id_column: str | None = "contract_id",
        hash_column: str | None = "contract_hash",
    ) -> tuple[int, list[dict[str, Any]]]:
        clause, params = self._contract_scope_clause(
            contract_id,
            contract_hash,
            id_column=id_column,
            hash_column=hash_column,
        )
        count = self.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {clause}", params).fetchone()["count"]
        rows = self.conn.execute(
            f"{select_sql} WHERE {clause} {order_sql} LIMIT ?",
            [*params, limit],
        ).fetchall()
        return count, [dict(row) for row in rows]

    def contract_evidence(
        self,
        *,
        contract_id: str | None = None,
        contract_hash: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        contract, resolved_id, resolved_hash = self._resolve_contract_scope(contract_id, contract_hash)
        counts: dict[str, int] = {"contracts": 1 if contract else 0}

        count, chain_entries = self._scoped_rows(
            table="chain_entries",
            select_sql="""
            SELECT entry_id, idx, tenant_id, entry_type, timestamp,
                   contract_hash, payload_hash
            FROM chain_entries
            """,
            order_sql="ORDER BY idx DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["chain_entries"] = count

        count, agent_delegations = self._scoped_rows(
            table="agent_delegations",
            select_sql="""
            SELECT entry_id, delegation_hash, contract_hash,
                   parent_agent_name, parent_agent_version, parent_agent_ref,
                   child_agent_name, child_agent_version, child_agent_ref,
                   reason, scope_json, delegated_at, delegation_json
            FROM agent_delegations
            """,
            order_sql="ORDER BY delegated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["agent_delegations"] = count
        for item in agent_delegations:
            item["scope"] = _decode_json_object(item.pop("scope_json", None))
            item["delegation"] = _decode_json_object(item.pop("delegation_json", None))

        count, agent_delegation_graphs = self._scoped_rows(
            table="agent_delegation_graphs",
            select_sql="""
            SELECT delegation_graph_id, entry_id, delegation_graph_hash,
                   contract_hash, contract_hash_filter, root_agent_filter,
                   source_chain_tenant_id, source_chain_entry_count,
                   node_count, edge_count, max_depth, cycle_detected,
                   root_agents_json, leaf_agents_json, missing_inventory_json,
                   contract_hashes_json, agent_refs_json, node_root, edge_root,
                   filters_json, source_chain_json, summary_json, generated_at
            FROM agent_delegation_graphs
            """,
            order_sql="ORDER BY generated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["agent_delegation_graphs"] = count
        for item in agent_delegation_graphs:
            _bool_fields(item, "cycle_detected")
            item["root_agents"] = _decode_json_array(item.pop("root_agents_json", None))
            item["leaf_agents"] = _decode_json_array(item.pop("leaf_agents_json", None))
            item["missing_inventory"] = _decode_json_array(item.pop("missing_inventory_json", None))
            item["contract_hashes"] = _decode_json_array(item.pop("contract_hashes_json", None))
            item["agent_refs"] = _decode_json_array(item.pop("agent_refs_json", None))
            item["filters"] = _decode_json_object(item.pop("filters_json", None))
            item["source_chain"] = _decode_json_object(item.pop("source_chain_json", None))
            item["summary"] = _decode_json_object(item.pop("summary_json", None))

        count, eval_runs = self._scoped_rows(
            table="eval_runs",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, results_hash, evaluated_at
            FROM eval_runs
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["eval_runs"] = count

        count, gate_decisions = self._scoped_rows(
            table="gate_decisions",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, outcome, passed, eval_entry_id,
                   contract_entry_id, results_hash, check_count,
                   failed_check_count, holdout_passed, approvals_passed,
                   evaluated_at
            FROM gate_decisions
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["gate_decisions"] = count
        gate_decisions = [_bool_fields(item, "passed", "holdout_passed", "approvals_passed") for item in gate_decisions]

        count, human_approvals = self._scoped_rows(
            table="human_approvals",
            select_sql="""
            SELECT entry_id, approval_hash, contract_id, contract_hash,
                   agent_name, agent_version, role, approver, source,
                   external_ref, approved_at, metadata_json
            FROM human_approvals
            """,
            order_sql="ORDER BY approved_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["human_approvals"] = count
        for item in human_approvals:
            item["metadata"] = _decode_json_object(item.pop("metadata_json", None))

        count, promotion_demotions = self._scoped_rows(
            table="promotion_demotions",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, from_environment, to_environment,
                   reason, triggering_entry_id, trigger_json, decided_at
            FROM promotion_demotions
            """,
            order_sql="ORDER BY decided_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["promotion_demotions"] = count
        for item in promotion_demotions:
            item["trigger"] = _decode_json_object(item.pop("trigger_json", None))

        count, promotion_rollbacks = self._scoped_rows(
            table="promotion_rollbacks",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, target_agent_version, reason,
                   triggering_entry_id, decided_at
            FROM promotion_rollbacks
            """,
            order_sql="ORDER BY decided_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["promotion_rollbacks"] = count

        count, soak_demotion_receipts = self._scoped_rows(
            table="soak_demotion_receipts",
            select_sql="""
            SELECT receipt_id, entry_id, receipt_hash, contract_id,
                   contract_hash, agent_name, agent_version,
                   soak_report_entry_id, demotion_entry_id,
                   source_json, violation_count, passed, attested_at
            FROM soak_demotion_receipts
            """,
            order_sql="ORDER BY attested_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["soak_demotion_receipts"] = count
        for item in soak_demotion_receipts:
            _bool_fields(item, "passed")
            item["source"] = _decode_json_object(item.pop("source_json", None))

        count, temporal_holdout_manifests = self._scoped_rows(
            table="temporal_holdout_manifests",
            select_sql="""
            SELECT manifest_id, entry_id, manifest_hash, run_id, dataset_id,
                   contract_id, contract_hash, candidate_version, record_count,
                   violation_count, passed, records_root,
                   earliest_record_timestamp, latest_record_timestamp, generated_at
            FROM temporal_holdout_manifests
            """,
            order_sql="ORDER BY generated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["temporal_holdout_manifests"] = count
        temporal_holdout_manifests = [_bool_fields(item, "passed") for item in temporal_holdout_manifests]

        count, shadow_replays = self._scoped_rows(
            table="shadow_replays",
            select_sql="""
            SELECT entry_id, run_id, contract_id, contract_hash,
                   candidate_version, replay_hash, records_checked, passed,
                   outcome, holdout_passed, holdout_error_count, check_count,
                   failed_check_count, temporal_holdout_manifest_id,
                   temporal_holdout_manifest_hash, evaluated_at, metrics_json
            FROM shadow_replays
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["shadow_replays"] = count
        for item in shadow_replays:
            _bool_fields(item, "passed", "holdout_passed")
            item["metrics"] = _decode_json_object(item.pop("metrics_json", None))

        count, soak_reports = self._scoped_rows(
            table="soak_reports",
            select_sql="""
            SELECT entry_id, report_id, contract_id, contract_hash,
                   candidate_version, soak_hash, window_count, incident_count,
                   drift_alarm_count, blocking_drift_alarm_count, passed,
                   outcome, check_count, failed_check_count, evaluated_at,
                   metrics_json
            FROM soak_reports
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["soak_reports"] = count
        for item in soak_reports:
            _bool_fields(item, "passed")
            item["metrics"] = _decode_json_object(item.pop("metrics_json", None))

        count, traffic_holdout_exports = self._scoped_rows(
            table="traffic_holdout_exports",
            select_sql="""
            SELECT export_id, entry_id, export_hash, export_ref, source_ref,
                   exporter_ref, contract_id, contract_hash, candidate_version,
                   record_count, violation_count, passed,
                   extraction_window_json, records_root,
                   earliest_record_timestamp, latest_record_timestamp,
                   produced_at
            FROM traffic_holdout_exports
            """,
            order_sql="ORDER BY produced_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["traffic_holdout_exports"] = count
        for item in traffic_holdout_exports:
            _bool_fields(item, "passed")
            item["extraction_window"] = _decode_json_object(item.pop("extraction_window_json", None))

        count, traffic_completeness_receipts = self._scoped_rows(
            table="traffic_completeness_receipts",
            select_sql="""
            SELECT completeness_id, entry_id, completeness_hash, mode,
                   authority_ref, export_id, export_hash, contract_id,
                   contract_hash, candidate_version, record_count,
                   violation_count, passed, source_completeness_json,
                   provider_exchange_json, produced_at
            FROM traffic_completeness_receipts
            """,
            order_sql="ORDER BY produced_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["traffic_completeness_receipts"] = count
        for item in traffic_completeness_receipts:
            _bool_fields(item, "passed")
            item["source_completeness"] = _decode_json_object(item.pop("source_completeness_json", None))
            item["provider_exchange"] = _decode_json_object(item.pop("provider_exchange_json", None))

        count, proof_packs = self._scoped_rows(
            table="proof_packs",
            select_sql="""
            SELECT pack_id, contract_id, contract_hash, agent_name,
                   agent_version, outcome, issued_at, path
            FROM proof_packs
            """,
            order_sql="ORDER BY issued_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["proof_packs"] = count

        count, ingest_events = self._scoped_rows(
            table="ingest_events",
            select_sql="""
            SELECT entry_id, event_hash, contract_hash, trace_id, span_id,
                   parent_span_id, event_name, agent_name, agent_version,
                   risk_class, schema_url, observed_at, attributes_json
            FROM ingest_events
            """,
            order_sql="ORDER BY observed_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["ingest_events"] = count
        for item in ingest_events:
            item["attributes"] = _decode_json_object(item.pop("attributes_json", None))

        count, mcp_tool_calls = self._scoped_rows(
            table="mcp_tool_calls",
            select_sql="""
            SELECT entry_id, session_id, request_id, tool_name,
                   contract_hash, agent_name, agent_version, risk_class,
                   request_hash, response_hash, tool_call_hash,
                   transcript_sequence, transcript_call_count,
                   previous_transcript_node_hash, transcript_node_hash,
                   transcript_root, observed_at
            FROM mcp_tool_calls
            """,
            order_sql="ORDER BY observed_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["mcp_tool_calls"] = count

        count, mcp_proxy_captures = self._scoped_rows(
            table="mcp_proxy_captures",
            select_sql="""
            SELECT capture_id, entry_id, proxy_ref, upstream_ref, session_id,
                   contract_hash, agent_name, agent_version, risk_class,
                   event_count, tool_call_count, event_chain_root,
                   transcript_root, proxy_events_artifact_json,
                   event_hashes_json, tool_call_hashes_json, captured_at
            FROM mcp_proxy_captures
            """,
            order_sql="ORDER BY captured_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["mcp_proxy_captures"] = count
        for item in mcp_proxy_captures:
            item["proxy_events_artifact"] = _decode_json_object(item.pop("proxy_events_artifact_json", None))
            item["event_hashes"] = _decode_json_array(item.pop("event_hashes_json", None))
            item["tool_call_hashes"] = _decode_json_array(item.pop("tool_call_hashes_json", None))

        count, framework_hook_operations = self._scoped_rows(
            table="framework_hook_operations",
            select_sql="""
            SELECT operation_id, entry_id, operation_hash, mode, environment,
                   contract_hash, agent_name, agent_version, risk_class,
                   framework, runtime_package, runtime_version,
                   hook_package, hook_version, collector_hook_ref,
                   hook_release_hash, source_trace_id, trace_id,
                   event_count, event_root, runtime_json, hook_json,
                   release_binding_json, trace_json, collector_json,
                   control_summary_json, captured_at
            FROM framework_hook_operations
            """,
            order_sql="ORDER BY captured_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["framework_hook_operations"] = count
        for item in framework_hook_operations:
            item["runtime"] = _decode_json_object(item.pop("runtime_json", None))
            item["hook"] = _decode_json_object(item.pop("hook_json", None))
            item["release_binding"] = _decode_json_object(item.pop("release_binding_json", None))
            item["trace"] = _decode_json_object(item.pop("trace_json", None))
            item["collector"] = _decode_json_object(item.pop("collector_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))

        count, promotion_statuses = self._scoped_rows(
            table="promotion_statuses",
            select_sql="""
            SELECT receipt_id, provider, pack_id, contract_id, contract_hash,
                   agent_name, agent_version, gate_outcome, passed,
                   provider_status_kind, provider_status_success,
                   target_ref_json, violation_count, attested_at
            FROM promotion_statuses
            """,
            order_sql="ORDER BY attested_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["promotion_statuses"] = count
        for item in promotion_statuses:
            _bool_fields(item, "passed", "provider_status_success")
            item["target_ref"] = _decode_json_object(item.pop("target_ref_json", None))

        count, runtime_attestations = self._scoped_rows(
            table="runtime_attestations",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, action_hash,
                   action_id, action_type, risk_class, passed, outcome,
                   check_count, failed_check_count, attested_at
            FROM runtime_attestations
            """,
            order_sql="ORDER BY attested_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["runtime_attestations"] = count
        runtime_attestations = [_bool_fields(item, "passed") for item in runtime_attestations]

        count, policy_decisions = self._scoped_rows(
            table="policy_decisions",
            select_sql="""
            SELECT entry_id, policy_pack_id, policy_pack_version,
                   policy_pack_hash, contract_hash, action_hash, passed,
                   outcome, matched_rule_count, check_count,
                   failed_check_count, evaluated_at
            FROM policy_decisions
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["policy_decisions"] = count
        policy_decisions = [_bool_fields(item, "passed") for item in policy_decisions]

        count, policy_engine_receipts = self._scoped_rows(
            table="policy_engine_receipts",
            select_sql="""
            SELECT receipt_id, entry_id, engine_name, engine_mode,
                   policy_pack_id, policy_pack_version, policy_pack_hash,
                   action_hash, action_id, action_type, risk_class,
                   pack_id, contract_id, contract_hash, decision_entry_id,
                   decision_outcome, decision_passed, evaluated_at
            FROM policy_engine_receipts
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["policy_engine_receipts"] = count
        policy_engine_receipts = [_bool_fields(item, "decision_passed") for item in policy_engine_receipts]

        count, incidents = self._scoped_rows(
            table="incidents",
            select_sql="""
            SELECT incident_id, entry_id, contract_hash, agent_name,
                   agent_version, severity, summary, detected_at
            FROM incidents
            """,
            order_sql="ORDER BY detected_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["incidents"] = count

        return {
            "scope": {"contract_id": resolved_id, "contract_hash": resolved_hash},
            "contract": contract,
            "counts": counts,
            "chain_entries": chain_entries,
            "agent_delegations": agent_delegations,
            "agent_delegation_graphs": agent_delegation_graphs,
            "eval_runs": eval_runs,
            "gate_decisions": gate_decisions,
            "human_approvals": human_approvals,
            "promotion_demotions": promotion_demotions,
            "promotion_rollbacks": promotion_rollbacks,
            "soak_demotion_receipts": soak_demotion_receipts,
            "temporal_holdout_manifests": temporal_holdout_manifests,
            "shadow_replays": shadow_replays,
            "soak_reports": soak_reports,
            "traffic_holdout_exports": traffic_holdout_exports,
            "traffic_completeness_receipts": traffic_completeness_receipts,
            "proof_packs": proof_packs,
            "ingest_events": ingest_events,
            "mcp_tool_calls": mcp_tool_calls,
            "mcp_proxy_captures": mcp_proxy_captures,
            "framework_hook_operations": framework_hook_operations,
            "promotion_statuses": promotion_statuses,
            "runtime_attestations": runtime_attestations,
            "policy_decisions": policy_decisions,
            "policy_engine_receipts": policy_engine_receipts,
            "incidents": incidents,
        }

    def _agent_scope_clause(
        self,
        agent_name: str,
        agent_version: str | None,
        *,
        name_column: str = "agent_name",
        version_column: str = "agent_version",
    ) -> tuple[str, list[str]]:
        clauses = [f"{name_column} = ?"]
        params = [agent_name]
        if agent_version:
            clauses.append(f"{version_column} = ?")
            params.append(agent_version)
        return "(" + " AND ".join(clauses) + ")", params

    def _agent_scoped_rows(
        self,
        *,
        table: str,
        select_sql: str,
        order_sql: str,
        agent_name: str,
        agent_version: str | None,
        limit: int,
        name_column: str = "agent_name",
        version_column: str = "agent_version",
    ) -> tuple[int, list[dict[str, Any]]]:
        clause, params = self._agent_scope_clause(
            agent_name,
            agent_version,
            name_column=name_column,
            version_column=version_column,
        )
        count = self.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {clause}", params).fetchone()["count"]
        rows = self.conn.execute(
            f"{select_sql} WHERE {clause} {order_sql} LIMIT ?",
            [*params, limit],
        ).fetchall()
        return count, [dict(row) for row in rows]

    def _agent_contract_hashes(self, agent_name: str, agent_version: str | None) -> list[str]:
        hashes: list[str] = []
        sources = [
            ("contracts", "agent_name", "agent_version"),
            ("eval_runs", "agent_name", "agent_version"),
            ("gate_decisions", "agent_name", "agent_version"),
            ("human_approvals", "agent_name", "agent_version"),
            ("promotion_demotions", "agent_name", "agent_version"),
            ("promotion_rollbacks", "agent_name", "agent_version"),
            ("soak_demotion_receipts", "agent_name", "agent_version"),
            ("proof_packs", "agent_name", "agent_version"),
            ("ingest_events", "agent_name", "agent_version"),
            ("mcp_tool_calls", "agent_name", "agent_version"),
            ("mcp_proxy_captures", "agent_name", "agent_version"),
            ("promotion_statuses", "agent_name", "agent_version"),
            ("incidents", "agent_name", "agent_version"),
        ]
        for table, name_column, version_column in sources:
            clause, params = self._agent_scope_clause(
                agent_name,
                agent_version,
                name_column=name_column,
                version_column=version_column,
            )
            rows = self.conn.execute(
                f"SELECT DISTINCT contract_hash FROM {table} WHERE {clause} AND contract_hash IS NOT NULL",
                params,
            ).fetchall()
            hashes.extend(row["contract_hash"] for row in rows if row["contract_hash"])
        return list(dict.fromkeys(hashes))

    def _hash_scope_clause(self, hashes: list[str], *, hash_column: str = "contract_hash") -> tuple[str, list[str]]:
        unique_hashes = [value for value in dict.fromkeys(hashes) if value]
        if not unique_hashes:
            return "1 = 0", []
        placeholders = ", ".join("?" for _ in unique_hashes)
        return f"{hash_column} IN ({placeholders})", unique_hashes

    def _hash_scoped_rows(
        self,
        *,
        table: str,
        select_sql: str,
        order_sql: str,
        hashes: list[str],
        limit: int,
        hash_column: str = "contract_hash",
    ) -> tuple[int, list[dict[str, Any]]]:
        clause, params = self._hash_scope_clause(hashes, hash_column=hash_column)
        count = self.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {clause}", params).fetchone()["count"]
        rows = self.conn.execute(
            f"{select_sql} WHERE {clause} {order_sql} LIMIT ?",
            [*params, limit],
        ).fetchall()
        return count, [dict(row) for row in rows]

    def agent_evidence(
        self,
        *,
        agent_name: str | None,
        agent_version: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        if not agent_name:
            raise ValueError("agent_name is required")
        counts: dict[str, int] = {}

        count, agents = self._agent_scoped_rows(
            table="agents",
            select_sql="""
            SELECT name, version, owner, risk_class, governed, source, observed_at
            FROM agents
            """,
            order_sql="ORDER BY observed_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
            name_column="name",
            version_column="version",
        )
        counts["agents"] = count
        agents = [_bool_fields(item, "governed") for item in agents]

        count, contracts = self._agent_scoped_rows(
            table="contracts",
            select_sql="""
            SELECT contract_hash, contract_id, version, agent_name, agent_version,
                   registered_entry_id, created_at
            FROM contracts
            """,
            order_sql="ORDER BY created_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["contracts"] = count
        contract_hashes = self._agent_contract_hashes(agent_name, agent_version)

        count, chain_entries = self._hash_scoped_rows(
            table="chain_entries",
            select_sql="""
            SELECT entry_id, idx, tenant_id, entry_type, timestamp,
                   contract_hash, payload_hash
            FROM chain_entries
            """,
            order_sql="ORDER BY idx DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["chain_entries"] = count

        if agent_version:
            delegation_clause = (
                "((parent_agent_name = ? AND parent_agent_version = ?) "
                "OR (child_agent_name = ? AND child_agent_version = ?))"
            )
            delegation_params = [agent_name, agent_version, agent_name, agent_version]
        else:
            delegation_clause = "(parent_agent_name = ? OR child_agent_name = ?)"
            delegation_params = [agent_name, agent_name]
        count = self.conn.execute(
            f"SELECT COUNT(*) AS count FROM agent_delegations WHERE {delegation_clause}",
            delegation_params,
        ).fetchone()["count"]
        agent_delegations = [
            dict(row)
            for row in self.conn.execute(
                f"""
                SELECT entry_id, delegation_hash, contract_hash,
                       parent_agent_name, parent_agent_version, parent_agent_ref,
                       child_agent_name, child_agent_version, child_agent_ref,
                       reason, scope_json, delegated_at, delegation_json
                FROM agent_delegations
                WHERE {delegation_clause}
                ORDER BY delegated_at DESC
                LIMIT ?
                """,
                [*delegation_params, limit],
            ).fetchall()
        ]
        counts["agent_delegations"] = count
        for item in agent_delegations:
            item["scope"] = _decode_json_object(item.pop("scope_json", None))
            item["delegation"] = _decode_json_object(item.pop("delegation_json", None))

        graph_rows = [
            dict(row)
            for row in self.conn.execute(
                """
                SELECT delegation_graph_id, entry_id, delegation_graph_hash,
                       contract_hash, contract_hash_filter, root_agent_filter,
                       source_chain_tenant_id, source_chain_entry_count,
                       node_count, edge_count, max_depth, cycle_detected,
                       root_agents_json, leaf_agents_json, missing_inventory_json,
                       contract_hashes_json, agent_refs_json, node_root, edge_root,
                       filters_json, source_chain_json, summary_json, generated_at
                FROM agent_delegation_graphs
                ORDER BY generated_at DESC
                """
            ).fetchall()
        ]
        agent_ref = f"{agent_name}@{agent_version}" if agent_version else None
        agent_ref_prefix = f"{agent_name}@"
        agent_delegation_graphs = []
        for row in graph_rows:
            refs = _decode_json_array(row.get("agent_refs_json"))
            if (agent_ref and agent_ref in refs) or (not agent_ref and any(ref.startswith(agent_ref_prefix) for ref in refs)):
                agent_delegation_graphs.append(row)
        count = len(agent_delegation_graphs)
        agent_delegation_graphs = agent_delegation_graphs[:limit]
        counts["agent_delegation_graphs"] = count
        for item in agent_delegation_graphs:
            _bool_fields(item, "cycle_detected")
            item["root_agents"] = _decode_json_array(item.pop("root_agents_json", None))
            item["leaf_agents"] = _decode_json_array(item.pop("leaf_agents_json", None))
            item["missing_inventory"] = _decode_json_array(item.pop("missing_inventory_json", None))
            item["contract_hashes"] = _decode_json_array(item.pop("contract_hashes_json", None))
            item["agent_refs"] = _decode_json_array(item.pop("agent_refs_json", None))
            item["filters"] = _decode_json_object(item.pop("filters_json", None))
            item["source_chain"] = _decode_json_object(item.pop("source_chain_json", None))
            item["summary"] = _decode_json_object(item.pop("summary_json", None))

        count, eval_runs = self._agent_scoped_rows(
            table="eval_runs",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, results_hash, evaluated_at
            FROM eval_runs
            """,
            order_sql="ORDER BY evaluated_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["eval_runs"] = count

        count, gate_decisions = self._agent_scoped_rows(
            table="gate_decisions",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, outcome, passed, eval_entry_id,
                   contract_entry_id, results_hash, check_count,
                   failed_check_count, holdout_passed, approvals_passed,
                   evaluated_at
            FROM gate_decisions
            """,
            order_sql="ORDER BY evaluated_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["gate_decisions"] = count
        gate_decisions = [_bool_fields(item, "passed", "holdout_passed", "approvals_passed") for item in gate_decisions]

        count, human_approvals = self._agent_scoped_rows(
            table="human_approvals",
            select_sql="""
            SELECT entry_id, approval_hash, contract_id, contract_hash,
                   agent_name, agent_version, role, approver, source,
                   external_ref, approved_at, metadata_json
            FROM human_approvals
            """,
            order_sql="ORDER BY approved_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["human_approvals"] = count
        for item in human_approvals:
            item["metadata"] = _decode_json_object(item.pop("metadata_json", None))

        count, promotion_demotions = self._agent_scoped_rows(
            table="promotion_demotions",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, from_environment, to_environment,
                   reason, triggering_entry_id, trigger_json, decided_at
            FROM promotion_demotions
            """,
            order_sql="ORDER BY decided_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["promotion_demotions"] = count
        for item in promotion_demotions:
            item["trigger"] = _decode_json_object(item.pop("trigger_json", None))

        count, promotion_rollbacks = self._agent_scoped_rows(
            table="promotion_rollbacks",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, target_agent_version, reason,
                   triggering_entry_id, decided_at
            FROM promotion_rollbacks
            """,
            order_sql="ORDER BY decided_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["promotion_rollbacks"] = count

        count, soak_demotion_receipts = self._agent_scoped_rows(
            table="soak_demotion_receipts",
            select_sql="""
            SELECT receipt_id, entry_id, receipt_hash, contract_id,
                   contract_hash, agent_name, agent_version,
                   soak_report_entry_id, demotion_entry_id,
                   source_json, violation_count, passed, attested_at
            FROM soak_demotion_receipts
            """,
            order_sql="ORDER BY attested_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["soak_demotion_receipts"] = count
        for item in soak_demotion_receipts:
            _bool_fields(item, "passed")
            item["source"] = _decode_json_object(item.pop("source_json", None))

        count, temporal_holdout_manifests = self._hash_scoped_rows(
            table="temporal_holdout_manifests",
            select_sql="""
            SELECT manifest_id, entry_id, manifest_hash, run_id, dataset_id,
                   contract_id, contract_hash, candidate_version, record_count,
                   violation_count, passed, records_root,
                   earliest_record_timestamp, latest_record_timestamp, generated_at
            FROM temporal_holdout_manifests
            """,
            order_sql="ORDER BY generated_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["temporal_holdout_manifests"] = count
        temporal_holdout_manifests = [_bool_fields(item, "passed") for item in temporal_holdout_manifests]

        count, shadow_replays = self._hash_scoped_rows(
            table="shadow_replays",
            select_sql="""
            SELECT entry_id, run_id, contract_id, contract_hash,
                   candidate_version, replay_hash, records_checked, passed,
                   outcome, holdout_passed, holdout_error_count, check_count,
                   failed_check_count, temporal_holdout_manifest_id,
                   temporal_holdout_manifest_hash, evaluated_at, metrics_json
            FROM shadow_replays
            """,
            order_sql="ORDER BY evaluated_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["shadow_replays"] = count
        for item in shadow_replays:
            _bool_fields(item, "passed", "holdout_passed")
            item["metrics"] = _decode_json_object(item.pop("metrics_json", None))

        count, soak_reports = self._hash_scoped_rows(
            table="soak_reports",
            select_sql="""
            SELECT entry_id, report_id, contract_id, contract_hash,
                   candidate_version, soak_hash, window_count, incident_count,
                   drift_alarm_count, blocking_drift_alarm_count, passed,
                   outcome, check_count, failed_check_count, evaluated_at,
                   metrics_json
            FROM soak_reports
            """,
            order_sql="ORDER BY evaluated_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["soak_reports"] = count
        for item in soak_reports:
            _bool_fields(item, "passed")
            item["metrics"] = _decode_json_object(item.pop("metrics_json", None))

        count, traffic_holdout_exports = self._hash_scoped_rows(
            table="traffic_holdout_exports",
            select_sql="""
            SELECT export_id, entry_id, export_hash, export_ref, source_ref,
                   exporter_ref, contract_id, contract_hash, candidate_version,
                   record_count, violation_count, passed,
                   extraction_window_json, records_root,
                   earliest_record_timestamp, latest_record_timestamp,
                   produced_at
            FROM traffic_holdout_exports
            """,
            order_sql="ORDER BY produced_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["traffic_holdout_exports"] = count
        for item in traffic_holdout_exports:
            _bool_fields(item, "passed")
            item["extraction_window"] = _decode_json_object(item.pop("extraction_window_json", None))

        count, traffic_completeness_receipts = self._hash_scoped_rows(
            table="traffic_completeness_receipts",
            select_sql="""
            SELECT completeness_id, entry_id, completeness_hash, mode,
                   authority_ref, export_id, export_hash, contract_id,
                   contract_hash, candidate_version, record_count,
                   violation_count, passed, source_completeness_json,
                   provider_exchange_json, produced_at
            FROM traffic_completeness_receipts
            """,
            order_sql="ORDER BY produced_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["traffic_completeness_receipts"] = count
        for item in traffic_completeness_receipts:
            _bool_fields(item, "passed")
            item["source_completeness"] = _decode_json_object(item.pop("source_completeness_json", None))
            item["provider_exchange"] = _decode_json_object(item.pop("provider_exchange_json", None))

        count, proof_packs = self._agent_scoped_rows(
            table="proof_packs",
            select_sql="""
            SELECT pack_id, contract_id, contract_hash, agent_name,
                   agent_version, outcome, issued_at, path
            FROM proof_packs
            """,
            order_sql="ORDER BY issued_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["proof_packs"] = count

        count, ingest_events = self._agent_scoped_rows(
            table="ingest_events",
            select_sql="""
            SELECT entry_id, event_hash, contract_hash, trace_id, span_id,
                   parent_span_id, event_name, agent_name, agent_version,
                   risk_class, schema_url, observed_at, attributes_json
            FROM ingest_events
            """,
            order_sql="ORDER BY observed_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["ingest_events"] = count
        for item in ingest_events:
            item["attributes"] = _decode_json_object(item.pop("attributes_json", None))

        count, mcp_tool_calls = self._agent_scoped_rows(
            table="mcp_tool_calls",
            select_sql="""
            SELECT entry_id, session_id, request_id, tool_name,
                   contract_hash, agent_name, agent_version, risk_class,
                   request_hash, response_hash, tool_call_hash,
                   transcript_sequence, transcript_call_count,
                   previous_transcript_node_hash, transcript_node_hash,
                   transcript_root, observed_at
            FROM mcp_tool_calls
            """,
            order_sql="ORDER BY observed_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["mcp_tool_calls"] = count

        count, mcp_proxy_captures = self._agent_scoped_rows(
            table="mcp_proxy_captures",
            select_sql="""
            SELECT capture_id, entry_id, proxy_ref, upstream_ref, session_id,
                   contract_hash, agent_name, agent_version, risk_class,
                   event_count, tool_call_count, event_chain_root,
                   transcript_root, proxy_events_artifact_json,
                   event_hashes_json, tool_call_hashes_json, captured_at
            FROM mcp_proxy_captures
            """,
            order_sql="ORDER BY captured_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["mcp_proxy_captures"] = count
        for item in mcp_proxy_captures:
            item["proxy_events_artifact"] = _decode_json_object(item.pop("proxy_events_artifact_json", None))
            item["event_hashes"] = _decode_json_array(item.pop("event_hashes_json", None))
            item["tool_call_hashes"] = _decode_json_array(item.pop("tool_call_hashes_json", None))

        count, framework_hook_operations = self._agent_scoped_rows(
            table="framework_hook_operations",
            select_sql="""
            SELECT operation_id, entry_id, operation_hash, mode, environment,
                   contract_hash, agent_name, agent_version, risk_class,
                   framework, runtime_package, runtime_version,
                   hook_package, hook_version, collector_hook_ref,
                   hook_release_hash, source_trace_id, trace_id,
                   event_count, event_root, runtime_json, hook_json,
                   release_binding_json, trace_json, collector_json,
                   control_summary_json, captured_at
            FROM framework_hook_operations
            """,
            order_sql="ORDER BY captured_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["framework_hook_operations"] = count
        for item in framework_hook_operations:
            item["runtime"] = _decode_json_object(item.pop("runtime_json", None))
            item["hook"] = _decode_json_object(item.pop("hook_json", None))
            item["release_binding"] = _decode_json_object(item.pop("release_binding_json", None))
            item["trace"] = _decode_json_object(item.pop("trace_json", None))
            item["collector"] = _decode_json_object(item.pop("collector_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))

        count, promotion_statuses = self._agent_scoped_rows(
            table="promotion_statuses",
            select_sql="""
            SELECT receipt_id, provider, pack_id, contract_id, contract_hash,
                   agent_name, agent_version, gate_outcome, passed,
                   provider_status_kind, provider_status_success,
                   target_ref_json, violation_count, attested_at
            FROM promotion_statuses
            """,
            order_sql="ORDER BY attested_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["promotion_statuses"] = count
        for item in promotion_statuses:
            _bool_fields(item, "passed", "provider_status_success")
            item["target_ref"] = _decode_json_object(item.pop("target_ref_json", None))

        count, runtime_attestations = self._hash_scoped_rows(
            table="runtime_attestations",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, action_hash,
                   action_id, action_type, risk_class, passed, outcome,
                   check_count, failed_check_count, attested_at
            FROM runtime_attestations
            """,
            order_sql="ORDER BY attested_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["runtime_attestations"] = count
        runtime_attestations = [_bool_fields(item, "passed") for item in runtime_attestations]

        count, policy_decisions = self._hash_scoped_rows(
            table="policy_decisions",
            select_sql="""
            SELECT entry_id, policy_pack_id, policy_pack_version,
                   policy_pack_hash, contract_hash, action_hash, passed,
                   outcome, matched_rule_count, check_count,
                   failed_check_count, evaluated_at
            FROM policy_decisions
            """,
            order_sql="ORDER BY evaluated_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["policy_decisions"] = count
        policy_decisions = [_bool_fields(item, "passed") for item in policy_decisions]

        count, policy_engine_receipts = self._hash_scoped_rows(
            table="policy_engine_receipts",
            select_sql="""
            SELECT receipt_id, entry_id, engine_name, engine_mode,
                   policy_pack_id, policy_pack_version, policy_pack_hash,
                   action_hash, action_id, action_type, risk_class,
                   pack_id, contract_id, contract_hash, decision_entry_id,
                   decision_outcome, decision_passed, evaluated_at
            FROM policy_engine_receipts
            """,
            order_sql="ORDER BY evaluated_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["policy_engine_receipts"] = count
        policy_engine_receipts = [_bool_fields(item, "decision_passed") for item in policy_engine_receipts]

        count, incidents = self._agent_scoped_rows(
            table="incidents",
            select_sql="""
            SELECT incident_id, entry_id, contract_hash, agent_name,
                   agent_version, severity, summary, detected_at
            FROM incidents
            """,
            order_sql="ORDER BY detected_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["incidents"] = count

        return {
            "scope": {"agent_name": agent_name, "agent_version": agent_version},
            "contract_hashes": contract_hashes,
            "counts": counts,
            "agents": agents,
            "contracts": contracts,
            "chain_entries": chain_entries,
            "agent_delegations": agent_delegations,
            "agent_delegation_graphs": agent_delegation_graphs,
            "eval_runs": eval_runs,
            "gate_decisions": gate_decisions,
            "human_approvals": human_approvals,
            "promotion_demotions": promotion_demotions,
            "promotion_rollbacks": promotion_rollbacks,
            "soak_demotion_receipts": soak_demotion_receipts,
            "temporal_holdout_manifests": temporal_holdout_manifests,
            "shadow_replays": shadow_replays,
            "soak_reports": soak_reports,
            "traffic_holdout_exports": traffic_holdout_exports,
            "traffic_completeness_receipts": traffic_completeness_receipts,
            "proof_packs": proof_packs,
            "ingest_events": ingest_events,
            "mcp_tool_calls": mcp_tool_calls,
            "mcp_proxy_captures": mcp_proxy_captures,
            "framework_hook_operations": framework_hook_operations,
            "promotion_statuses": promotion_statuses,
            "runtime_attestations": runtime_attestations,
            "policy_decisions": policy_decisions,
            "policy_engine_receipts": policy_engine_receipts,
            "incidents": incidents,
        }

    def agents(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT name, version, owner, risk_class, governed, source, observed_at
            FROM agents
            ORDER BY name, version
            """
        ).fetchall()
        return [dict(row) for row in rows]



