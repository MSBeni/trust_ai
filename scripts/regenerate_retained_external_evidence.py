#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from trustai.canonical import content_hash, without_keys
from trustai.external_evidence import (
    build_external_evidence_manifest,
    build_external_evidence_source_map_template,
    build_external_evidence_source_snapshot,
    load_external_evidence_collection_plan,
    parse_evidence_arg,
    verify_external_evidence_manifest,
    verify_external_evidence_source_snapshot,
    write_external_evidence_markdown,
    write_external_evidence_manifest,
    write_external_evidence_source_snapshot,
)
from trustai.roadmap_audit import (
    build_roadmap_audit,
    verify_roadmap_audit,
    write_roadmap_audit,
)

DIR = Path("examples/aitrade/external-evidence")
NOW = "2026-07-12T00:00:00Z"
AUDIT_TIME = "2026-07-12T00:00:00Z"
COLLECTION_TIME = "2026-07-12T00:01:00Z"
MAP_TIME = "2026-07-12T01:00:00Z"

RETAINED_SOURCES: dict[str, dict[str, str]] = {
    "oss-verifier-and-public-spec:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/go-verifier.yml",
        "description": "Go verifier release workflow CI authority export",
        "artifact": "examples/aitrade/external-evidence/github-actions-workflow-run-source-snapshot.json",
        "source_file": "examples/aitrade/oss-verifier-ci-run-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "trustai OSS verifier public spec and release workflow CI",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-actions-workflow-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/oss-verifier-ci-run.json",
    },
    "oss-verifier-and-public-spec:provider-api": {
        "source_uri": "git+https://github.com/MSBeni/trust_ai.git#refs/heads/main",
        "description": "GitHub remote main ref advertisement for pushed TrustAI checkpoint",
        "artifact": "examples/aitrade/external-evidence/github-main-ref-source-snapshot.json",
        "retrieval_method": "git-ls-remote",
        "content_type": "application/json",
        "issuer": "GitHub Git",
        "subject": "MSBeni/trust_ai main branch",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-main-ref-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/oss-verifier-provider-api.json",
    },
    "oss-verifier-and-public-spec:hosted-service": {
        "source_uri": "git+https://github.com/MSBeni/trust_ai.git#HEAD",
        "description": "GitHub hosted git service remote advertisement for TrustAI verifier and spec repository",
        "artifact": "examples/aitrade/external-evidence/github-hosted-service-source-snapshot.json",
        "retrieval_method": "git-ls-remote",
        "content_type": "application/json",
        "issuer": "GitHub Git",
        "subject": "MSBeni/trust_ai hosted repository service",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/oss-verifier-hosted-service.json",
    },
    "self-serve-onboarding:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/self-serve-provider-api-authority-export.json?ref=main",
        "description": "Retained provider API export for self-serve tenant and SDK provisioning evidence",
        "artifact": "examples/aitrade/external-evidence/self-serve-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/self-serve-provider-api-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud Provider API",
        "subject": "aitrade self-serve onboarding provider API",
        "issued_at": "2026-07-11T20:11:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/self-serve-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/self-serve-onboarding-provider-api.json",
    },
    "self-serve-onboarding:hosted-service": {
        "source_uri": "https://status.trustai.example/self-serve/aitrade/signup-prod",
        "description": "Retained hosted service export for self-serve signup and quickstart completion evidence",
        "artifact": "examples/aitrade/external-evidence/self-serve-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/self-serve-hosted-service-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud",
        "subject": "aitrade self-serve onboarding hosted service",
        "issued_at": "2026-07-11T20:10:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/self-serve-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/self-serve-onboarding-hosted-service.json",
    },
    "self-serve-onboarding:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/self-serve/signup-prod",
        "description": "Retained identity-provider export for self-serve OIDC, MFA, and tenant-admin sessions",
        "artifact": "examples/aitrade/external-evidence/self-serve-identity-provider-source-snapshot.json",
        "source_file": "examples/aitrade/self-serve-identity-provider-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example IdP",
        "subject": "aitrade self-serve onboarding identity federation",
        "issued_at": "2026-07-11T20:12:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/self-serve-identity-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/self-serve-onboarding-identity-provider.json",
    },
    "cicd-provider-approvals:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions",
        "description": "Retained GitHub check-suite callback export for CI/CD promotion provider evidence",
        "artifact": "examples/aitrade/external-evidence/github-check-suite-source-snapshot.json",
        "source_file": "examples/webhooks/github-check-suite.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Checks",
        "subject": "trustai GitHub check-suite promotion callback",
        "issued_at": "2026-07-08T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-check-suite-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-ci-run.json",
    },
    "cicd-provider-approvals:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/actions/runs",
        "description": "Retained GitHub audit-log export for CI/CD promotion provider API evidence",
        "artifact": "examples/aitrade/external-evidence/github-audit-log-source-snapshot.json",
        "source_file": "examples/webhooks/github-audit-log.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Audit Log",
        "subject": "trustai GitHub provider audit-log export",
        "issued_at": "2026-07-08T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/github-audit-log-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-provider-api.json",
    },
    "cicd-provider-approvals:hosted-service": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/python-ci.yml",
        "description": "Retained GitHub hosted checks export for CI/CD promotion approval service evidence",
        "artifact": "examples/aitrade/external-evidence/cicd-provider-approvals-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/cicd-provider-approvals-hosted-service-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Hosted Checks",
        "subject": "trustai CI/CD promotion approval hosted service",
        "issued_at": "2026-07-08T00:02:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/cicd-provider-approvals-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-hosted-service.json",
    },
    "cicd-provider-approvals:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/cicd-approvals/reviewer-sessions",
        "description": "Retained identity-provider export for CI/CD promotion reviewer approval sessions",
        "artifact": "examples/aitrade/external-evidence/cicd-provider-approvals-identity-provider-source-snapshot.json",
        "source_file": "examples/aitrade/cicd-provider-approvals-identity-provider-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example IdP",
        "subject": "aitrade CI/CD promotion reviewer identity federation",
        "issued_at": "2026-07-08T00:03:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/cicd-provider-approvals-identity-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/cicd-provider-approvals-identity-provider.json",
    },
    "design-partner-pilot-exit-criteria:regulator": {
        "source_uri": "https://regulator.example/exports/trustai/design-partner/proof-pack-scrutiny",
        "description": "Retained regulator export for design-partner proof-pack scrutiny survival evidence",
        "artifact": "examples/aitrade/external-evidence/design-partner-regulator-source-snapshot.json",
        "source_file": "examples/aitrade/design-partner-regulator-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example Regulator",
        "subject": "TrustAI design-partner proof-pack scrutiny survival",
        "issued_at": "2026-07-11T23:10:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/design-partner-regulator-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/design-partner-pilot-exit-criteria-regulator.json",
    },
    "design-partner-pilot-exit-criteria:insurer": {
        "source_uri": "https://insurer.example/exports/trustai/design-partner/underwriting-review",
        "description": "Retained insurer export for design-partner underwriting review evidence",
        "artifact": "examples/aitrade/external-evidence/design-partner-insurer-source-snapshot.json",
        "source_file": "examples/aitrade/design-partner-insurer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example AI Liability Underwriter",
        "subject": "TrustAI design-partner underwriting review",
        "issued_at": "2026-07-11T23:11:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/design-partner-insurer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/design-partner-pilot-exit-criteria-insurer.json",
    },
    "design-partner-pilot-exit-criteria:customer": {
        "source_uri": "https://customer.example/exports/trustai/design-partner/paid-pilot-acceptance",
        "description": "Retained customer export for design-partner paid pilot acceptance evidence",
        "artifact": "examples/aitrade/external-evidence/design-partner-customer-source-snapshot.json",
        "source_file": "examples/aitrade/design-partner-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example Customer",
        "subject": "TrustAI design-partner paid pilot acceptance",
        "issued_at": "2026-07-11T23:12:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/design-partner-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/design-partner-pilot-exit-criteria-customer.json",
    },
    "framework-adapters:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/python-ci.yml",
        "description": "Retained GitHub Actions export for framework adapter hook release CI evidence",
        "artifact": "examples/aitrade/external-evidence/framework-adapters-ci-run-source-snapshot.json",
        "source_file": "examples/aitrade/framework-adapters-ci-run-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "trustai framework adapter release CI",
        "issued_at": "2026-07-09T00:35:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/framework-adapters-ci-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/framework-adapters-ci-run.json",
    },
    "framework-adapters:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/framework-hook-release.json?ref=main",
        "description": "Retained GitHub contents API export for framework adapter hook release evidence",
        "artifact": "examples/aitrade/external-evidence/framework-hook-release-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/framework-hook-release.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Contents API",
        "subject": "trustai framework hook release export",
        "issued_at": "2026-07-09T00:30:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/framework-hook-release-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/framework-adapters-provider-api.json",
    },
    "framework-adapters:hosted-service": {
        "source_uri": "https://github.com/MSBeni/trust_ai/blob/main/examples/aitrade/framework-hook-release.json",
        "description": "Retained GitHub hosted file export for framework adapter hook release evidence",
        "artifact": "examples/aitrade/external-evidence/framework-hook-release-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/framework-hook-release.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Hosted Repository",
        "subject": "trustai framework hook release export",
        "issued_at": "2026-07-09T00:30:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/framework-hook-release-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/framework-adapters-hosted-service.json",
    },
    "auditor-and-review-portal:kms-hsm": {
        "source_uri": "https://kms.example/attestations/trustai/review-portal/session-data-encryption",
        "description": "Retained KMS/HSM export for review portal session and disclosed artifact encryption evidence",
        "artifact": "examples/aitrade/external-evidence/review-portal-kms-hsm-source-snapshot.json",
        "source_file": "examples/aitrade/review-portal-kms-hsm-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example KMS/HSM",
        "subject": "aitrade review portal KMS-backed session encryption",
        "issued_at": "2026-07-08T06:12:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/review-portal-kms-hsm-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/auditor-and-review-portal-kms-hsm.json",
    },
    "auditor-and-review-portal:provider-api": {
        "source_uri": "https://api.trustai.example/v1/review-portals/aitrade-prod/authority-dossier",
        "description": "Retained provider API export for review portal authority dossier and control evidence",
        "artifact": "examples/aitrade/external-evidence/review-portal-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/review-portal-provider-api-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud Provider API",
        "subject": "aitrade review portal provider API authority dossier export",
        "issued_at": "2026-07-08T06:13:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/review-portal-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/auditor-and-review-portal-provider-api.json",
    },
    "auditor-and-review-portal:hosted-service": {
        "source_uri": "https://review.trustai.example/aitrade/regulator/.well-known/trustai-authority",
        "description": "Retained hosted service export for review portal worker fleet and service health evidence",
        "artifact": "examples/aitrade/external-evidence/review-portal-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/review-portal-hosted-service-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud",
        "subject": "aitrade review portal hosted service authority export",
        "issued_at": "2026-07-08T06:14:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/review-portal-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/auditor-and-review-portal-hosted-service.json",
    },
    "auditor-and-review-portal:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/review-portal/reviewer-sessions",
        "description": "Retained identity-provider export for review portal reviewer sessions and account lifecycle evidence",
        "artifact": "examples/aitrade/external-evidence/review-portal-identity-provider-source-snapshot.json",
        "source_file": "examples/aitrade/review-portal-identity-provider-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example IdP",
        "subject": "aitrade review portal reviewer identity-provider authority export",
        "issued_at": "2026-07-08T06:15:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/review-portal-identity-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/auditor-and-review-portal-identity-provider.json",
    },
    "auditor-and-review-portal:regulator": {
        "source_uri": "https://regulator.example/exports/aitrade/review-portal/supervised-access-acceptance",
        "description": "Retained regulator export for review portal supervised-access acceptance evidence",
        "artifact": "examples/aitrade/external-evidence/review-portal-regulator-source-snapshot.json",
        "source_file": "examples/aitrade/review-portal-regulator-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example Regulator",
        "subject": "aitrade review portal regulator supervised-access acceptance export",
        "issued_at": "2026-07-08T06:16:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/review-portal-regulator-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/auditor-and-review-portal-regulator.json",
    },
    "agent-inventory-and-identity:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/agent-inventory.json?ref=main",
        "description": "Retained GitHub contents API export for agent registry inventory evidence",
        "artifact": "examples/aitrade/external-evidence/agent-inventory-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/agent-inventory.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Contents API",
        "subject": "trustai agent registry inventory export",
        "issued_at": "2026-07-03T11:55:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/agent-inventory-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/agent-inventory-and-identity-provider-api.json",
    },
    "agent-inventory-and-identity:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/identity-inventory",
        "description": "Retained identity-provider export for governed agent inventory reconciliation evidence",
        "artifact": "examples/aitrade/external-evidence/identity-inventory-provider-source-snapshot.json",
        "source_file": "examples/aitrade/identity-inventory.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Identity Provider Export",
        "subject": "aitrade governed agent identity inventory",
        "issued_at": "2026-07-03T11:57:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/identity-inventory-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/agent-inventory-and-identity-identity-provider.json",
    },
    "mcp-gateway:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/python-ci.yml",
        "description": "Retained GitHub Actions export for MCP gateway proxy capture and authority test evidence",
        "artifact": "examples/aitrade/external-evidence/mcp-gateway-ci-run-source-snapshot.json",
        "source_file": "examples/aitrade/mcp-gateway-ci-run-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "trustai MCP gateway reference capture CI",
        "issued_at": "2026-07-03T12:06:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/mcp-gateway-ci-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/mcp-gateway-ci-run.json",
    },
    "mcp-gateway:kms-hsm": {
        "source_uri": "https://kms.example/attestations/trustai/mcp-gateway/evidence-signing",
        "description": "Retained KMS/HSM export for MCP gateway evidence-signing enforcement",
        "artifact": "examples/aitrade/external-evidence/mcp-gateway-kms-hsm-source-snapshot.json",
        "source_file": "examples/aitrade/mcp-gateway-kms-hsm-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example KMS/HSM",
        "subject": "trustai MCP gateway evidence-signing enforcement",
        "issued_at": "2026-07-03T12:07:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/mcp-gateway-kms-hsm-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/mcp-gateway-kms-hsm.json",
    },
    "mcp-gateway:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/mcp-proxy-events.json?ref=main",
        "description": "Retained GitHub contents API export for MCP gateway proxy event evidence",
        "artifact": "examples/aitrade/external-evidence/mcp-proxy-events-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/mcp-proxy-events.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Contents API",
        "subject": "trustai MCP proxy event export",
        "issued_at": "2026-07-03T12:05:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/mcp-proxy-events-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/mcp-gateway-provider-api.json",
    },
    "mcp-gateway:hosted-service": {
        "source_uri": "https://github.com/MSBeni/trust_ai/blob/main/examples/aitrade/mcp-proxy-events.json",
        "description": "Retained GitHub hosted file export for MCP gateway proxy event evidence",
        "artifact": "examples/aitrade/external-evidence/mcp-proxy-events-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/mcp-proxy-events.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Hosted Repository",
        "subject": "trustai MCP proxy event export",
        "issued_at": "2026-07-03T12:05:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/mcp-proxy-events-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/mcp-gateway-hosted-service.json",
    },
    "runtime-policy-and-attestation:kms-hsm": {
        "source_uri": "https://kms.example/attestations/trustai/runtime-policy/evidence-signing",
        "description": "Retained KMS/HSM enforcement export for runtime policy evidence signing",
        "artifact": "examples/aitrade/external-evidence/runtime-policy-kms-hsm-source-snapshot.json",
        "source_file": "examples/aitrade/trust-authority-kms-response.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example KMS/HSM",
        "subject": "trustai runtime policy evidence-signing enforcement",
        "issued_at": "2026-07-03T12:03:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/runtime-policy-kms-hsm-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-kms-hsm.json",
    },
    "runtime-policy-and-attestation:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/policy-pack.json?ref=main",
        "description": "Retained GitHub contents API export for runtime policy pack evidence",
        "artifact": "examples/aitrade/external-evidence/runtime-policy-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/policy-pack.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Contents API",
        "subject": "trustai runtime policy pack export",
        "issued_at": "2026-07-03T12:02:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/runtime-policy-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-provider-api.json",
    },
    "runtime-policy-and-attestation:hosted-service": {
        "source_uri": "https://github.com/MSBeni/trust_ai/blob/main/examples/aitrade/runtime-action.json",
        "description": "Retained GitHub hosted file export for runtime action attestation evidence",
        "artifact": "examples/aitrade/external-evidence/runtime-action-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/runtime-action.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Hosted Repository",
        "subject": "trustai runtime action attestation export",
        "issued_at": "2026-07-03T12:00:12Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/runtime-action-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-hosted-service.json",
    },
    "runtime-policy-and-attestation:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/runtime-policy-agent-identity",
        "description": "Retained identity-provider export for runtime policy agent identity binding evidence",
        "artifact": "examples/aitrade/external-evidence/runtime-policy-identity-provider-source-snapshot.json",
        "source_file": "examples/aitrade/identity-inventory.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Identity Provider Export",
        "subject": "aitrade runtime policy governed agent identity binding",
        "issued_at": "2026-07-03T11:57:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/runtime-policy-identity-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-identity-provider.json",
    },
    "shadow-replay-temporal-holdout:kms-hsm": {
        "source_uri": "https://kms.example/attestations/trustai/shadow-holdout/evidence-signing",
        "description": "Retained KMS/HSM enforcement export for shadow replay temporal holdout evidence signing",
        "artifact": "examples/aitrade/external-evidence/shadow-holdout-kms-hsm-source-snapshot.json",
        "source_file": "examples/aitrade/trust-authority-kms-response.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example KMS/HSM",
        "subject": "trustai shadow replay temporal holdout evidence-signing enforcement",
        "issued_at": "2026-07-03T12:03:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/shadow-holdout-kms-hsm-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-kms-hsm.json",
    },
    "shadow-replay-temporal-holdout:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/traffic-completeness-provider-export.json?ref=main",
        "description": "Retained provider API export for traffic holdout completeness evidence",
        "artifact": "examples/aitrade/external-evidence/traffic-completeness-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/traffic-completeness-provider-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Traffic Completeness Provider API",
        "subject": "aitrade production traffic holdout completeness export",
        "issued_at": "2026-07-03T12:23:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/traffic-completeness-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-provider-api.json",
    },
    "shadow-replay-temporal-holdout:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/shadow-holdout-agent-identity",
        "description": "Retained identity-provider export for shadow holdout agent identity binding evidence",
        "artifact": "examples/aitrade/external-evidence/shadow-holdout-identity-provider-source-snapshot.json",
        "source_file": "examples/aitrade/identity-inventory.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Identity Provider Export",
        "subject": "aitrade shadow holdout governed agent identity binding",
        "issued_at": "2026-07-03T11:57:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/shadow-holdout-identity-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-identity-provider.json",
    },
    "shadow-replay-temporal-holdout:standards-body": {
        "source_uri": "https://standards.example/lf-trustai/ballots/LF-TRUSTAI-BALLOT-2026-001",
        "description": "Retained standards-body ballot system response for temporal holdout evidence semantics",
        "artifact": "examples/aitrade/external-evidence/shadow-holdout-standards-body-source-snapshot.json",
        "source_file": "examples/aitrade/standards-ballot-system-response.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "LF TrustAI Ballot System",
        "subject": "trustai temporal holdout standards ballot system response",
        "issued_at": "2026-07-03T12:04:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/shadow-holdout-standards-body-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-standards-body.json",
    },
    "shadow-replay-temporal-holdout:customer": {
        "source_uri": "https://customer.example/exports/aitrade/shadow-holdout/customer-acceptance",
        "description": "Retained customer acceptance export for shadow replay temporal holdout review evidence",
        "artifact": "examples/aitrade/external-evidence/shadow-holdout-customer-source-snapshot.json",
        "source_file": "examples/aitrade/shadow-holdout-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example Aitrade Customer",
        "subject": "aitrade shadow replay temporal holdout customer acceptance",
        "issued_at": "2026-07-03T13:12:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/shadow-holdout-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/shadow-replay-temporal-holdout-customer.json",
    },
    "byoc-self-hosted:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/python-ci.yml",
        "description": "Retained GitHub Actions export for BYOC deployment, operator, and authority validation CI evidence",
        "artifact": "examples/aitrade/external-evidence/byoc-ci-run-source-snapshot.json",
        "source_file": "examples/aitrade/byoc-ci-run-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "trustai BYOC/self-hosted deployment validation CI",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/byoc-ci-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/byoc-self-hosted-ci-run.json",
    },
    "byoc-self-hosted:standards-body": {
        "source_uri": "https://standards.example/lf-trustai/profiles/byoc-self-hosted/LF-TRUSTAI-BYOC-SELF-HOSTED-0.1",
        "description": "Retained standards-body profile export for BYOC/self-hosted deployment evidence semantics",
        "artifact": "examples/aitrade/external-evidence/byoc-standards-body-source-snapshot.json",
        "source_file": "examples/aitrade/byoc-standards-body-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "LF TrustAI Ballot System",
        "subject": "trustai BYOC/self-hosted standards profile acceptance",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/byoc-standards-body-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/byoc-self-hosted-standards-body.json",
    },
    "byoc-self-hosted:customer": {
        "source_uri": "https://customers.example/aitrade/model-risk/byoc-self-hosted/acceptance/2026-07-12",
        "description": "Retained customer acceptance export for aitrade BYOC/self-hosted deployment evidence",
        "artifact": "examples/aitrade/external-evidence/byoc-customer-source-snapshot.json",
        "source_file": "examples/aitrade/byoc-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Aitrade Model Risk Committee",
        "subject": "aitrade BYOC/self-hosted TrustAI deployment acceptance",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/byoc-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/byoc-self-hosted-customer.json",
    },
    "byoc-self-hosted:provider-api": {
        "source_uri": "https://api.github.com/repos/MSBeni/trust_ai/contents/examples/aitrade/byoc-network-policy-authority-export.json?ref=main",
        "description": "Retained provider API export for BYOC NetworkPolicy admission and audit evidence",
        "artifact": "examples/aitrade/external-evidence/byoc-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/byoc-network-policy-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example Kubernetes API",
        "subject": "aitrade BYOC NetworkPolicy admission export",
        "issued_at": "2026-07-04T03:07:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/byoc-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/byoc-self-hosted-provider-api.json",
    },
    "byoc-self-hosted:kms-hsm": {
        "source_uri": "https://kms.example/attestations/trustai/byoc/evidence-signing",
        "description": "Retained KMS/HSM enforcement export for BYOC evidence signing",
        "artifact": "examples/aitrade/external-evidence/byoc-kms-hsm-source-snapshot.json",
        "source_file": "examples/aitrade/trust-authority-kms-response.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example KMS/HSM",
        "subject": "trustai BYOC evidence-signing enforcement",
        "issued_at": "2026-07-03T12:03:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/byoc-kms-hsm-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/byoc-self-hosted-kms-hsm.json",
    },
    "byoc-self-hosted:cloud-object-lock": {
        "source_uri": "https://cloud.example/s3/trustai-aitrade-evidence/object-lock",
        "description": "Retained cloud Object Lock export for BYOC immutable evidence storage",
        "artifact": "examples/aitrade/external-evidence/byoc-object-lock-source-snapshot.json",
        "source_file": "examples/aitrade/byoc-object-lock-provider-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example S3 Object Lock",
        "subject": "trustai-aitrade-evidence BYOC Object Lock configuration",
        "issued_at": "2026-07-04T03:06:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/byoc-object-lock-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/byoc-self-hosted-cloud-object-lock.json",
    },
    "compliance-mapper-and-eu-ai-act:provider-api": {
        "source_uri": "https://api.trustai.example/v1/compliance/aitrade-prod/evidence",
        "description": "Retained provider API export for compliance mapper and EU AI Act evidence",
        "artifact": "examples/aitrade/external-evidence/compliance-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/compliance-provider-api-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud Provider API",
        "subject": "aitrade compliance mapper and EU AI Act provider API evidence",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/compliance-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/compliance-mapper-and-eu-ai-act-provider-api.json",
    },
    "compliance-mapper-and-eu-ai-act:regulator": {
        "source_uri": "https://regulator.example/exports/aitrade/compliance/eu-ai-act-supervisory-acknowledgement",
        "description": "Retained regulator acknowledgement export for compliance mapper and EU AI Act evidence",
        "artifact": "examples/aitrade/external-evidence/compliance-regulator-source-snapshot.json",
        "source_file": "examples/aitrade/compliance-regulator-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example Regulator",
        "subject": "aitrade compliance mapper and EU AI Act regulator acceptance export",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/compliance-regulator-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/compliance-mapper-and-eu-ai-act-regulator.json",
    },
    "compliance-mapper-and-eu-ai-act:standards-body": {
        "source_uri": "https://standards.example/lf-trustai/compliance-mapper/eu-ai-act/2026-07-12",
        "description": "Retained standards-body submission export for compliance mapper and EU AI Act evidence",
        "artifact": "examples/aitrade/external-evidence/compliance-standards-body-source-snapshot.json",
        "source_file": "examples/aitrade/compliance-standards-body-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "LF TrustAI Ballot System",
        "subject": "aitrade compliance mapper and EU AI Act standards-body submission export",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/compliance-standards-body-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/compliance-mapper-and-eu-ai-act-standards-body.json",
    },
    "trustai-own-compliance:standards-body": {
        "source_uri": "https://standards.example/lf-trustai/own-compliance/soc2-iso42001/2026-07-12",
        "description": "Retained standards-body docket export for TrustAI own SOC 2 Type II and ISO/IEC 42001 compliance evidence",
        "artifact": "examples/aitrade/external-evidence/trustai-own-compliance-standards-body-source-snapshot.json",
        "source_file": "examples/aitrade/trustai-own-compliance-standards-body-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "LF TrustAI Ballot System",
        "subject": "TrustAI own SOC 2 Type II and ISO/IEC 42001 standards-body dossier review",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/trustai-own-compliance-standards-body-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/trustai-own-compliance-standards-body.json",
    },
    "trustai-own-compliance:customer": {
        "source_uri": "https://customers.example/aitrade/model-risk/trustai-own-compliance/soc2-iso42001/2026-07-12",
        "description": "Retained customer acceptance export for TrustAI own SOC 2 Type II and ISO/IEC 42001 compliance evidence",
        "artifact": "examples/aitrade/external-evidence/trustai-own-compliance-customer-source-snapshot.json",
        "source_file": "examples/aitrade/trustai-own-compliance-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Aitrade Model Risk Committee",
        "subject": "TrustAI own SOC 2 Type II and ISO/IEC 42001 customer due-diligence acceptance",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/trustai-own-compliance-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/trustai-own-compliance-customer.json",
    },
    "vertical-packs:regulator": {
        "source_uri": "https://regulator.example/exports/trustai/vertical-packs/reference-supervisory-review/2026-07-12",
        "description": "Retained regulator acknowledgement export for TrustAI vertical-pack reference review evidence",
        "artifact": "examples/aitrade/external-evidence/vertical-packs-regulator-source-snapshot.json",
        "source_file": "examples/aitrade/vertical-packs-regulator-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example Regulator",
        "subject": "TrustAI vertical-pack supervisory reference review export",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/vertical-packs-regulator-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/vertical-packs-regulator.json",
    },
    "vertical-packs:insurer": {
        "source_uri": "https://insurer.example/exports/trustai/vertical-packs/reference-underwriting-review/2026-07-12",
        "description": "Retained insurer underwriting export for TrustAI vertical-pack reference evidence",
        "artifact": "examples/aitrade/external-evidence/vertical-packs-insurer-source-snapshot.json",
        "source_file": "examples/aitrade/vertical-packs-insurer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example AI Liability Underwriter",
        "subject": "TrustAI vertical-pack underwriting reference review export",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/vertical-packs-insurer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/vertical-packs-insurer.json",
    },
    "vertical-packs:customer": {
        "source_uri": "https://customers.example/aitrade/model-risk/vertical-packs/reference-acceptance/2026-07-12",
        "description": "Retained customer acceptance export for TrustAI vertical-pack reference evidence",
        "artifact": "examples/aitrade/external-evidence/vertical-packs-customer-source-snapshot.json",
        "source_file": "examples/aitrade/vertical-packs-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Aitrade Model Risk Committee",
        "subject": "TrustAI vertical-pack customer reference acceptance export",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/vertical-packs-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/vertical-packs-customer.json",
    },
    "insurer-api-and-actuarial-products:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/python-ci.yml",
        "description": "Retained GitHub Actions export for insurer API and actuarial products CI evidence",
        "artifact": "examples/aitrade/external-evidence/insurer-api-actuarial-ci-run-source-snapshot.json",
        "source_file": "examples/aitrade/insurer-api-and-actuarial-products-ci-run-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "trustai insurer API and actuarial products CI",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/insurer-api-actuarial-ci-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/insurer-api-and-actuarial-products-ci-run.json",
    },
    "insurer-api-and-actuarial-products:kms-hsm": {
        "source_uri": "https://kms.example/attestations/trustai/insurer-api-actuarial-products/evidence-signing",
        "description": "Retained KMS/HSM export for insurer API and actuarial products evidence signing",
        "artifact": "examples/aitrade/external-evidence/insurer-api-actuarial-kms-hsm-source-snapshot.json",
        "source_file": "examples/aitrade/insurer-api-and-actuarial-products-kms-hsm-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example KMS/HSM",
        "subject": "trustai insurer API and actuarial products KMS/HSM evidence-signing enforcement",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/insurer-api-actuarial-kms-hsm-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/insurer-api-and-actuarial-products-kms-hsm.json",
    },
    "insurer-api-and-actuarial-products:provider-api": {
        "source_uri": "https://api.trustai.example/v1/insurer/aitrade/authority-evidence",
        "description": "Retained provider API export for insurer API and actuarial products evidence",
        "artifact": "examples/aitrade/external-evidence/insurer-api-actuarial-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/insurer-api-and-actuarial-products-provider-api-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud Provider API",
        "subject": "aitrade insurer API and actuarial products provider API evidence",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/insurer-api-actuarial-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/insurer-api-and-actuarial-products-provider-api.json",
    },
    "insurer-api-and-actuarial-products:hosted-service": {
        "source_uri": "https://status.trustai.example/insurer/aitrade/actuarial-products",
        "description": "Retained hosted service export for insurer API and actuarial products evidence",
        "artifact": "examples/aitrade/external-evidence/insurer-api-actuarial-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/insurer-api-and-actuarial-products-hosted-service-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud",
        "subject": "aitrade insurer API and actuarial products hosted service evidence",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/insurer-api-actuarial-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/insurer-api-and-actuarial-products-hosted-service.json",
    },
    "insurer-api-and-actuarial-products:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/insurer-api-actuarial-products/partner-sessions",
        "description": "Retained identity-provider export for insurer API and actuarial products evidence",
        "artifact": "examples/aitrade/external-evidence/insurer-api-actuarial-identity-provider-source-snapshot.json",
        "source_file": "examples/aitrade/insurer-api-and-actuarial-products-identity-provider-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example IdP",
        "subject": "aitrade insurer API and actuarial products identity-provider evidence",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/insurer-api-actuarial-identity-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/insurer-api-and-actuarial-products-identity-provider.json",
    },
    "insurer-api-and-actuarial-products:insurer": {
        "source_uri": "https://insurer.example/exports/aitrade/insurer-api-actuarial-products/underwriting-review/2026-07-12",
        "description": "Retained insurer underwriting export for insurer API and actuarial products evidence",
        "artifact": "examples/aitrade/external-evidence/insurer-api-actuarial-insurer-source-snapshot.json",
        "source_file": "examples/aitrade/insurer-api-and-actuarial-products-insurer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example AI Liability Underwriter",
        "subject": "aitrade insurer API and actuarial products underwriting review evidence",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/insurer-api-actuarial-insurer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/insurer-api-and-actuarial-products-insurer.json",
    },
    "insurer-api-and-actuarial-products:customer": {
        "source_uri": "https://customers.example/aitrade/model-risk/insurer-api-actuarial-products/reference-acceptance/2026-07-12",
        "description": "Retained customer acceptance export for insurer API and actuarial products evidence",
        "artifact": "examples/aitrade/external-evidence/insurer-api-actuarial-customer-source-snapshot.json",
        "source_file": "examples/aitrade/insurer-api-and-actuarial-products-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Aitrade Model Risk Committee",
        "subject": "aitrade insurer API and actuarial products customer acceptance evidence",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/insurer-api-actuarial-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/insurer-api-and-actuarial-products-customer.json",
    },
    "state-of-agent-reliability-report:customer": {
        "source_uri": "https://customers.example/aitrade/model-risk/state-of-agent-reliability-report/reference-acceptance/2026-07-12",
        "description": "Retained customer export for state-of-agent-reliability-report evidence",
        "artifact": "examples/aitrade/external-evidence/state-of-agent-reliability-report-customer-source-snapshot.json",
        "source_file": "examples/aitrade/state-of-agent-reliability-report-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Aitrade Model Risk Committee",
        "subject": "TrustAI state of agent reliability report customer customer publication acceptance",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/state-of-agent-reliability-report-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/state-of-agent-reliability-report-customer.json",
    },
    "roadmap-phase-scoreboard:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/python-ci.yml",
        "description": "Retained ci-run export for roadmap-phase-scoreboard evidence",
        "artifact": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-ci-run-source-snapshot.json",
        "source_file": "examples/aitrade/roadmap-phase-scoreboard-ci-run-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "TrustAI roadmap phase scoreboard ci run phase scoreboard CI verification",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-ci-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/roadmap-phase-scoreboard-ci-run.json",
    },
    "roadmap-phase-scoreboard:regulator": {
        "source_uri": "https://regulator.example/exports/trustai/roadmap-phase-scoreboard/supervisory-review/2026-07-12",
        "description": "Retained regulator export for roadmap-phase-scoreboard evidence",
        "artifact": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-regulator-source-snapshot.json",
        "source_file": "examples/aitrade/roadmap-phase-scoreboard-regulator-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example Regulator",
        "subject": "TrustAI roadmap phase scoreboard regulator phase exit supervisory acceptance",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-regulator-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/roadmap-phase-scoreboard-regulator.json",
    },
    "roadmap-phase-scoreboard:insurer": {
        "source_uri": "https://insurer.example/exports/trustai/roadmap-phase-scoreboard/underwriting-review/2026-07-12",
        "description": "Retained insurer export for roadmap-phase-scoreboard evidence",
        "artifact": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-insurer-source-snapshot.json",
        "source_file": "examples/aitrade/roadmap-phase-scoreboard-insurer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example AI Liability Underwriter",
        "subject": "TrustAI roadmap phase scoreboard insurer phase exit underwriting review",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-insurer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/roadmap-phase-scoreboard-insurer.json",
    },
    "roadmap-phase-scoreboard:standards-body": {
        "source_uri": "https://standards.example/lf-trustai/roadmap-phase-scoreboard/docket-review/2026-07-12",
        "description": "Retained standards-body export for roadmap-phase-scoreboard evidence",
        "artifact": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-standards-body-source-snapshot.json",
        "source_file": "examples/aitrade/roadmap-phase-scoreboard-standards-body-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "LF TrustAI Ballot System",
        "subject": "TrustAI roadmap phase scoreboard standards body phase exit standards-track docket review",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-standards-body-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/roadmap-phase-scoreboard-standards-body.json",
    },
    "roadmap-phase-scoreboard:customer": {
        "source_uri": "https://customers.example/aitrade/model-risk/roadmap-phase-scoreboard/reference-acceptance/2026-07-12",
        "description": "Retained customer export for roadmap-phase-scoreboard evidence",
        "artifact": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-customer-source-snapshot.json",
        "source_file": "examples/aitrade/roadmap-phase-scoreboard-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Aitrade Model Risk Committee",
        "subject": "TrustAI roadmap phase scoreboard customer phase exit customer acceptance",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/roadmap-phase-scoreboard-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/roadmap-phase-scoreboard-customer.json",
    },
    "product-scope-discipline:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/python-ci.yml",
        "description": "Retained ci-run export for product-scope-discipline evidence",
        "artifact": "examples/aitrade/external-evidence/product-scope-discipline-ci-run-source-snapshot.json",
        "source_file": "examples/aitrade/product-scope-discipline-ci-run-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "TrustAI product scope discipline ci run scope discipline CI verification",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/product-scope-discipline-ci-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/product-scope-discipline-ci-run.json",
    },
    "product-scope-discipline:customer": {
        "source_uri": "https://customers.example/aitrade/model-risk/product-scope-discipline/reference-acceptance/2026-07-12",
        "description": "Retained customer export for product-scope-discipline evidence",
        "artifact": "examples/aitrade/external-evidence/product-scope-discipline-customer-source-snapshot.json",
        "source_file": "examples/aitrade/product-scope-discipline-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Aitrade Model Risk Committee",
        "subject": "TrustAI product scope discipline customer scope discipline customer acceptance",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/product-scope-discipline-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/product-scope-discipline-customer.json",
    },
    "runtime-policy-and-attestation:ci-run": {
        "source_uri": "https://github.com/MSBeni/trust_ai/actions/workflows/python-ci.yml",
        "description": "Retained ci-run export for runtime-policy-and-attestation evidence",
        "artifact": "examples/aitrade/external-evidence/runtime-policy-ci-run-source-snapshot.json",
        "source_file": "examples/aitrade/runtime-policy-and-attestation-ci-run-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "GitHub Actions",
        "subject": "TrustAI runtime policy and attestation ci run runtime policy CI verification",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/runtime-policy-ci-run-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/runtime-policy-and-attestation-ci-run.json",
    },
    "standards-track-and-auditor-ecosystem:kms-hsm": {
        "source_uri": "https://kms.example/attestations/trustai/standards-track-and-auditor-ecosystem/evidence-signing/2026-07-12",
        "description": "Retained kms-hsm export for standards-track-and-auditor-ecosystem evidence",
        "artifact": "examples/aitrade/external-evidence/standards-track-auditor-kms-hsm-source-snapshot.json",
        "source_file": "examples/aitrade/standards-track-and-auditor-ecosystem-kms-hsm-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example KMS/HSM",
        "subject": "TrustAI standards track and auditor ecosystem kms hsm auditor ecosystem KMS signing enforcement",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/standards-track-auditor-kms-hsm-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/standards-track-and-auditor-ecosystem-kms-hsm.json",
    },
    "standards-track-and-auditor-ecosystem:standards-body": {
        "source_uri": "https://standards.example/lf-trustai/standards-track-and-auditor-ecosystem/docket-review/2026-07-12",
        "description": "Retained standards-body export for standards-track-and-auditor-ecosystem evidence",
        "artifact": "examples/aitrade/external-evidence/standards-track-auditor-standards-body-source-snapshot.json",
        "source_file": "examples/aitrade/standards-track-and-auditor-ecosystem-standards-body-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "LF TrustAI Ballot System",
        "subject": "TrustAI standards track and auditor ecosystem standards body standards and auditor ecosystem docket review",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/standards-track-auditor-standards-body-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/standards-track-and-auditor-ecosystem-standards-body.json",
    },
    "trust-network-procurement-and-marketplace:provider-api": {
        "source_uri": "https://api.trustai.example/v1/trust-network-procurement-and-marketplace/authority-evidence/2026-07-12",
        "description": "Retained provider-api export for trust-network-procurement-and-marketplace evidence",
        "artifact": "examples/aitrade/external-evidence/trust-network-provider-api-source-snapshot.json",
        "source_file": "examples/aitrade/trust-network-procurement-and-marketplace-provider-api-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud Provider API",
        "subject": "TrustAI trust network procurement and marketplace provider api trust network provider API export",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/trust-network-provider-api-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/trust-network-procurement-and-marketplace-provider-api.json",
    },
    "trust-network-procurement-and-marketplace:hosted-service": {
        "source_uri": "https://status.trustai.example/trust-network-procurement-and-marketplace/authority-evidence/2026-07-12",
        "description": "Retained hosted-service export for trust-network-procurement-and-marketplace evidence",
        "artifact": "examples/aitrade/external-evidence/trust-network-hosted-service-source-snapshot.json",
        "source_file": "examples/aitrade/trust-network-procurement-and-marketplace-hosted-service-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "TrustAI Cloud",
        "subject": "TrustAI trust network procurement and marketplace hosted service trust network hosted marketplace service export",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/trust-network-hosted-service-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/trust-network-procurement-and-marketplace-hosted-service.json",
    },
    "trust-network-procurement-and-marketplace:identity-provider": {
        "source_uri": "https://idp.example/exports/aitrade/trust-network-procurement-and-marketplace/authority-sessions/2026-07-12",
        "description": "Retained identity-provider export for trust-network-procurement-and-marketplace evidence",
        "artifact": "examples/aitrade/external-evidence/trust-network-identity-provider-source-snapshot.json",
        "source_file": "examples/aitrade/trust-network-procurement-and-marketplace-identity-provider-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Example IdP",
        "subject": "TrustAI trust network procurement and marketplace identity provider trust network vendor identity federation export",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/trust-network-identity-provider-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/trust-network-procurement-and-marketplace-identity-provider.json",
    },
    "trust-network-procurement-and-marketplace:customer": {
        "source_uri": "https://customers.example/aitrade/model-risk/trust-network-procurement-and-marketplace/reference-acceptance/2026-07-12",
        "description": "Retained customer export for trust-network-procurement-and-marketplace evidence",
        "artifact": "examples/aitrade/external-evidence/trust-network-customer-source-snapshot.json",
        "source_file": "examples/aitrade/trust-network-procurement-and-marketplace-customer-authority-export.json",
        "retrieval_method": "file-copy",
        "content_type": "application/json",
        "issuer": "Aitrade Model Risk Committee",
        "subject": "TrustAI trust network procurement and marketplace customer trust network procurement customer acceptance",
        "issued_at": "2026-07-12T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "snapshot_out": "examples/aitrade/external-evidence/trust-network-customer-source-snapshot.json",
        "intake_out": "examples/aitrade/external-evidence/intakes/trust-network-procurement-and-marketplace-customer.json",
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh or verify retained external evidence artifacts.")
    parser.add_argument("--verify-only", action="store_true", help="verify retained artifacts without rewriting them")
    args = parser.parse_args()

    if not args.verify_only:
        refresh_retained_artifacts()
    verify_retained_artifacts()
    print("retained external evidence artifacts verified")
    return 0


def refresh_retained_artifacts() -> None:
    write_deterministic_source_roadmap_audit()
    write_deterministic_source_manifest()
    run(
        "external-evidence-plan",
        path("source-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--status-filter",
        "all",
        "--generated-at",
        MAP_TIME,
        "--out",
        path("source-external-evidence-plan-all.json"),
    )
    write_retained_source_map()
    rebuild_retained_source_snapshots()
    rebuild_retained_intakes()
    write_collection_run_from_retained_intakes()
    run(
        "external-evidence-collect-batch-verify",
        path("retained-external-evidence-collection-run.json"),
        path("source-external-evidence-plan-all.json"),
        path("source-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--source-map",
        path("retained-external-evidence-collected-source-map.json"),
        "--require-fresh",
        "--require-live-source-uris",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
    )
    run(
        "external-evidence-manifest-from-intakes",
        path("source-external-evidence-plan-all.json"),
        path("source-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--intake-dir",
        str(DIR / "intakes"),
        "--require-fresh",
        "--require-live-source-uris",
        "--require-source-snapshot-artifacts",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-manifest.json"),
        "--markdown",
        path("retained-external-evidence-manifest.md"),
    )
    run(
        "external-evidence-plan",
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--generated-at",
        MAP_TIME,
        "--out",
        path("remaining-external-evidence-plan.json"),
        "--markdown",
        path("remaining-external-evidence-plan.md"),
    )
    run(
        "external-evidence-source-map-template",
        path("remaining-external-evidence-plan.json"),
        "--status-filter",
        "missing",
        "--generated-at",
        MAP_TIME,
        "--out",
        path("remaining-external-evidence-source-map-template.json"),
    )
    run(
        "external-evidence-gap-report",
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--require-fresh",
        "--now",
        NOW,
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-gap-report.json"),
        "--markdown",
        path("retained-external-evidence-gap-report.md"),
    )
    run(
        "external-evidence-work-package",
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-work-package.json"),
        "--markdown",
        path("remaining-external-evidence-work-package.md"),
    )
    run(
        "external-evidence-owner-packets",
        path("remaining-external-evidence-work-package.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-packets.json"),
        "--markdown",
        path("remaining-external-evidence-owner-packets.md"),
    )
    run(
        "external-evidence-owner-packet-status",
        path("remaining-external-evidence-owner-packets.json"),
        path("remaining-external-evidence-work-package.json"),
        path("remaining-external-evidence-source-map-template.json"),
        "--root",
        ".",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-packet-status.json"),
        "--markdown",
        path("remaining-external-evidence-owner-packet-status.md"),
    )
    run(
        "external-evidence-owner-fulfillment-template",
        path("remaining-external-evidence-owner-packet-status.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-fulfillment-template.json"),
        "--markdown",
        path("remaining-external-evidence-owner-fulfillment-template.md"),
    )
    run(
        "external-evidence-owner-fulfillment-review",
        path("remaining-external-evidence-owner-fulfillment-template.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("remaining-external-evidence-plan.json"),
        "--root",
        ".",
        "--require-live-source-uris",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-fulfillment-review.json"),
        "--markdown",
        path("remaining-external-evidence-owner-fulfillment-review.md"),
        "--fulfilled-source-map-out",
        path("remaining-external-evidence-owner-fulfilled-source-map.json"),
    )
    run(
        "external-evidence-owner-fulfillment-closure",
        path("remaining-external-evidence-owner-fulfillment-review.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
        path("retained-external-evidence-manifest.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--require-fresh",
        "--require-live-source-uris",
        "--require-source-snapshot-artifacts",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("remaining-external-evidence-owner-fulfillment-closure.json"),
        "--markdown",
        path("remaining-external-evidence-owner-fulfillment-closure.md"),
    )
    run(
        "external-evidence-readiness",
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--work-package",
        path("remaining-external-evidence-work-package.json"),
        "--root",
        ".",
        "--require-fresh",
        "--now",
        NOW,
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-readiness.json"),
        "--markdown",
        path("retained-external-evidence-readiness.md"),
    )
    run(
        "external-evidence-production-replacement-plan",
        path("retained-external-evidence-readiness.json"),
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-plan.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-plan.md"),
    )


    run(
        "external-evidence-production-replacement-owner-packets",
        path("retained-external-evidence-production-replacement-plan.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-owner-packets.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-owner-packets.md"),
    )
    run(
        "external-evidence-production-replacement-owner-packet-status",
        path("retained-external-evidence-production-replacement-owner-packets.json"),
        path("retained-external-evidence-production-replacement-plan.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-owner-packet-status.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-owner-packet-status.md"),
    )
    run(
        "external-evidence-production-replacement-intake-template",
        path("retained-external-evidence-production-replacement-owner-packet-status.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-intake-template.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-intake-template.md"),
    )
    run(
        "external-evidence-production-replacement-submission",
        path("retained-external-evidence-production-replacement-intake-template.json"),
        "--fulfillment-file",
        path("retained-external-evidence-production-replacement-intake-template.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-submission.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-submission.md"),
        "--submitted-template-out",
        path("retained-external-evidence-production-replacement-submitted-template.json"),
    )
    run(
        "external-evidence-production-replacement-submission-review",
        path("retained-external-evidence-production-replacement-submitted-template.json"),
        path("retained-external-evidence-production-replacement-owner-packet-status.json"),
        path("source-external-evidence-plan-all.json"),
        "--require-live-source-uris",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-submission-review.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-submission-review.md"),
        "--fulfilled-source-map-out",
        path("retained-external-evidence-production-replacement-fulfilled-source-map.json"),
    )
    run(
        "external-evidence-production-replacement-remediation-queue",
        path("retained-external-evidence-production-replacement-submission-review.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-remediation-queue.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-remediation-queue.md"),
    )
    run(
        "external-evidence-production-replacement-collection-package",
        path("retained-external-evidence-production-replacement-submission-review.json"),
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-collection-package.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-collection-package.md"),
        "--fulfilled-source-map-out",
        path("retained-external-evidence-production-replacement-package-source-map.json"),
    )
    run(
        "external-evidence-production-replacement-closure",
        path("retained-external-evidence-production-replacement-submission-review.json"),
        path("retained-external-evidence-readiness.json"),
        "--generated-at",
        COLLECTION_TIME,
        "--out",
        path("retained-external-evidence-production-replacement-closure.json"),
        "--markdown",
        path("retained-external-evidence-production-replacement-closure.md"),
    )


def write_deterministic_source_roadmap_audit() -> None:
    audit = build_roadmap_audit(ROOT)
    audit["generated_at"] = AUDIT_TIME
    audit["audit_id"] = content_hash(without_keys(audit, "audit_id"))
    result = verify_roadmap_audit(audit, root=ROOT)
    if not result.ok:
        raise SystemExit("invalid deterministic roadmap audit: " + "; ".join(result.errors))
    write_roadmap_audit(ROOT / DIR / "source-roadmap-audit.json", audit)


def write_deterministic_source_manifest() -> None:
    audit = json_load(DIR / "source-roadmap-audit.json")
    evidence = [
        parse_evidence_arg(
            "oss-verifier-and-public-spec,ci-run,"
            "examples/aitrade/oss-verifier-ci-run-authority-export.json,"
            "Go verifier release workflow CI authority export;"
            "issuer=GitHub Actions;"
            "subject=trustai OSS verifier public spec and release workflow CI;"
            "source_uri=https://github.com/MSBeni/trust_ai/actions/workflows/go-verifier.yml;"
            "issued_at=2026-07-12T00:00:00Z;"
            "expires_at=2026-12-31T00:00:00Z"
        )
    ]
    manifest = build_external_evidence_manifest(
        audit,
        root=ROOT,
        evidence=evidence,
        generated_at=COLLECTION_TIME,
    )
    result = verify_external_evidence_manifest(
        manifest,
        audit,
        root=ROOT,
        require_fresh=True,
        require_live_source_uris=True,
        now=NOW,
    )
    if not result.ok:
        raise SystemExit("invalid deterministic external evidence manifest: " + "; ".join(result.errors))
    write_external_evidence_manifest(ROOT / DIR / "source-external-evidence-manifest.json", manifest)
    write_external_evidence_markdown(ROOT / DIR / "source-external-evidence-manifest.md", manifest)


def write_retained_source_map() -> None:
    plan = load_external_evidence_collection_plan(ROOT / DIR / "source-external-evidence-plan-all.json")
    source_map = build_external_evidence_source_map_template(
        plan,
        status_filter="all",
        limit=None,
        source_uri_template="TODO://authority/{requirement_id}/{authority_kind}",
        description_template="{authority_kind} evidence for {requirement_id}",
        snapshot_dir=str(DIR),
        intake_dir=str(DIR / "intakes"),
        generated_at=MAP_TIME,
    )
    source_map["entries"] = [
        entry for entry in source_map["entries"] if entry.get("unit_ref") in RETAINED_SOURCES
    ]
    for entry in source_map["entries"]:
        unit_ref = entry["unit_ref"]
        retained = RETAINED_SOURCES[unit_ref]
        entry.update(
            {
                "source_uri": retained["source_uri"],
                "description": retained["description"],
                "retrieval_method": retained["retrieval_method"],
                "content_type": retained["content_type"],
                "issuer": retained["issuer"],
                "subject": retained["subject"],
                "issued_at": retained["issued_at"],
                "expires_at": retained["expires_at"],
                "snapshot_out": retained["snapshot_out"],
                "intake_out": retained["intake_out"],
            }
        )
    source_map["summary"]["snapshot_dir"] = str(DIR)
    source_map["summary"]["intake_dir"] = str(DIR / "intakes")
    source_map["summary"]["entry_count"] = len(source_map["entries"])
    source_map["summary"]["placeholder_source_uri_count"] = 0
    source_map["summary"]["live_source_uri_count"] = len(source_map["entries"])
    source_map["source_map_id"] = content_hash(without_keys(source_map, "source_map_id"))
    json_write(DIR / "retained-external-evidence-collected-source-map.json", source_map)


def rebuild_retained_source_snapshots() -> None:
    for retained in RETAINED_SOURCES.values():
        source_file = retained.get("source_file")
        if not source_file:
            continue
        body = (ROOT / source_file).read_bytes()
        snapshot = build_external_evidence_source_snapshot(
            source_uri=retained["source_uri"],
            body=body,
            retrieval_method=retained["retrieval_method"],
            issuer=retained["issuer"],
            subject=retained["subject"],
            content_type=retained["content_type"],
            issued_at=retained["issued_at"],
            expires_at=retained["expires_at"],
            generated_at=COLLECTION_TIME,
        )
        result = verify_external_evidence_source_snapshot(snapshot, require_fresh=True, now=NOW)
        if not result.ok:
            raise SystemExit("invalid retained source snapshot: " + "; ".join(result.errors))
        write_external_evidence_source_snapshot(ROOT / retained["snapshot_out"], snapshot)


def rebuild_retained_intakes() -> None:
    for unit_ref, retained in RETAINED_SOURCES.items():
        run(
            "external-evidence-intake",
            path("source-external-evidence-plan-all.json"),
            path("source-external-evidence-manifest.json"),
            path("source-roadmap-audit.json"),
            "--root",
            ".",
            "--task",
            unit_ref,
            "--artifact",
            retained["artifact"],
            "--description",
            retained["description"],
            "--issuer",
            retained["issuer"],
            "--subject",
            retained["subject"],
            "--source-uri",
            retained["source_uri"],
            "--issued-at",
            retained["issued_at"],
            "--expires-at",
            retained["expires_at"],
            "--require-fresh",
            "--require-live-source-uris",
            "--require-source-snapshot-artifact",
            "--require-fresh-source-snapshot-artifact",
            "--now",
            NOW,
            "--generated-at",
            COLLECTION_TIME,
            "--out",
            retained["intake_out"],
        )


def write_collection_run_from_retained_intakes() -> None:
    source_map_path = DIR / "retained-external-evidence-collected-source-map.json"
    source_map = json_load(source_map_path)
    collected = []
    for entry in source_map["entries"]:
        intake_path = Path(entry["intake_out"])
        snapshot_path = Path(entry["snapshot_out"])
        intake = json_load(intake_path)
        snapshot = json_load(snapshot_path)
        collected.append(
            {
                "evidence_argument": intake["evidence_argument"],
                "intake_id": intake["intake_id"],
                "intake_path": intake_path.as_posix(),
                "snapshot_artifact_path": snapshot_path.as_posix(),
                "snapshot_id": snapshot["snapshot_id"],
                "snapshot_path": snapshot_path.as_posix(),
                "source_uri": entry["source_uri"],
                "task": entry["unit_ref"],
                "warnings": [],
            }
        )
    body = {
        "schema": "trustai.external-evidence-collection-run/0.1",
        "generated_at": COLLECTION_TIME,
        "source_map": {
            "path": source_map_path.as_posix(),
            "source_map_hash": content_hash(source_map),
        },
        "summary": {
            "collected_count": len(collected),
            "task_count": len({item["task"] for item in collected}),
            "require_fresh": True,
        },
        "collected": collected,
    }
    json_write(DIR / "retained-external-evidence-collection-run.json", {**body, "run_id": content_hash(body)})


def verify_retained_artifacts() -> None:
    run(
        "external-evidence-verify",
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--require-fresh",
        "--require-live-source-uris",
        "--require-source-snapshot-artifacts",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
    )
    run(
        "external-evidence-plan-verify",
        path("remaining-external-evidence-plan.json"),
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
    )
    run(
        "external-evidence-source-map-verify",
        path("remaining-external-evidence-source-map-template.json"),
        path("remaining-external-evidence-plan.json"),
    )
    run(
        "external-evidence-collect-batch-verify",
        path("retained-external-evidence-collection-run.json"),
        path("source-external-evidence-plan-all.json"),
        path("source-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--source-map",
        path("retained-external-evidence-collected-source-map.json"),
        "--require-fresh",
        "--require-live-source-uris",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
    )
    run(
        "external-evidence-gap-report-verify",
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--require-fresh",
        "--now",
        NOW,
    )
    run(
        "external-evidence-work-package-verify",
        path("remaining-external-evidence-work-package.json"),
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
    )
    run(
        "external-evidence-owner-packets-verify",
        path("remaining-external-evidence-owner-packets.json"),
        path("remaining-external-evidence-work-package.json"),
    )
    run(
        "external-evidence-owner-packet-status-verify",
        path("remaining-external-evidence-owner-packet-status.json"),
        path("remaining-external-evidence-owner-packets.json"),
        path("remaining-external-evidence-work-package.json"),
        path("remaining-external-evidence-source-map-template.json"),
        "--root",
        ".",
    )
    run(
        "external-evidence-owner-fulfillment-template-verify",
        path("remaining-external-evidence-owner-fulfillment-template.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
    )
    run(
        "external-evidence-owner-fulfillment-review-verify",
        path("remaining-external-evidence-owner-fulfillment-review.json"),
        path("remaining-external-evidence-owner-fulfillment-template.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("remaining-external-evidence-plan.json"),
        "--root",
        ".",
        "--require-live-source-uris",
    )
    run(
        "external-evidence-owner-fulfillment-closure-verify",
        path("remaining-external-evidence-owner-fulfillment-closure.json"),
        path("remaining-external-evidence-owner-fulfillment-review.json"),
        path("remaining-external-evidence-owner-packet-status.json"),
        path("retained-external-evidence-manifest.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
        "--require-fresh",
        "--require-live-source-uris",
        "--require-source-snapshot-artifacts",
        "--require-fresh-source-snapshot-artifacts",
        "--now",
        NOW,
    )
    run(
        "external-evidence-readiness-verify",
        path("retained-external-evidence-readiness.json"),
        path("retained-external-evidence-gap-report.json"),
        path("retained-external-evidence-manifest.json"),
        path("remaining-external-evidence-plan.json"),
        path("remaining-external-evidence-source-map-template.json"),
        path("source-roadmap-audit.json"),
        "--work-package",
        path("remaining-external-evidence-work-package.json"),
        "--root",
        ".",
    )
    run(
        "external-evidence-production-replacement-plan-verify",
        path("retained-external-evidence-production-replacement-plan.json"),
        path("retained-external-evidence-readiness.json"),
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
    )
    run(
        "external-evidence-production-replacement-owner-packets-verify",
        path("retained-external-evidence-production-replacement-owner-packets.json"),
        path("retained-external-evidence-production-replacement-plan.json"),
    )
    run(
        "external-evidence-production-replacement-owner-packet-status-verify",
        path("retained-external-evidence-production-replacement-owner-packet-status.json"),
        path("retained-external-evidence-production-replacement-owner-packets.json"),
        path("retained-external-evidence-production-replacement-plan.json"),
    )
    run(
        "external-evidence-production-replacement-intake-template-verify",
        path("retained-external-evidence-production-replacement-intake-template.json"),
        path("retained-external-evidence-production-replacement-owner-packet-status.json"),
    )
    run(
        "external-evidence-production-replacement-submission-verify",
        path("retained-external-evidence-production-replacement-submission.json"),
        path("retained-external-evidence-production-replacement-intake-template.json"),
    )
    run(
        "external-evidence-production-replacement-submission-review-verify",
        path("retained-external-evidence-production-replacement-submission-review.json"),
        path("retained-external-evidence-production-replacement-submitted-template.json"),
        path("retained-external-evidence-production-replacement-owner-packet-status.json"),
        path("source-external-evidence-plan-all.json"),
        "--require-live-source-uris",
    )
    run(
        "external-evidence-production-replacement-remediation-queue-verify",
        path("retained-external-evidence-production-replacement-remediation-queue.json"),
        path("retained-external-evidence-production-replacement-submission-review.json"),
    )
    run(
        "external-evidence-production-replacement-collection-package-verify",
        path("retained-external-evidence-production-replacement-collection-package.json"),
        path("retained-external-evidence-production-replacement-submission-review.json"),
        path("retained-external-evidence-manifest.json"),
        path("source-roadmap-audit.json"),
        "--root",
        ".",
    )
    run(
        "external-evidence-production-replacement-closure-verify",
        path("retained-external-evidence-production-replacement-closure.json"),
        path("retained-external-evidence-production-replacement-submission-review.json"),
        path("retained-external-evidence-readiness.json"),
    )
    assert_retained_counts()
    verify_retained_collection_chain()


def assert_retained_counts() -> None:
    retained_count = len(RETAINED_SOURCES)
    manifest = json_load(DIR / "retained-external-evidence-manifest.json")
    total_authority_count = (
        manifest["summary"]["covered_authority_kind_count"]
        + manifest["summary"]["missing_authority_kind_count"]
    )
    remaining_count = total_authority_count - retained_count
    plan = json_load(DIR / "remaining-external-evidence-plan.json")
    source_map = json_load(DIR / "remaining-external-evidence-source-map-template.json")
    gap_report = json_load(DIR / "retained-external-evidence-gap-report.json")
    work_package = json_load(DIR / "remaining-external-evidence-work-package.json")
    owner_packets = json_load(DIR / "remaining-external-evidence-owner-packets.json")
    owner_packet_status = json_load(DIR / "remaining-external-evidence-owner-packet-status.json")
    owner_fulfillment_template = json_load(DIR / "remaining-external-evidence-owner-fulfillment-template.json")
    owner_fulfillment_review = json_load(DIR / "remaining-external-evidence-owner-fulfillment-review.json")
    owner_fulfillment_closure = json_load(DIR / "remaining-external-evidence-owner-fulfillment-closure.json")
    owner_fulfilled_source_map = json_load(DIR / "remaining-external-evidence-owner-fulfilled-source-map.json")
    readiness = json_load(DIR / "retained-external-evidence-readiness.json")
    production_replacement_plan = json_load(DIR / "retained-external-evidence-production-replacement-plan.json")
    production_replacement_owner_packets = json_load(DIR / "retained-external-evidence-production-replacement-owner-packets.json")
    production_replacement_owner_packet_status = json_load(DIR / "retained-external-evidence-production-replacement-owner-packet-status.json")
    production_replacement_intake_template = json_load(DIR / "retained-external-evidence-production-replacement-intake-template.json")
    production_replacement_submission = json_load(DIR / "retained-external-evidence-production-replacement-submission.json")
    production_replacement_submitted_template = json_load(DIR / "retained-external-evidence-production-replacement-submitted-template.json")
    production_replacement_submission_review = json_load(DIR / "retained-external-evidence-production-replacement-submission-review.json")
    production_replacement_remediation_queue = json_load(DIR / "retained-external-evidence-production-replacement-remediation-queue.json")
    production_replacement_collection_package = json_load(DIR / "retained-external-evidence-production-replacement-collection-package.json")
    production_replacement_closure = json_load(DIR / "retained-external-evidence-production-replacement-closure.json")
    production_replacement_fulfilled_source_map = json_load(DIR / "retained-external-evidence-production-replacement-fulfilled-source-map.json")
    production_replacement_package_source_map = json_load(DIR / "retained-external-evidence-production-replacement-package-source-map.json")
    remaining_package_count = len(work_package.get("packages", []))
    expected_review_status = "ready-to-collect" if remaining_count == 0 else "blocked"
    expected_review_source_map_ok = remaining_count == 0
    expected_closure_status = "closed" if remaining_count == 0 else "blocked"
    expected_readiness_status = "not-ready"
    expected_non_production_count = retained_count
    checks = [
        (manifest["summary"]["covered_authority_kind_count"], retained_count, "manifest covered authority kind count"),
        (manifest["summary"]["missing_authority_kind_count"], remaining_count, "manifest missing authority kind count"),
        (plan["summary"]["selected_task_count"], remaining_count, "remaining plan task count"),
        (source_map["summary"]["entry_count"], remaining_count, "source-map entry count"),
        (source_map["summary"]["placeholder_source_uri_count"], remaining_count, "source-map placeholder URI count"),
        (gap_report["summary"]["remaining_task_count"], remaining_count, "gap remaining task count"),
        (work_package["summary"]["task_count"], remaining_count, "work-package task count"),
        (work_package["summary"]["package_count"], remaining_package_count, "work-package package count"),
        (owner_packets["summary"]["packet_count"], remaining_package_count, "owner packet count"),
        (owner_packets["summary"]["task_count"], remaining_count, "owner packet task count"),
        (owner_packet_status["summary"]["packet_count"], remaining_package_count, "owner packet status packet count"),
        (owner_packet_status["summary"]["task_count"], remaining_count, "owner packet status task count"),
        (owner_packet_status["summary"]["closed_task_count"], 0, "owner packet status closed task count"),
        (owner_packet_status["summary"]["blocked_task_count"], remaining_count, "owner packet status blocked task count"),
        (owner_fulfillment_template["summary"]["fulfillment_count"], remaining_count, "owner fulfillment template count"),
        (owner_fulfillment_template["summary"]["placeholder_source_uri_count"], remaining_count, "owner fulfillment template placeholder URI count"),
        (owner_fulfillment_review["summary"]["review_status"], expected_review_status, "owner fulfillment review status"),
        (owner_fulfillment_review["summary"]["blocked_task_count"], remaining_count, "owner fulfillment review blocked task count"),
        (owner_fulfillment_review["summary"]["placeholder_source_uri_count"], remaining_count, "owner fulfillment review placeholder URI count"),
        (owner_fulfillment_review["summary"]["fulfilled_source_map_verification_ok"], expected_review_source_map_ok, "owner fulfillment review source-map verification status"),
        (owner_fulfilled_source_map["summary"]["placeholder_source_uri_count"], remaining_count, "owner fulfilled source-map placeholder URI count"),
        (owner_fulfillment_closure["summary"]["closure_status"], expected_closure_status, "owner fulfillment closure status"),
        (owner_fulfillment_closure["summary"]["task_count"], remaining_count, "owner fulfillment closure task count"),
        (owner_fulfillment_closure["summary"]["closed_task_count"], 0, "owner fulfillment closure closed task count"),
        (owner_fulfillment_closure["summary"]["missing_intake_count"], remaining_count, "owner fulfillment closure missing intake count"),
        (owner_fulfillment_closure["summary"]["missing_manifest_coverage_count"], remaining_count, "owner fulfillment closure missing manifest coverage count"),
        (owner_fulfillment_closure["summary"]["placeholder_source_uri_count"], remaining_count, "owner fulfillment closure placeholder URI count"),
        (readiness["summary"]["readiness_status"], expected_readiness_status, "readiness status"),
        (readiness["summary"]["non_production_covered_authority_kind_count"], expected_non_production_count, "readiness non-production coverage count"),
        (production_replacement_plan["summary"]["replacement_status"], "open", "production replacement plan status"),
        (production_replacement_plan["summary"]["task_count"], expected_non_production_count, "production replacement plan task count"),
        (production_replacement_plan["summary"]["non_production_covered_authority_kind_count"], expected_non_production_count, "production replacement plan non-production coverage count"),
        (production_replacement_owner_packets["summary"]["packet_count"], production_replacement_plan["summary"]["package_count"], "production replacement owner packet count"),
        (production_replacement_owner_packets["summary"]["task_count"], expected_non_production_count, "production replacement owner packet task count"),
        (production_replacement_owner_packets["summary"]["open_task_count"], expected_non_production_count, "production replacement owner packet open task count"),
        (production_replacement_owner_packet_status["summary"]["packet_count"], production_replacement_plan["summary"]["package_count"], "production replacement owner packet status packet count"),
        (production_replacement_owner_packet_status["summary"]["task_count"], expected_non_production_count, "production replacement owner packet status task count"),
        (production_replacement_owner_packet_status["summary"]["open_task_count"], expected_non_production_count, "production replacement owner packet status open task count"),
        (production_replacement_owner_packet_status["summary"]["blocked_task_count"], 0, "production replacement owner packet status blocked task count"),
        (production_replacement_owner_packet_status["summary"]["closed_task_count"], 0, "production replacement owner packet status closed task count"),
        (production_replacement_intake_template["summary"]["request_count"], expected_non_production_count, "production replacement intake template request count"),
        (production_replacement_intake_template["summary"]["fulfillment_count"], expected_non_production_count, "production replacement intake template fulfillment count"),
        (production_replacement_intake_template["summary"]["owner_count"], production_replacement_owner_packet_status["summary"]["packet_count"], "production replacement intake template owner count"),
        (production_replacement_intake_template["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement intake template placeholder URI count"),
        (production_replacement_intake_template["summary"]["open_task_count"], expected_non_production_count, "production replacement intake template open task count"),
        (production_replacement_submission["summary"]["submission_status"], "blocked", "production replacement submission status"),
        (production_replacement_submission["summary"]["submitted_task_count"], expected_non_production_count, "production replacement submission task count"),
        (production_replacement_submission["summary"]["submitted_placeholder_source_uri_count"], expected_non_production_count, "production replacement submission submitted placeholder URI count"),
        (production_replacement_submission["summary"]["submitted_live_source_uri_count"], 0, "production replacement submission submitted live URI count"),
        (production_replacement_submission["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement submission total placeholder URI count"),
        (production_replacement_submitted_template["summary"]["submitted_task_count"], expected_non_production_count, "production replacement submitted template task count"),
        (production_replacement_submitted_template["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement submitted template placeholder URI count"),
        (production_replacement_submission_review["summary"]["review_status"], "blocked", "production replacement submission review status"),
        (production_replacement_submission_review["summary"]["ready_task_count"], 0, "production replacement submission review ready task count"),
        (production_replacement_submission_review["summary"]["blocked_task_count"], expected_non_production_count, "production replacement submission review blocked task count"),
        (production_replacement_submission_review["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement submission review placeholder URI count"),
        (production_replacement_submission_review["summary"]["live_source_uri_count"], 0, "production replacement submission review live URI count"),
        (production_replacement_submission_review["summary"]["fulfilled_source_map_verification_ok"], False, "production replacement submission review source-map verification status"),
        (production_replacement_remediation_queue["summary"]["queue_status"], "blocked", "production replacement remediation queue status"),
        (production_replacement_remediation_queue["summary"]["remediation_task_count"], expected_non_production_count, "production replacement remediation queue task count"),
        (production_replacement_remediation_queue["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement remediation queue placeholder URI count"),
        (production_replacement_collection_package["summary"]["collection_status"], "blocked", "production replacement collection package status"),
        (production_replacement_collection_package["summary"]["ready_task_count"], 0, "production replacement collection package ready task count"),
        (production_replacement_collection_package["summary"]["blocked_task_count"], expected_non_production_count, "production replacement collection package blocked task count"),
        (production_replacement_collection_package["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement collection package placeholder URI count"),
        (production_replacement_closure["summary"]["closure_status"], "blocked", "production replacement closure status"),
        (production_replacement_closure["summary"]["readiness_status"], expected_readiness_status, "production replacement closure readiness status"),
        (production_replacement_closure["summary"]["task_count"], expected_non_production_count, "production replacement closure task count"),
        (production_replacement_closure["summary"]["closed_task_count"], 0, "production replacement closure closed task count"),
        (production_replacement_closure["summary"]["blocked_task_count"], expected_non_production_count, "production replacement closure blocked task count"),
        (production_replacement_closure["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement closure placeholder URI count"),
        (production_replacement_fulfilled_source_map["summary"]["entry_count"], expected_non_production_count, "production replacement fulfilled source-map entry count"),
        (production_replacement_fulfilled_source_map["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement fulfilled source-map placeholder URI count"),
        (production_replacement_package_source_map["summary"]["entry_count"], expected_non_production_count, "production replacement package source-map entry count"),
        (production_replacement_package_source_map["summary"]["placeholder_source_uri_count"], expected_non_production_count, "production replacement package source-map placeholder URI count"),
    ]
    for actual, expected, label in checks:
        if actual != expected:
            raise SystemExit(f"{label} expected {expected!r}, got {actual!r}")


def verify_retained_collection_chain() -> None:
    with tempfile.TemporaryDirectory(prefix="trustai-retained-chain-") as tmp:
        tmp_path = Path(tmp)
        state = tmp_path / "evidence-chain.json"
        tenant = "retained-collection-run-script-check"
        run(
            "roadmap-audit-append",
            path("source-roadmap-audit.json"),
            "--state",
            str(state),
            "--tenant",
            tenant,
            "--out",
            str(tmp_path / "roadmap-audit-entry.json"),
        )
        collection_entry = tmp_path / "collection-run-entry.json"
        run(
            "external-evidence-collect-batch-append",
            path("retained-external-evidence-collection-run.json"),
            path("source-external-evidence-plan-all.json"),
            path("source-external-evidence-manifest.json"),
            path("source-roadmap-audit.json"),
            "--root",
            ".",
            "--source-map",
            path("retained-external-evidence-collected-source-map.json"),
            "--require-fresh",
            "--require-live-source-uris",
            "--require-fresh-source-snapshot-artifacts",
            "--now",
            NOW,
            "--state",
            str(state),
            "--tenant",
            tenant,
            "--out",
            str(collection_entry),
        )
        run("roadmap-evidence-verify", "--state", str(state), "--tenant", tenant)
        report = tmp_path / "roadmap-evidence-report.json"
        run(
            "roadmap-evidence-report",
            "--state",
            str(state),
            "--tenant",
            tenant,
            "--out",
            str(report),
            "--markdown",
            str(tmp_path / "roadmap-evidence-report.md"),
        )
        bundle = tmp_path / "roadmap-evidence-bundle.json"
        run(
            "roadmap-evidence-bundle",
            "--state",
            str(state),
            "--tenant",
            tenant,
            "--report",
            str(report),
            "--root",
            ".",
            "--source-artifact",
            "roadmap-audit,examples/aitrade/external-evidence/source-roadmap-audit.json,Retained source roadmap audit JSON",
            "--source-artifact",
            "external-evidence-collection-run,examples/aitrade/external-evidence/retained-external-evidence-collection-run.json,Retained collection-run report JSON",
            "--include-collection-run-artifacts",
            "--require-source-artifacts",
            "--out",
            str(bundle),
            "--markdown",
            str(tmp_path / "roadmap-evidence-bundle.md"),
        )
        run("roadmap-evidence-bundle-verify", str(bundle), "--require-source-artifacts")
        entry = json_load(collection_entry)
        bundle_value = json_load(bundle)
        retained_count = len(RETAINED_SOURCES)
        expected_source_artifacts = 3 + (2 * retained_count)
        if entry["payload"]["collected_count"] != retained_count:
            raise SystemExit(f"retained collection-run chain entry did not record {retained_count} collected receipts")
        if bundle_value["summary"]["source_artifact_count"] != expected_source_artifacts:
            raise SystemExit(f"retained collection-run bundle did not include {expected_source_artifacts} source artifacts")


def run(*args: str) -> None:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    subprocess.run([sys.executable, "-m", "trustai", *args], cwd=ROOT, env=env, check=True)


def path(name: str) -> str:
    return (DIR / name).as_posix()


def json_load(path_value: str | Path) -> dict[str, Any]:
    return json.loads((ROOT / path_value).read_text(encoding="utf-8"))


def json_write(path_value: str | Path, value: dict[str, Any]) -> None:
    target = ROOT / path_value
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
