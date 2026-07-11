from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now, without_keys

STANDARDS_SUBMISSION_SCHEMA = "trustai.standards-submission/0.1"

REQUIRED_SPEC_PATHS = (
    "docs/specs/actuarial-corpus-v0.1.md",
    "docs/specs/actuarial-product-v0.1.md",
    "docs/specs/state-of-agent-reliability-report-v0.1.md",
    "docs/specs/roadmap-phase-scoreboard-v0.1.md",
    "docs/specs/product-scope-decision-v0.1.md",
    "docs/specs/agent-registry-v0.1.md",
    "docs/specs/proof-pack-v0.1.md",
    "docs/specs/verification-contract-v0.1.md",
    "docs/specs/tamper-stress-report-v0.1.md",
    "docs/specs/production-trust-v0.1.md",
    "docs/specs/roadmap-audit-v0.1.md",
    "docs/specs/design-partner-pilot-v0.1.md",
    "docs/specs/own-compliance-dossier-v0.1.md",
    "docs/specs/external-evidence-manifest-v0.1.md",
    "docs/specs/anchor-provider-receipt-v0.1.md",
    "docs/specs/otel-ingest-v0.1.md",
    "docs/specs/collector-topology-v0.1.md",
    "docs/specs/collector-service-attestation-v0.1.md",
    "docs/specs/collector-worker-v0.1.md",
    "docs/specs/mcp-gateway-v0.1.md",
    "docs/specs/mcp-gateway-production-authority-v0.1.md",
    "docs/specs/keyring-v0.1.md",
    "docs/specs/trust-authority-receipt-v0.1.md",
    "docs/specs/trust-authority-provider-attestation-v0.1.md",
    "docs/specs/trust-authority-kms-enforcement-v0.1.md",
    "docs/specs/deployment-manifest-v0.1.md",
    "docs/specs/helm-chart-validation-v0.1.md",
    "docs/specs/deployment-image-integrity-v0.1.md",
    "docs/specs/kubernetes-release-state-v0.1.md",
    "docs/specs/byoc-operator-attestation-v0.1.md",
    "docs/specs/byoc-production-authority-v0.1.md",
    "docs/specs/compliance-production-authority-v0.1.md",
    "docs/specs/eu-data-plane-attestation-v0.1.md",
    "docs/specs/worm-object-store-v0.1.md",
    "docs/specs/human-approval-v0.1.md",
    "docs/specs/control-plane-v0.1.md",
    "docs/specs/runtime-policy-v0.1.md",
    "docs/specs/approval-callback-v0.1.md",
    "docs/specs/framework-adapters-v0.1.md",
    "docs/specs/framework-adapter-production-authority-v0.1.md",
    "docs/specs/consumption-exports-v0.1.md",
    "docs/specs/provider-delivery-v0.1.md",
    "docs/specs/promotion-status-receipt-v0.1.md",
    "docs/specs/provider-delivery-service-attestation-v0.1.md",
    "docs/specs/provider-delivery-worker-v0.1.md",
    "docs/specs/provider-delivery-production-authority-v0.1.md",
    "docs/specs/provider-approval-production-authority-v0.1.md",
    "docs/specs/provider-webhook-v0.1.md",
    "docs/specs/provider-audit-correlation-v0.1.md",
    "docs/specs/provider-audit-stream-v0.1.md",
    "docs/specs/provider-audit-worker-v0.1.md",
    "docs/specs/provider-credential-custody-v0.1.md",
    "docs/specs/provider-operations-service-attestation-v0.1.md",
    "docs/specs/provider-operations-production-authority-v0.1.md",
    "docs/specs/provider-installation-v0.1.md",
    "docs/specs/provider-callback-store-v0.1.md",
    "docs/specs/provider-ingress-v0.1.md",
    "docs/specs/provider-callback-storage-v0.1.md",
    "docs/specs/provider-lifecycle-v0.1.md",
    "docs/specs/provider-lifecycle-operation-v0.1.md",
    "docs/specs/policy-engine-receipt-v0.1.md",
    "docs/specs/policy-backend-enforcement-v0.1.md",
    "docs/specs/policy-backend-service-attestation-v0.1.md",
    "docs/specs/policy-backend-worker-v0.1.md",
    "docs/specs/policy-backend-provider-export-v0.1.md",
    "docs/specs/policy-backend-provider-export-bundle-v0.1.md",
    "docs/specs/policy-backend-production-authority-v0.1.md",
    "docs/specs/policy-backend-service-bundle-v0.1.md",
    "docs/specs/insurer-consent-v0.1.md",
    "docs/specs/underwriting-quote-v0.1.md",
    "docs/specs/insurer-partner-service-attestation-v0.1.md",
    "docs/specs/insurer-partner-worker-v0.1.md",
    "docs/specs/insurer-partner-production-authority-v0.1.md",
    "docs/specs/regulator-disclosure-v0.1.md",
    "docs/specs/regulator-acceptance-v0.1.md",
    "docs/specs/supervised-access-v0.1.md",
    "docs/specs/review-portal-service-attestation-v0.1.md",
    "docs/specs/review-portal-production-authority-v0.1.md",
    "docs/specs/eu-ai-act-technical-documentation-v0.1.md",
    "docs/specs/standards-submission-v0.1.md",
    "docs/specs/standards-body-submission-v0.1.md",
    "docs/specs/standards-body-status-v0.1.md",
    "docs/specs/standards-body-ballot-v0.1.md",
    "docs/specs/standards-body-ballot-system-v0.1.md",
    "docs/specs/standards-body-provider-posting-v0.1.md",
    "docs/specs/auditor-certification-v0.1.md",
    "docs/specs/auditor-program-governance-v0.1.md",
    "docs/specs/auditor-program-sponsorship-v0.1.md",
    "docs/specs/auditor-accreditation-v0.1.md",
    "docs/specs/auditor-accreditation-countersignature-v0.1.md",
    "docs/specs/auditor-accreditation-signing-ceremony-v0.1.md",
    "docs/specs/auditor-credential-registry-v0.1.md",
    "docs/specs/trust-network-v0.1.md",
    "docs/specs/trust-network-registry-v0.1.md",
    "docs/specs/trust-network-registry-status-v0.1.md",
    "docs/specs/vendor-identity-v0.1.md",
    "docs/specs/identity-provider-attestation-v0.1.md",
    "docs/specs/identity-provider-session-v0.1.md",
    "docs/specs/identity-provider-lifecycle-operation-v0.1.md",
    "docs/specs/identity-provider-lifecycle-worker-v0.1.md",
    "docs/specs/identity-provider-production-authority-v0.1.md",
    "docs/specs/procurement-clause-v0.1.md",
    "docs/specs/procurement-integration-v0.1.md",
    "docs/specs/marketplace-v0.1.md",
    "docs/specs/vertical-pack-v0.1.md",
    "docs/specs/marketplace-distribution-v0.1.md",
    "docs/specs/marketplace-author-governance-v0.1.md",
    "docs/specs/marketplace-settlement-v0.1.md",
    "docs/specs/trust-network-service-attestation-v0.1.md",
    "docs/specs/trust-network-worker-v0.1.md",
    "docs/specs/trust-network-production-authority-v0.1.md",
    "docs/specs/verifier-conformance-v0.1.md",
    "docs/specs/verifier-release-v0.1.md",
    "docs/specs/verifier-distribution-v0.1.md",
    "docs/specs/verifier-public-release-v0.1.md",
    "docs/specs/verifier-public-release-authority-v0.1.md",
    "docs/specs/go-verifier-v0.1.md",
    "docs/specs/go-verifier-build-attestation-v0.1.md",
    "docs/specs/go-verifier-release-workflow-v0.1.md",
    "docs/specs/go-verifier-release-run-v0.1.md",
    "docs/specs/go-verifier-release-run-bundle-v0.1.md",
    "docs/specs/python-sdk-v0.1.md",
    "docs/specs/typescript-sdk-v0.1.md",
    "docs/specs/self-serve-onboarding-v0.1.md",
    "docs/specs/shadow-replay-v0.1.md",
    "docs/specs/traffic-holdout-export-v0.1.md",
    "docs/specs/traffic-completeness-receipt-v0.1.md",
    "docs/specs/soak-demotion-receipt-v0.1.md",
    "docs/specs/reexecution-report-v0.1.md",
    "docs/specs/reexecution-policy-v0.1.md",
    "docs/specs/reexecution-runner-v0.1.md",
    "docs/specs/reexecution-isolation-attestation-v0.1.md",
    "docs/specs/reexecution-runner-service-attestation-v0.1.md",
    "docs/specs/reexecution-runner-worker-v0.1.md",
    "docs/specs/reexecution-runner-production-authority-v0.1.md",
)

CONFORMANCE_TARGETS = (
    {
        "id": "design-partner-pilot-dossiers",
        "description": "Design-partner pilot dossiers bind Phase 1 exit-criteria readiness and external-evidence claims to partner counts, signed value, external scrutiny events, proof machinery source artifacts, and explicit no-customer-data limits.",
        "reference": "src/trustai/design_partner.py",
        "commands": [
            "python -m trustai design-partner-dossier --root . --dossier-ref dossier:design-partner/phase1-readiness --producer-ref oidc:trustai.example/gtm-ops --partner \"partner:bank-a,finserv,agent:payments-risk,60000,negotiating\" --partner \"partner:insurer-b,insurance,agent:claims-triage,90000,negotiating\" --partner \"partner:fintech-c,fintech,agent:treasury-ops,100000,negotiating\" --scrutiny \"scrutiny:model-risk-a,model-risk,team:model-risk,partner:bank-a,submitted\" --out artifacts/design-partner-dossier.json",
            "python -m trustai design-partner-dossier-verify artifacts/design-partner-dossier.json --root .",
            "python -m trustai design-partner-dossier-append artifacts/design-partner-dossier.json --root . --state .trustai/design-partner-demo/evidence-chain.json --tenant design-partner-local --out artifacts/design-partner-dossier-entry.json",
            "python -m unittest tests.test_design_partner",
        ],
    },
    {
        "id": "trustai-own-compliance-dossiers",
        "description": "TrustAI own compliance dossiers bind SOC 2 Type II and ISO/IEC 42001 readiness/external-certification claims to proof-pack, compliance mapper, standards, roadmap audit, trust authority, WORM retention source artifacts, and no-sensitive-data limits.",
        "reference": "src/trustai/own_compliance.py",
        "commands": [
            "python -m trustai own-compliance-dossier --root . --dossier-ref dossier:trustai/own-compliance-readiness --producer-ref oidc:trustai.example/compliance-ops --scope-ref scope:trustai/company --out artifacts/own-compliance-dossier.json",
            "python -m trustai own-compliance-dossier-verify artifacts/own-compliance-dossier.json --root .",
            "python -m trustai own-compliance-dossier-append artifacts/own-compliance-dossier.json --root . --state .trustai/own-compliance-demo/evidence-chain.json --tenant own-compliance-local --out artifacts/own-compliance-dossier-entry.json",
            "python -m unittest tests.test_own_compliance",
        ],
    },
    {
        "id": "state-of-agent-reliability-reports",
        "description": "State of Agent Reliability reports bind aggregate anonymized cohort metrics, actuarial product source bindings, consent/proof-pack source artifacts, privacy thresholds, publication evidence, and explicit no-direct-identifier limits for the roadmap GTM publication surface.",
        "reference": "src/trustai/reliability_report.py",
        "commands": [
            "python -m trustai reliability-report --root . --report-ref report:trustai/state-of-agent-reliability/2026 --producer-ref oidc:trustai.example/reliability-research --period-start 2026-01-01T00:00:00Z --period-end 2026-12-31T00:00:00Z --cohort \"segment:finserv,3,12,48,42,6,2,125000,actuarial-product:finserv\" --actuarial-product artifacts/actuarial-product.json --out artifacts/state-of-agent-reliability-report.json",
            "python -m trustai reliability-report-verify artifacts/state-of-agent-reliability-report.json --root . --actuarial-product artifacts/actuarial-product.json",
            "python -m trustai reliability-report-append artifacts/state-of-agent-reliability-report.json --root . --actuarial-product artifacts/actuarial-product.json --state .trustai/reliability-report-demo/evidence-chain.json --tenant reliability-report-local --out artifacts/state-of-agent-reliability-report-entry.json",
            "python -m unittest tests.test_reliability_report",
        ],
    },
    {
        "id": "roadmap-phase-scoreboards",
        "description": "Roadmap phase scoreboards bind P1-P4 external business milestone evidence references for paying partners, signed value, ARR, customers, insurer pricing, regulator acceptance, standards-track status, procurement adoption, data-product revenue, and market usage while preserving local-readiness separation.",
        "reference": "src/trustai/phase_scoreboard.py",
        "commands": [
            "python -m trustai phase-scoreboard --root . --scoreboard-ref scoreboard:trustai/roadmap/2026 --producer-ref oidc:trustai.example/strategy --out artifacts/phase-scoreboard.json",
            "python -m trustai phase-scoreboard-verify artifacts/phase-scoreboard.json --root .",
            "python -m trustai phase-scoreboard-append artifacts/phase-scoreboard.json --root . --state .trustai/phase-scoreboard-demo/evidence-chain.json --tenant phase-scoreboard-local --out artifacts/phase-scoreboard-entry.json",
            "python -m unittest tests.test_phase_scoreboard",
        ],
    },
    {
        "id": "product-scope-decisions",
        "description": "Product scope decisions bind feature requests to the roadmap discipline test, proof impact categories, explicit anti-focus flags, decline-required controls, and source artifacts for proof-pack, verifier, gate, and roadmap evidence surfaces.",
        "reference": "src/trustai/product_scope.py",
        "commands": [
            "python -m trustai product-scope-decision --root . --decision-ref scope:request/regulator-export --requester-ref product:gtm --reviewer-ref oidc:trustai.example/product --feature-title \"Regulator export evidence\" --feature-summary \"Portable regulator export that strengthens third-party proof review.\" --decision accept --proof-impact proof-strength --proof-impact wider-acceptance --out artifacts/product-scope-decision.json",
            "python -m trustai product-scope-decision-verify artifacts/product-scope-decision.json --root .",
            "python -m trustai product-scope-decision-append artifacts/product-scope-decision.json --root . --state .trustai/product-scope-demo/evidence-chain.json --tenant product-scope-local --out artifacts/product-scope-decision-entry.json",
            "python -m unittest tests.test_product_scope",
        ],
    },
    {
        "id": "vertical-pack-receipts",
        "description": "Vertical pack receipts bind contract templates, policy packs, proof-pack sources, compliance/runtime sources, and vertical-specific external-evidence limits for trading/treasury, insurance claims, healthcare RCM, and public sector packs.",
        "reference": "src/trustai/vertical_pack.py",
        "commands": [
            "python -m trustai vertical-pack --root . --pack-ref vertical-pack:healthcare-rcm/local --vertical healthcare-rcm --producer-ref oidc:trustai.example/vertical-pack-author --reviewer-ref oidc:auditor.example/vertical-pack-reviewer --out artifacts/healthcare-vertical-pack.json",
            "python -m trustai vertical-pack-verify artifacts/healthcare-vertical-pack.json --root .",
            "python -m trustai vertical-pack-append artifacts/healthcare-vertical-pack.json --root . --state .trustai/vertical-pack-demo/evidence-chain.json --tenant vertical-pack-local --out artifacts/healthcare-vertical-pack-entry.json",
            "python -m unittest tests.test_vertical_pack",
        ],
    },
    {
        "id": "self-serve-sdk-gateway-onboarding",
        "description": "Self-serve onboarding receipts bind Python/TypeScript SDKs, OTel ingest, MCP gateway transcript/proxy capture, quickstart commands, examples, and production-claim limits for the SDK/gateway PLG tier.",
        "reference": "src/trustai/onboarding.py",
        "commands": [
            "python -m trustai self-serve-onboarding --root . --onboarding-ref onboarding:self-serve/aitrade --tenant-ref tenant:aitrade-local --agent-ref agent:aitrade-risk --requester-ref mailto:engineer@example.com --out artifacts/self-serve-onboarding.json",
            "python -m trustai self-serve-onboarding-verify artifacts/self-serve-onboarding.json --root .",
            "python -m trustai self-serve-onboarding-append artifacts/self-serve-onboarding.json --root . --state .trustai/self-serve-onboarding/evidence-chain.json --tenant self-serve-onboarding-local --out artifacts/self-serve-onboarding-entry.json",
            "python -m unittest tests.test_self_serve_onboarding",
        ],
    },
    {
        "id": "traffic-holdout-export-receipts",
        "description": "Traffic holdout export and completeness receipts bind production traffic source refs, extraction windows, replay record hashes, collector/provider stream records, retained provider export byte replay, cursor bounds, audit records, freeze and holdout boundaries, privacy limits, and chain append evidence before shadow replay promotion evidence is trusted.",
        "reference": "src/trustai/shadow.py",
        "commands": [
            "python -m trustai traffic-holdout-export examples/aitrade/verification-contract.yaml examples/aitrade/shadow-replay.json --export-ref traffic-export:aitrade/prod-traffic-holdout-20260702 --source-ref collector:aitrade-prod/redpanda/trustai.otel.events --exporter-ref oidc:trustai.example/traffic-exporter --window-start 2026-07-02T00:00:00Z --window-end 2026-07-03T23:59:59Z --produced-at 2026-07-03T12:20:00Z --out artifacts/traffic-holdout-export.json",
            "python -m trustai traffic-holdout-export-verify artifacts/traffic-holdout-export.json --contract examples/aitrade/verification-contract.yaml --replay examples/aitrade/shadow-replay.json",
            "python -m trustai traffic-holdout-export-append artifacts/traffic-holdout-export.json --contract examples/aitrade/verification-contract.yaml --replay examples/aitrade/shadow-replay.json --state .trustai/traffic-holdout-demo/evidence-chain.json --tenant traffic-holdout-local --out artifacts/traffic-holdout-export-entry.json",
            "python -m trustai traffic-completeness artifacts/traffic-holdout-export.json examples/aitrade/traffic-completeness-provider-export.json --mode production-export --authority-ref authority:traffic-completeness/aitrade-prod --endpoint-url https://provider.example/aitrade/traffic-holdout/export --request-hash sha256:traffic-completeness-request --response-status 200 --response-hash sha256:traffic-completeness-response --actor-ref oidc:trustai.example/traffic-completeness-worker --produced-at 2026-07-03T12:25:00Z --out artifacts/traffic-completeness.json",
            "python -m trustai traffic-completeness-verify artifacts/traffic-completeness.json --traffic-export artifacts/traffic-holdout-export.json --provider-export examples/aitrade/traffic-completeness-provider-export.json",
            "python -m trustai traffic-completeness-append artifacts/traffic-completeness.json --traffic-export artifacts/traffic-holdout-export.json --provider-export examples/aitrade/traffic-completeness-provider-export.json --state .trustai/traffic-completeness-demo/evidence-chain.json --tenant traffic-completeness-local --out artifacts/traffic-completeness-entry.json",
            "python -m unittest tests.test_temporal_holdout",
        ],
    },
    {
        "id": "soak-demotion-receipts",
        "description": "Soak demotion receipts bind failed post-promotion soak reports to promotion_gate.demoted lifecycle entries with replayed contract, failure, trigger, reason, and environment-transition evidence.",
        "reference": "src/trustai/lifecycle.py",
        "commands": [
            "python -m trustai soak-report examples/aitrade/verification-contract.yaml examples/aitrade/failed-soak-window.json --out artifacts/soak-report-entry.json --demote-on-failure --auto-register --state .trustai/soak-demotion-demo/evidence-chain.json --tenant soak-demotion-local --demotion-out artifacts/soak-demotion-entry.json",
            "python -m trustai soak-demotion examples/aitrade/verification-contract.yaml artifacts/soak-report-entry.json artifacts/soak-demotion-entry.json --attested-at 2026-07-04T01:00:00Z --out artifacts/soak-demotion-receipt.json",
            "python -m trustai soak-demotion-verify artifacts/soak-demotion-receipt.json --contract examples/aitrade/verification-contract.yaml --soak-entry artifacts/soak-report-entry.json --demotion-entry artifacts/soak-demotion-entry.json",
            "python -m trustai soak-demotion-append artifacts/soak-demotion-receipt.json --contract examples/aitrade/verification-contract.yaml --soak-entry artifacts/soak-report-entry.json --demotion-entry artifacts/soak-demotion-entry.json --state .trustai/soak-demotion-demo/evidence-chain.json --tenant soak-demotion-local --out artifacts/soak-demotion-receipt-entry.json",
            "python -m unittest tests.test_phase1_phase2",
        ],
    },
    {
        "id": "compliance-production-authority-dossiers",
        "description": "Compliance production authority dossiers bind compliance framework mappings, EU AI Act technical documentation, proof-pack source replay, selective regulator disclosure, optional EU data-plane sovereignty evidence, freshness windows, and strict production-claim gates.",
        "reference": "src/trustai/compliance_authority.py",
        "commands": [
            "python -m trustai compliance-authority artifacts/compliance-export.json artifacts/eu-ai-act-technical-documentation.json --pack artifacts/aitrade-proof-pack.json --regulator-disclosure artifacts/regulator-disclosure.json --environment aitrade-prod --dossier-ref dossier:compliance-authority/aitrade-prod --authority-ref authority:compliance/aitrade-prod --producer-ref oidc:trustai.example/compliance-authority-worker --authority-evidence \"framework-control-mapping-ontology,standards-body,standards:compliance-ontology/2026,sha256:compliance-ontology,Nightly compliance ontology replay;issuer=TrustAI CI;subject=aitrade-prod compliance mapper;source_uri=https://ci.example/trustai/compliance/aitrade-prod;issued_at=2026-07-04T03:00:00Z;expires_at=2026-12-31T00:00:00Z\" --generated-at 2026-07-04T03:05:00Z --out artifacts/compliance-authority.json",
            "python -m trustai compliance-authority-verify artifacts/compliance-authority.json --compliance-export artifacts/compliance-export.json --eu-ai-act-document artifacts/eu-ai-act-technical-documentation.json --pack artifacts/aitrade-proof-pack.json --regulator-disclosure artifacts/regulator-disclosure.json",
            "python -m trustai compliance-authority-append artifacts/compliance-authority.json artifacts/compliance-export.json artifacts/eu-ai-act-technical-documentation.json --pack artifacts/aitrade-proof-pack.json --regulator-disclosure artifacts/regulator-disclosure.json",
            "python -m unittest tests.test_compliance_authority",
        ],
    },
    {
        "id": "framework-adapter-production-authority-dossiers",
        "description": "Framework adapter production authority dossiers bind adapter matrices, native hook releases, optional runtime service authority, compatibility evidence, freshness windows, and production-claim limits for maintained native framework hooks.",
        "reference": "src/trustai/framework_adapter_authority.py",
        "commands": [
            "python -m trustai framework-adapter-authority artifacts/framework-adapter-matrix.json artifacts/framework-hook-release.json --runtime-service-authority artifacts/framework-runtime-service-authority.json --environment aitrade-prod --dossier-ref dossier:framework-adapter-authority/aitrade-prod --authority-ref authority:framework-adapter/aitrade-prod --producer-ref oidc:trustai.example/framework-adapter-authority-worker --authority-evidence \"exact-runtime-release-matrix,ci-run,ci:framework-adapter-matrix/nightly/aitrade-prod,sha256:framework-adapter-matrix-ci-run,Nightly adapter matrix replay export;issuer=TrustAI CI;subject=aitrade-prod framework adapter matrix;source_uri=https://ci.example/trustai/framework-adapter-matrix/aitrade-prod;issued_at=2026-07-09T00:45:00Z;expires_at=2026-12-31T00:00:00Z\" --generated-at 2026-07-09T01:05:00Z --out artifacts/framework-adapter-authority.json",
            "python -m trustai framework-adapter-authority-verify artifacts/framework-adapter-authority.json --matrix artifacts/framework-adapter-matrix.json --release artifacts/framework-hook-release.json --runtime-service-authority artifacts/framework-runtime-service-authority.json",
            "python -m trustai framework-adapter-authority-append artifacts/framework-adapter-authority.json artifacts/framework-adapter-matrix.json artifacts/framework-hook-release.json --runtime-service-authority artifacts/framework-runtime-service-authority.json",
            "python -m unittest tests.test_framework_adapter_authority",
        ],
    },
    {
        "id": "proof-pack-offline-verification",
        "description": "Proof packs verify without network access or a TrustAI account.",
        "reference": "src/trustai/verifier.py",
        "commands": [
            "python -m trustai verify artifacts/aitrade-proof-pack.json",
            "python -m trustai verify artifacts/aitrade-proof-pack.json --keyring .trustai/keyring.local.json",
        ],
    },
    {
        "id": "tamper-evident-chain",
        "description": "Single-entry mutation invalidates hashes, signatures, timestamp tokens, or Merkle inclusion, including roadmap-scale stress reports.",
        "reference": "src/trustai/tamper_stress.py",
        "commands": [
            "python -m trustai tamper-test --entries 1000",
            "python -m trustai tamper-stress-report --entries 1000000 --sample-index 0 --sample-index 500000 --sample-index 999999 --tamper-index 500000 --out artifacts/tamper-stress-report.json",
            "python -m trustai tamper-stress-verify artifacts/tamper-stress-report.json --deep",
        ],
    },
    {
        "id": "deployment-manifest-attestation",
        "description": "Deployment manifests, Helm chart validation receipts, Kubernetes release-state receipts, and deployment image integrity receipts bind Docker/Helm BYOC API Deployment, Service, NetworkPolicy, demo Job, provider/customer release-state exports, image digest, SBOM, provenance, signature artifacts, implemented controls, and planned production controls by hash.",
        "reference": "src/trustai/deployment.py",
        "commands": [
            "python -m trustai deployment-manifest --root . --environment aitrade-byoc",
            "python -m trustai deployment-verify artifacts/deployment-manifest.json --root .",
            "python -m trustai helm-chart-validation artifacts/deployment-manifest.json --root . --out artifacts/helm-chart-validation.json",
            "python -m trustai helm-chart-validation-verify artifacts/helm-chart-validation.json artifacts/deployment-manifest.json --root .",
            "python -m trustai kubernetes-release-state artifacts/deployment-manifest.json artifacts/helm-chart-validation.json --root . --environment aitrade-byoc --provider ExampleKubernetesAPI --cluster-ref k8s:cluster/aitrade-prod --namespace trustai --release-name trustai --release-revision 7 --release-status deployed --export-ref k8s-export:aitrade-prod/trustai/2026-07-04 --export-hash sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --service-account-ref k8s:sa/trustai/trustai-api --deployment-ref k8s:deployment/trustai/trustai-api --service-ref k8s:service/trustai/trustai-api --network-policy-ref k8s:networkpolicy/trustai/trustai-api --secret-ref k8s:secret/trustai/trustai-signing-key --desired-replicas 2 --ready-replicas 2 --pod-selector-hash sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --ingress-policy-hash sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --egress-policy-hash sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd --audit-log-ref audit-log:kubernetes/aitrade-prod/trustai --audit-log-root sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --issued-at 2026-07-04T03:08:00Z --expires-at 2026-07-05T03:08:00Z --out artifacts/kubernetes-release-state.json",
            "python -m trustai kubernetes-release-state-verify artifacts/kubernetes-release-state.json artifacts/deployment-manifest.json artifacts/helm-chart-validation.json --root .",
            "python -m trustai deployment-image-integrity artifacts/deployment-manifest.json --root . --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --sbom artifacts/trustai-image.sbom.json --provenance artifacts/trustai-image.provenance.json --signature artifacts/trustai-image.sig --out artifacts/deployment-image-integrity.json",
            "python -m trustai deployment-image-integrity-verify artifacts/deployment-image-integrity.json artifacts/deployment-manifest.json --root .",
            "python -m unittest tests.test_deployment",
        ],
    },
    {
        "id": "collector-topology-attestation",
        "description": "Collector topology manifests bind OTel/file ingest, SDKs, framework adapters, MCP capture, local API, control-plane stores, and planned production collector services by hash.",
        "reference": "src/trustai/collector_topology.py",
        "commands": [
            "python -m trustai collector-topology --root . --environment aitrade-local",
            "python -m trustai collector-topology-verify artifacts/collector-topology.json --root .",
        ],
    },
    {
        "id": "collector-service-attestations",
        "description": "Collector service attestations bind collector topology to mTLS/authn/z, replay protection, rate limits, streaming bus, ClickHouse, Postgres, MCP proxy, framework hook, audit, and BYOC operator evidence.",
        "reference": "src/trustai/collector_service.py",
        "commands": [
            "python -m trustai collector-service-attestation artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --environment aitrade-prod --service-ref collector:trustai/otel-prod --service-version 0.1.0 --collector-image ghcr.io/trustai/collector:0.1.0 --collector-image-digest sha256:trustai-collector-image --collector-binary-hash sha256:trustai-collector-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --mtls-policy-ref policy:collector/mtls-required-v0.1 --auth-policy-ref policy:collector/oidc-tenant-authz-v0.1 --tenant-isolation-ref tenant-isolation:aitrade/collector --rate-limit-policy-ref rate-limit:collector/aitrade --replay-cache-ref redis:collector/replay-cache --idempotency-store-ref postgres:collector/idempotency --ingress-ref ingress:collector/private --network-policy-ref netpol:collector/deny-by-default --egress-policy-ref egress:collector/kms-tsa-only --stream-backend redpanda --stream-ref redpanda:trustai/collector-events --stream-topic trustai.otel.events --stream-retention-hours 168 --stream-dlq-ref redpanda:trustai/collector-events-dlq --clickhouse-ref clickhouse:trustai/traces --clickhouse-retention-days 2555 --clickhouse-backup-ref backup:clickhouse/trustai/daily --postgres-ref postgres:trustai/control-plane --postgres-schema-hash sha256:trustai-control-plane-schema --postgres-backup-ref backup:postgres/trustai/daily --mcp-proxy-ref mcp-proxy:trustai/prod --mcp-proxy-image-digest sha256:trustai-mcp-proxy-image --framework-hook-ref hook:langgraph/0.3 --framework-hook-ref hook:openai-agents/0.2 --framework-hook-ref hook:claude-agent-sdk/0.1 --audit-log-ref audit-log:collector/service --audit-log-root sha256:collector-service-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/collector-operator --credential-ref env:COLLECTOR_SERVICE_TOKEN --evidence-ref evidence:collector/service --attested-at 2026-07-04T04:00:00Z",
            "python -m trustai collector-service-verify artifacts/collector-service-attestation.json artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm",
            "python -m unittest tests.test_collector_service",
        ],
    },
    {
        "id": "collector-worker-receipts",
        "description": "Collector worker receipts bind individual ingestion operations to service attestations, topology sources, scheduler leases, trace batch hashes, idempotency, stream offsets, ClickHouse/Postgres writes, MCP/framework captures, audit roots, and redacted worker credentials.",
        "reference": "src/trustai/collector_worker.py",
        "commands": [
            "python -m trustai collector-worker --service-attestation artifacts/collector-service-attestation.json artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --mode hosted-worker --environment aitrade-prod --worker-ref worker:collector/otel-batch --run-ref worker-run:collector/otel/2026-07-04T04:05:00Z --operation-kind otlp_batch_ingest --actor-ref oidc:trustai.example/collector-worker --schedule-ref schedule:collector/otel/continuous --cadence-seconds 15 --lease-ref lease:collector/otel/2026-07-04T04:05:00Z --checkpoint-ref checkpoint:collector/otel/aitrade --checkpoint-hash sha256:collector-worker-checkpoint --previous-cursor-ref cursor:collector/otel/before --next-cursor-ref cursor:collector/otel/after --next-run-at 2026-07-04T04:05:15Z --tenant-ref tenant:aitrade --trace-batch-ref trace-batch:aitrade/2026-07-04T04:05:00Z --trace-batch-hash sha256:collector-worker-trace-batch --source-endpoint-ref otlp:http-v0-ingest --received-span-count 2 --accepted-span-count 2 --rejected-span-count 0 --idempotency-key-hash sha256:collector-worker-idempotency-key --otlp-request-hash sha256:collector-worker-otlp-request --otlp-response-status 200 --otlp-response-hash sha256:collector-worker-otlp-response --stream-ref redpanda:trustai/collector-events --stream-topic trustai.otel.events --partition-ref redpanda:trustai/collector-events/0 --offset-start 100 --offset-end 101 --stream-message-ref stream-message:collector/aitrade/2026-07-04T04:05:00Z --stream-message-hash sha256:collector-worker-stream-message --stream-dlq-ref redpanda:trustai/collector-events-dlq --clickhouse-batch-ref clickhouse:trustai/traces/batch/2026-07-04T04:05:00Z --clickhouse-batch-hash sha256:collector-worker-clickhouse-batch --clickhouse-rows-written 2 --postgres-index-ref postgres:trustai/control-plane/index/2026-07-04T04:05:00Z --postgres-index-hash sha256:collector-worker-postgres-index --postgres-rows-written 2 --control-index-ref control-index:collector/aitrade/2026-07-04T04:05:00Z --control-index-hash sha256:collector-worker-control-index --mcp-transcript-ref mcp-transcript:aitrade/2026-07-04T04:05:00Z --mcp-transcript-hash sha256:collector-worker-mcp-transcript --framework-hook-ref hook:langgraph/0.3 --framework-hook-hash sha256:collector-worker-framework-hook --metrics-ref metrics:collector/workers --audit-log-ref audit-log:collector/workers --audit-log-root sha256:collector-worker-audit-root --retention-until 2033-07-04T00:00:00Z --credential-ref env:COLLECTOR_WORKER_TOKEN --evidence-ref evidence:collector/worker --started-at 2026-07-04T04:05:00Z --completed-at 2026-07-04T04:05:02Z",
            "python -m trustai collector-worker-verify artifacts/collector-worker.json --service-attestation artifacts/collector-service-attestation.json artifacts/collector-topology.json --byoc-operator artifacts/byoc-operator-attestation.json --deployment-manifest artifacts/deployment-manifest.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm",
            "python -m unittest tests.test_collector_worker",
        ],
    },
    {
        "id": "mcp-proxy-capture-receipts",
        "description": "MCP proxy capture receipts bind raw MCP JSON-RPC tools/call request/response envelopes and retained source export byte replay to redacted event hash chains, derived normalized tool-call transcripts, signed capture ids, and chain append evidence.",
        "reference": "src/trustai/mcp_gateway.py",
        "commands": [
            "python -m trustai mcp-proxy-capture examples/aitrade/mcp-proxy-events.json --agent-name aitrade-risk-agent --agent-version sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234 --risk-class trading-prod-write --contract-hash 22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2 --proxy-ref mcp-proxy:trustai/local --upstream-ref mcp-server:aitrade/tools --captured-at 2026-07-03T12:00:12Z --out artifacts/mcp-proxy-capture.json",
            "python -m trustai mcp-proxy-capture-verify artifacts/mcp-proxy-capture.json --events examples/aitrade/mcp-proxy-events.json",
            "python -m trustai mcp-proxy-capture-append artifacts/mcp-proxy-capture.json --events examples/aitrade/mcp-proxy-events.json --state .trustai/mcp-proxy-capture-demo/evidence-chain.json --tenant mcp-proxy-capture-local --out artifacts/mcp-proxy-capture-entry.json",
            "python -m unittest tests.test_mcp_gateway",
        ],
    },
    {
        "id": "mcp-gateway-production-authority-dossiers",
        "description": "MCP gateway production authority dossiers bind normalized MCP transcript hash chains to production proxy fleet, tool registry, session auth, replay, immutable audit, scheduler, policy, network, KMS, freshness, and observability authority evidence.",
        "reference": "src/trustai/mcp_gateway_authority.py",
        "commands": [
            "python -m trustai mcp-gateway-authority examples/aitrade/mcp-transcript.json --mode proxy-dossier --environment aitrade-prod --dossier-ref dossier:mcp-gateway-authority/aitrade-prod --authority-ref authority:mcp-gateway/proxy-prod --producer-ref oidc:trustai.example/mcp-gateway-authority-worker --authority-evidence 'production-mcp-proxy-worker-fleet,hosted-service,mcp-proxy:fleet/aitrade-prod,sha256:mcp-proxy-worker-fleet,Hosted MCP proxy worker fleet export for governed tool-call capture;issuer=TrustAI Hosted Ops;subject=aitrade-prod MCP proxy fleet;source_uri=https://mcp.example/audit/fleet/aitrade-prod;issued_at=2026-07-12T03:10:00Z;expires_at=2026-07-19T03:10:00Z' --generated-at 2026-07-12T03:12:00Z --now 2026-07-15T00:00:00Z",
            "python -m trustai mcp-gateway-authority-verify artifacts/mcp-gateway-authority.json examples/aitrade/mcp-transcript.json --now 2026-07-15T00:00:00Z",
            "python -m unittest tests.test_mcp_gateway_authority",
        ],
    },
    {
        "id": "trust-authority-receipts",
        "description": "Trust authority receipts bind keyring-verified chain and proof-pack evidence to redacted KMS/TSA provider summaries.",
        "reference": "src/trustai/trust_authority.py",
        "commands": [
            "python -m trustai trust-authority-receipt --state .trustai/demo/evidence-chain.json --tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json",
            "python -m trustai trust-authority-verify artifacts/trust-authority-receipt.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json",
        ],
    },
    {
        "id": "trust-authority-provider-attestations",
        "description": "Trust authority provider attestations bind verified trust-authority receipts to KMS/HSM signing and independent RFC 3161 TSA endpoint/request/response evidence.",
        "reference": "src/trustai/trust_authority_provider.py",
        "commands": [
            "python -m trustai trust-authority-provider-attestation artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json --kms-provider ExampleCloudKMS --kms-endpoint https://kms.example/sign --kms-key-ref kms:example/trustai/evidence-signing --kms-request-hash sha256:kms-sign-request --kms-response-status 200 --kms-response-hash sha256:kms-sign-response --tsa-provider ExampleRFC3161TSA --tsa-endpoint https://tsa.example/timestamp --tsa-request-hash sha256:tsa-request --tsa-response-status 200 --tsa-response-hash sha256:tsa-response --tsa-certificate-chain-hash sha256:tsa-certificate-chain --actor-ref oidc:trustai.example/trust-authority-worker --credential-ref env:TRUST_AUTHORITY_PROVIDER_TOKEN --audit-log-ref audit-log:trust-authority/provider --audit-log-root sha256:trust-authority-provider-audit-root --retention-until 2033-07-04T00:00:00Z --mode provider-attested --attested-at 2026-07-04T03:01:00Z",
            "python -m trustai trust-authority-provider-verify artifacts/trust-authority-provider-attestation.json artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json",
            "python -m unittest tests.test_trust_authority_provider",
        ],
    },
    {
        "id": "trust-authority-kms-enforcement",
        "description": "Trust authority KMS enforcement receipts bind provider attestations to customer-controlled HSM attestation, key/timestamp policy, actor, quorum, denied-operation, response, and audit-root evidence.",
        "reference": "src/trustai/trust_authority_kms_enforcement.py",
        "commands": [
            "python -m trustai trust-authority-kms-enforcement artifacts/trust-authority-provider-attestation.json artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json --mode provider-enforced --enforcement-ref kms-enforcement:trust-authority/provider/2026-07-04 --provider ExampleCloudHSM --provider-endpoint https://kms.example/enforcement/trust-authority --credential-ref env:TRUST_AUTHORITY_KMS_TOKEN --actor-ref oidc:trustai.example/trust-authority-kms-worker --hsm-attestation-ref hsm-attestation:example/trust-authority/2026-07-04 --hsm-attestation-hash sha256:trust-authority-hsm-attestation --key-policy-ref policy:kms/trustai-evidence-signing-v0.1 --key-policy-hash sha256:kms-key-policy --timestamp-policy-ref policy:tsa/trustai-timestamping-v0.1 --timestamp-policy-hash sha256:tsa-policy --timestamp-attestation-ref tsa-attestation:example/trust-authority/2026-07-04 --timestamp-attestation-hash sha256:trust-authority-tsa-attestation --allowed-actor-ref oidc:trustai.example/trust-authority-kms-worker --denied-operation-ref kms:export-private-key --quorum-required 2 --quorum-approver-ref oidc:trustai.example/security-admin --quorum-approver-ref oidc:trustai.example/compliance-admin --audit-log-ref audit-log:trust-authority/provider --audit-log-root sha256:trust-authority-provider-audit-root --audit-log-size 7 --evidence-ref evidence:trust-authority/kms-enforcement --response-status 200 --response-body examples/aitrade/trust-authority-kms-response.json --enforced-at 2026-07-04T03:02:00Z",
            "python -m trustai trust-authority-kms-enforcement-verify artifacts/trust-authority-kms-enforcement.json artifacts/trust-authority-provider-attestation.json artifacts/trust-authority-receipt.json --source-state .trustai/demo/evidence-chain.json --source-tenant aitrade-local --keyring .trustai/keyring.local.json --pack artifacts/aitrade-proof-pack.json",
            "python -m unittest tests.test_trust_authority_kms_enforcement",
        ],
    },
    {
        "id": "verifier-conformance-report",
        "description": "Verifier conformance vectors prove valid packs pass and tampered packs fail offline.",
        "reference": "src/trustai/verifier_conformance.py",
        "commands": [
            "python -m trustai verifier-conformance artifacts/aitrade-proof-pack.json",
            "python -m trustai verifier-conformance-verify artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "worm-legal-hold-audit",
        "description": "WORM receipts and legal holds verify stored object hash, retention state, and legal-hold binding offline.",
        "reference": "src/trustai/object_store.py",
        "commands": [
            "python -m trustai seal artifacts/aitrade-proof-pack.json --artifact-type proof-pack --out artifacts/aitrade-proof-pack.worm-receipt.json",
            "python -m trustai worm-legal-hold artifacts/aitrade-proof-pack.worm-receipt.json --case-id external-audit-2026-001 --reason Preserve --applied-by legal@example.com --out artifacts/aitrade-proof-pack.legal-hold.json",
            "python -m trustai worm-audit artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json",
        ],
    },
    {
        "id": "byoc-operator-attestations",
        "description": "BYOC operator attestations bind deployment manifests to Object Lock, WORM legal holds, backup/restore, tenant, keyring, network, and operator controls.",
        "reference": "src/trustai/byoc_operator.py",
        "commands": [
            "python -m trustai byoc-operator-attestation artifacts/deployment-manifest.json artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --environment aitrade-byoc --operator-ref operator:trustai/byoc --operator-version 0.1.0 --operator-image ghcr.io/trustai/operator:0.1.0 --operator-image-digest sha256:trustai-byoc-operator-digest --namespace trustai --service-account-ref k8s:sa/trustai/operator --reconciler-ref controller:trustai/byoc-operator --upgrade-policy-ref policy:trustai/byoc-upgrade-v0.1 --rollback-policy-ref policy:trustai/byoc-rollback-v0.1 --tenant-id aitrade-local --customer-account-ref aws:123456789012 --data-plane-ref k8s:cluster/aitrade-prod --keyring-ref keyring:.trustai/keyring.local.json --object-lock-provider ExampleS3ObjectLock --object-lock-bucket arn:aws:s3:::trustai-aitrade-evidence --object-lock-region us-east-1 --backup-policy-ref backup:trustai/daily --backup-schedule daily --restore-test-ref restore-test:trustai/2026-07-04 --restore-test-at 2026-07-04T02:00:00Z --rpo-minutes 60 --rto-minutes 240 --ingress-mode private-load-balancer --egress-policy-ref egress-policy:trustai/deny-by-default --audit-log-ref audit-log:byoc/operator --audit-log-root sha256:byoc-operator-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/byoc-operator --credential-ref env:BYOC_OPERATOR_TOKEN --attested-at 2026-07-04T03:00:00Z",
            "python -m trustai byoc-operator-verify artifacts/byoc-operator-attestation.json artifacts/deployment-manifest.json artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm",
            "python -m unittest tests.test_byoc_operator",
        ],
    },
    {
        "id": "byoc-production-authority-dossiers",
        "description": "BYOC/self-hosted production authority dossiers bind deployment manifests, BYOC operator attestations, Object Lock/legal-hold evidence, customer account/keyring/network/backup/audit bindings, retained authority artifact replay, freshness windows, and production-claim limits.",
        "reference": "src/trustai/byoc_authority.py",
        "commands": [
            'python -m trustai byoc-authority artifacts/deployment-manifest.json artifacts/byoc-operator-attestation.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --environment aitrade-byoc --dossier-ref dossier:byoc-authority/aitrade-byoc --authority-ref authority:byoc/aitrade-byoc --producer-ref oidc:trustai.example/byoc-authority-worker --authority-evidence "live-cloud-account-binding,provider-api,aws:account/123456789012/trustai-byoc,sha256:byoc-live-cloud-account,Provider account export;issuer=ExampleCloud;subject=aitrade BYOC account;source_uri=https://cloud.example/accounts/123456789012/trustai;issued_at=2026-07-04T03:05:00Z;expires_at=2026-12-31T00:00:00Z" --authority-evidence "network-policy-admission-audit-export,provider-api,k8s:networkpolicy/trustai/trustai-api,sha256:9522f836335568ccbad169b9bfe7ba2a214e101732edba04665f9833fc2e2f8d,Provider Kubernetes NetworkPolicy admission export;issuer=Example Kubernetes API;subject=trustai-api NetworkPolicy;source_uri=https://cloud.example/kubernetes/aitrade-prod/networkpolicies/trustai-api;issued_at=2026-07-04T03:07:00Z;expires_at=2026-12-31T00:00:00Z" --authority-artifact "network-policy-admission-audit-export,examples/aitrade/byoc-network-policy-authority-export.json" --generated-at 2026-07-04T03:10:00Z --out artifacts/byoc-authority.json',
            'python -m trustai byoc-authority-verify artifacts/byoc-authority.json --deployment-manifest artifacts/deployment-manifest.json --byoc-operator artifacts/byoc-operator-attestation.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --authority-artifact "network-policy-admission-audit-export,examples/aitrade/byoc-network-policy-authority-export.json" --require-fresh --now 2026-07-04T03:10:00Z',
            'python -m trustai byoc-authority-append artifacts/byoc-authority.json artifacts/deployment-manifest.json artifacts/byoc-operator-attestation.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --authority-artifact "network-policy-admission-audit-export,examples/aitrade/byoc-network-policy-authority-export.json"',
            "python -m unittest tests.test_byoc_authority",
        ],
    },
    {
        "id": "eu-data-plane-attestations",
        "description": "EU data-plane attestations bind deployment and BYOC operator evidence to Frankfurt/EU region, residency, key-residency, transfer-governance, subprocessor, network, and audit controls.",
        "reference": "src/trustai/eu_data_plane.py",
        "commands": [
            "python -m trustai eu-data-plane-attestation artifacts/deployment-manifest.json artifacts/eu-byoc-operator-attestation.json --root . --environment aitrade-eu-prod --tenant-id aitrade-eu --data-plane-ref k8s:cluster/aitrade-eu-central-1 --control-plane-ref trustai:control-plane/eu --primary-region eu-central-1 --primary-location 'Frankfurt, Germany' --availability-zone eu-central-1a --availability-zone eu-central-1b --availability-zone eu-central-1c --replica-region eu-west-1 --backup-region eu-central-1 --backup-region eu-west-3 --analytics-region eu-central-1 --log-region eu-central-1 --data-category agent_trace_hashes --data-category proof_pack_metadata --data-category policy_decision_metadata --subprocessor-ref subprocessor:aws-eu --subprocessor-ref subprocessor:example-rfc3161-tsa-eu --residency-policy-ref policy:trustai/eu-residency-v0.1 --data-classification-policy-ref policy:trustai/eu-data-classification-v0.1 --dpa-ref dpa:trustai/aitrade-eu-2026 --transfer-impact-assessment-ref tia:trustai/aitrade-eu-2026 --deletion-policy-ref policy:trustai/eu-deletion-v0.1 --data-export-policy-ref policy:trustai/eu-export-v0.1 --encryption-key-ref kms:eu-central-1:trustai/aitrade-eu/evidence --kms-key-region eu-central-1 --key-access-policy-ref policy:kms/aitrade-eu-key-access-v0.1 --hsm-ref hsm:eu-central-1/trustai-eu --network-policy-ref netpol:trustai/eu-deny-by-default --support-access-policy-ref policy:trustai/eu-jit-support-v0.1 --breakglass-policy-ref policy:trustai/eu-breakglass-v0.1 --audit-log-ref audit-log:eu-data-plane/service --audit-log-root sha256:eu-data-plane-audit-root --access-log-ref access-log:eu-data-plane/sessions --access-log-root sha256:eu-data-plane-access-root --transfer-log-ref transfer-log:eu-data-plane/egress --transfer-log-root sha256:eu-data-plane-transfer-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/eu-data-plane-operator --credential-ref env:EU_DATA_PLANE_TOKEN --evidence-ref evidence:eu-data-plane/service --attested-at 2026-07-04T04:00:00Z",
            "python -m trustai eu-data-plane-verify artifacts/eu-data-plane-attestation.json artifacts/deployment-manifest.json artifacts/eu-byoc-operator-attestation.json --root .",
            "python -m unittest tests.test_eu_data_plane",
        ],
    },
    {
        "id": "signed-verifier-release",
        "description": "Verifier release manifests bind hashed source files, conformance evidence, standards package, and detached signature.",
        "reference": "src/trustai/verifier_release.py",
        "commands": [
            "python -m trustai verifier-release --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json",
            "python -m trustai verifier-release-verify artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json",
        ],
    },
    {
        "id": "go-offline-verifier-source",
        "description": "Dependency-free Go verifier source mirrors offline proof-pack checks for static binary builds.",
        "reference": "verifier/go/trustai-verify/main.go",
        "commands": [
            "python -m unittest tests.test_go_verifier_source",
            "Push-Location verifier/go/trustai-verify; go test .; Pop-Location",
        ],
    },
    {
        "id": "go-verifier-release-workflow",
        "description": "GitHub Actions release workflow tests the dependency-free Go verifier source, cross-builds static verifier artifacts, and emits checksums, SBOM, provenance, and build attestation hooks.",
        "reference": ".github/workflows/go-verifier.yml",
        "commands": [
            "python -m unittest tests.test_go_verifier_release_workflow",
            "GitHub Actions: Go verifier workflow on pull_request, main, verifier-v* tags, and workflow_dispatch",
        ],
    },
    {
        "id": "go-verifier-build-attestations",
        "description": "Go verifier build attestations bind release source, conformance evidence, standards package, static-build controls, and optional binary/provenance hashes.",
        "reference": "src/trustai/go_verifier_build.py",
        "commands": [
            "python -m trustai go-verifier-build-attestation artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --mode source-plan --builder-ref builder:trustai/go-verifier/local --toolchain-ref go:download-required --toolchain-version not-installed-local-reference --goos linux --goarch amd64 --build-started-at 2026-07-16T00:00:00Z --build-finished-at 2026-07-16T00:01:00Z --attested-at 2026-07-16T00:02:00Z",
            "python -m trustai go-verifier-build-verify artifacts/go-verifier-build-attestation.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root .",
            "python -m unittest tests.test_go_verifier_build",
        ],
    },
    {
        "id": "verifier-source-distribution-receipts",
        "description": "Verifier distribution receipts bind the signed verifier release to a deterministic source bundle, SBOM, provenance metadata, detached signature artifact, and chain append evidence without claiming a compiled Go binary.",
        "reference": "src/trustai/verifier_distribution.py",
        "commands": [
            "python -m trustai verifier-distribution artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --bundle artifacts/verifier-source-bundle.zip --sbom artifacts/verifier-source-sbom.json --provenance artifacts/verifier-source-provenance.json --signature artifacts/verifier-source-signature.json --distribution-ref release:trustai-verifier/source-v0.1 --channel local-source-bundle --publisher-ref publisher:trustai/local --release-url https://github.com/MSBeni/trust_ai/releases/tag/source-v0.1 --generated-at 2026-07-16T00:03:00Z",
            "python -m trustai verifier-distribution-verify artifacts/verifier-distribution.json artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --bundle artifacts/verifier-source-bundle.zip --sbom artifacts/verifier-source-sbom.json --provenance artifacts/verifier-source-provenance.json --signature artifacts/verifier-source-signature.json",
            "python -m unittest tests.test_verifier_distribution",
        ],
    },
    {
        "id": "verifier-public-release-authority-dossiers",
        "description": "Verifier public release authority dossiers bind signed verifier public release receipts to provider workflow, release API, artifact manifest, SBOM/provenance/signature, transparency-log, audit-log, credential-custody, freshness, retained provider workflow export replay, and production-claim evidence.",
        "reference": "src/trustai/verifier_release_authority.py",
        "commands": [
            "python -m trustai verifier-release-authority artifacts/verifier-public-release.json artifacts/verifier-release.json artifacts/verifier-distribution.json artifacts/go-verifier-build-attestation.json artifacts/go-verifier-release-run.json artifacts/go-verifier-release-run-bundle.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --distribution-bundle artifacts/verifier-source-bundle.zip --distribution-sbom artifacts/verifier-source-sbom.json --distribution-provenance artifacts/verifier-source-provenance.json --distribution-signature artifacts/verifier-source-signature.json --binary dist/trustai-verify-linux-amd64 --environment release-prod --dossier-ref dossier:verifier-release-authority/v0.1.0 --authority-ref authority:verifier-release/github/v0.1.0 --producer-ref oidc:trustai.example/verifier-release-authority-worker --authority-evidence 'completed-provider-workflow-run,ci-run,github-actions-run:1234567890,sha256:a86fee6cea8e9a0f1128988ebf3d64cfb14baa788c5f1626be1bf1f6e4a99c94,Provider workflow run export;issuer=GitHub Actions;subject=trustai verifier release v0.1.0;source_uri=https://github.com/MSBeni/trust_ai/actions/runs/1234567890;issued_at=2026-07-16T00:10:00Z;expires_at=2026-07-23T00:10:00Z' --authority-artifact 'completed-provider-workflow-run,examples/aitrade/external-evidence/go-verifier-workflow-run.json' --generated-at 2026-07-16T00:12:00Z",
            "python -m trustai verifier-release-authority-verify artifacts/verifier-release-authority.json artifacts/verifier-public-release.json artifacts/verifier-release.json artifacts/verifier-distribution.json artifacts/go-verifier-build-attestation.json artifacts/go-verifier-release-run.json artifacts/go-verifier-release-run-bundle.json --conformance-report artifacts/verifier-conformance.json --standards-package artifacts/standards-submission.json --root . --distribution-bundle artifacts/verifier-source-bundle.zip --distribution-sbom artifacts/verifier-source-sbom.json --distribution-provenance artifacts/verifier-source-provenance.json --distribution-signature artifacts/verifier-source-signature.json --binary dist/trustai-verify-linux-amd64 --authority-artifact 'completed-provider-workflow-run,examples/aitrade/external-evidence/go-verifier-workflow-run.json'",
            "python -m unittest tests.test_verifier_release_authority",
        ],
    },
    {
        "id": "standards-body-submission-receipts",
        "description": "Standards-body submission receipts bind a standards package, verifier release, and conformance report to standards-track docket evidence.",
        "reference": "src/trustai/standards_body_submission.py",
        "commands": [
            "python -m trustai standards-body-submit --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --standards-body LinuxFoundationTrustAI --submitted-at 2026-07-17T00:00:00Z",
            "python -m trustai standards-body-verify artifacts/standards-body-submission.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "standards-body-status-receipts",
        "description": "Standards-body status receipts bind docket acknowledgement, ballot, and decision updates to a verified standards-body submission receipt.",
        "reference": "src/trustai/standards_body_status.py",
        "commands": [
            "python -m trustai standards-body-status artifacts/standards-body-submission.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --new-status acknowledged --docket-ref LF-TRUSTAI-DKT-2026-001 --actor-ref oidc:standards.example/chair-1 --decided-at 2026-07-18T00:00:00Z",
            "python -m trustai standards-body-status-verify artifacts/standards-body-status.json --submission artifacts/standards-body-submission.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "standards-body-ballot-receipts",
        "description": "Standards-body ballot receipts bind ballot tally, quorum math, decision references, source submission evidence, and optional docket status context.",
        "reference": "src/trustai/standards_body_ballot.py",
        "commands": [
            "python -m trustai standards-body-ballot artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --ballot-ref LF-TRUSTAI-BALLOT-2026-001 --decision-ref LF-TRUSTAI-DECISION-2026-001 --eligible-voters 7 --votes-for 6 --votes-against 1 --quorum-required 4 --approval-threshold-percent 66 --actor-ref oidc:standards.example/chair-1 --decided-at 2026-07-25T02:00:00Z",
            "python -m trustai standards-body-ballot-verify artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "standards-body-ballot-system-receipts",
        "description": "Standards-body ballot-system receipts bind accepted ballot receipts to hosted ballot-system export requests, export hashes, and optional provider responses.",
        "reference": "src/trustai/standards_body_ballot_system.py",
        "commands": [
            "python -m trustai standards-body-ballot-system artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --ballot-system LFTrustAIBallotSystem --endpoint-base https://ballots.example --credential-ref env:STANDARDS_BALLOT_TOKEN --mode authenticated-export --export-ref LF-TRUSTAI-BALLOT-2026-001:export --actor-ref oidc:standards.example/ballot-system --response-status 200 --exported-at 2026-07-25T04:00:00Z",
            "python -m trustai standards-body-ballot-system-verify artifacts/standards-body-ballot-system.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "standards-body-provider-posting-receipts",
        "description": "Standards-body provider posting receipts bind hosted ballot-system exports to credential exchange metadata, provider request hashes, and optional accepted provider responses.",
        "reference": "src/trustai/standards_body_provider_posting.py",
        "commands": [
            "python -m trustai standards-body-provider-posting artifacts/standards-body-ballot-system.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --provider LFStandardsPostingAPI --endpoint-base https://standards.example --credential-ref env:STANDARDS_API_TOKEN --mode provider-posted --posting-ref LF-TRUSTAI-BALLOT-2026-001:provider-post --actor-ref oidc:standards.example/ballot-system --credential-response-status 200 --response-status 201 --posted-at 2026-07-25T05:00:00Z",
            "python -m trustai standards-body-provider-posting-verify artifacts/standards-body-provider-posting.json --ballot-system artifacts/standards-body-ballot-system.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --standards-package artifacts/standards-submission.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "provider-installation-manifests",
        "description": "Provider installation manifests verify GitHub/GitLab/Slack app installation references, permissions, scopes, subscribed events, callback ingress, redacted credentials, and audit-log access scopes.",
        "reference": "src/trustai/provider_installation.py",
        "commands": [
            "python -m trustai provider-installation --provider github --app-ref github-app:trustai-local --installation-ref github-installation:123456 --tenant-ref github-org:volelabs --permission checks:write --event check_suite",
            "python -m trustai provider-installation-verify artifacts/provider-installation.json",
            "python -m unittest tests.test_provider_installation",
        ],
    },
    {
        "id": "provider-delivery-receipts",
        "description": "Provider delivery receipts verify API-ready payload dispatch intent, retained payload artifact byte replay, optional local HTTP dispatch, redacted credential binding, request hash, and response hash.",
        "reference": "src/trustai/delivery.py",
        "commands": [
            "python -m trustai provider-delivery artifacts/github-check-run-payload.json --endpoint-base https://api.github.com --credential-ref env:GITHUB_TOKEN",
            "python -m trustai provider-delivery-verify artifacts/provider-delivery.json --payload artifacts/github-check-run-payload.json",
            "python -m unittest tests.test_provider_delivery",
        ],
    },
    {
        "id": "promotion-status-receipts",
        "description": "Promotion status receipts bind verified proof-pack gate decisions to GitHub/GitLab status payloads and optional provider delivery receipts before CI/CD promotion status is trusted.",
        "reference": "src/trustai/cicd.py",
        "commands": [
            "python -m trustai promotion-status artifacts/aitrade-proof-pack.json artifacts/github-check-run-payload.json --delivery artifacts/github-check-run-delivery.json --attested-at 2026-07-04T00:01:00Z --out artifacts/promotion-status.json",
            "python -m trustai promotion-status-verify artifacts/promotion-status.json --pack artifacts/aitrade-proof-pack.json --payload artifacts/github-check-run-payload.json --delivery artifacts/github-check-run-delivery.json",
            "python -m trustai promotion-status-append artifacts/promotion-status.json --pack artifacts/aitrade-proof-pack.json --payload artifacts/github-check-run-payload.json --delivery artifacts/github-check-run-delivery.json --state .trustai/promotion-status-demo/evidence-chain.json --tenant promotion-status-local --out artifacts/promotion-status-entry.json",
            "python -m unittest tests.test_provider_delivery",
        ],
    },
    {
        "id": "provider-webhook-receipts",
        "description": "Provider webhook receipts verify GitHub/GitLab callback signatures or tokens, bind raw payload hashes and retained payload artifact byte replay, redact provider secrets, deduplicate provider retries, and append first-seen inbound provider events as chain evidence.",
        "reference": "src/trustai/provider_webhook.py",
        "commands": [
            "python -m trustai provider-webhook github examples/webhooks/github-check-suite.json --secret env:GITHUB_WEBHOOK_SECRET --header X-Hub-Signature-256:sha256=... --header X-GitHub-Delivery:delivery-123 --header X-GitHub-Event:check_suite",
            "python -m trustai provider-webhook-verify artifacts/provider-webhook.json examples/webhooks/github-check-suite.json --secret env:GITHUB_WEBHOOK_SECRET --header X-Hub-Signature-256:sha256=... --header X-GitHub-Delivery:delivery-123 --header X-GitHub-Event:check_suite",
            "python -m unittest tests.test_provider_webhook",
        ],
    },
    {
        "id": "provider-delivery-service-attestations",
        "description": "Provider delivery service attestations bind provider delivery receipts and retained payload artifact replay to dispatch worker fleet, queue, DLQ, retry, idempotency, outbound proxy, provider endpoint, egress, rate limits, request signing, audit, metrics, actor, redacted credentials, and optional provider operations service evidence.",
        "reference": "src/trustai/provider_delivery_service.py",
        "commands": [
            "python -m trustai provider-delivery-service-attestation artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json --environment aitrade-prod --service-ref provider-delivery:trustai/github-prod --service-version 0.1.0 --service-image ghcr.io/trustai/provider-delivery:0.1.0 --service-image-digest sha256:trustai-provider-delivery-image --service-binary-hash sha256:trustai-provider-delivery-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --dispatch-worker-ref worker:provider-delivery/github --queue-ref queue:provider-delivery/github --dead-letter-queue-ref queue:provider-delivery/github-dlq --idempotency-store-ref redis:provider-delivery/idempotency --retry-policy-ref retry:provider-delivery/exponential-v0.1 --outbound-proxy-ref egress-proxy:provider-delivery --provider-endpoint-base https://api.github.com --provider-credential-ref env:GITHUB_TOKEN --mtls-policy-ref policy:provider-delivery/mtls-required-v0.1 --auth-policy-ref policy:provider-delivery/oidc-authz-v0.1 --network-policy-ref netpol:provider-delivery/deny-by-default --egress-policy-ref egress:provider-delivery/provider-apis-only --rate-limit-policy-ref rate-limit:provider-delivery/github --request-signing-policy-ref policy:provider-delivery/request-signing-v0.1 --audit-log-ref audit-log:provider-delivery/service --audit-log-root sha256:provider-delivery-service-audit-root --metrics-ref metrics:provider-delivery/service --alert-policy-ref alert:provider-delivery/service --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/provider-delivery-operator --credential-ref env:PROVIDER_DELIVERY_TOKEN --evidence-ref evidence:provider-delivery/service --attested-at 2026-07-08T05:10:00Z --out artifacts/provider-delivery-service-attestation.json",
            "python -m trustai provider-delivery-service-verify artifacts/provider-delivery-service-attestation.json --delivery artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json",
            "python -m unittest tests.test_provider_delivery_service",
        ],
    },
    {
        "id": "provider-delivery-worker-receipts",
        "description": "Provider delivery worker receipts bind individual dispatch worker runs to delivery service attestations, source delivery receipts, retained payload artifact replay, scheduler leases, checkpoints, queue/DLQ metadata, idempotency, provider request/response hashes, delivery/provider/audit log roots, and redacted worker/provider credentials.",
        "reference": "src/trustai/provider_delivery_worker.py",
        "commands": [
            "python -m trustai provider-delivery-worker artifacts/github-check-run-delivery.json --service-attestation artifacts/provider-delivery-service-attestation.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json --mode dispatch-worker --environment aitrade-prod --worker-ref worker:provider-delivery/github --run-ref worker-run:provider-delivery/github/2026-07-08T05:15:00Z --operation-kind provider_payload_dispatch --actor-ref oidc:trustai.example/provider-delivery-worker --schedule-ref schedule:provider-delivery/github/continuous --cadence-seconds 30 --lease-ref lease:provider-delivery/github/2026-07-08T05:15:00Z --checkpoint-ref checkpoint:provider-delivery/github --checkpoint-hash sha256:provider-delivery-worker-checkpoint --queue-ref queue:provider-delivery/github --queue-message-ref queue-message:provider-delivery/github/check-run --dead-letter-queue-ref queue:provider-delivery/github-dlq --destination-ref https://api.github.com/repos/volelabs/trust_ai/check-runs --idempotency-record-hash sha256:provider-delivery-worker-idempotency --provider-request-ref provider-request:github/check-run/2026-07-08T05:15:00Z --request-hash sha256:provider-delivery-worker-request --delivery-log-ref delivery-log:provider-delivery/github --delivery-log-root sha256:provider-delivery-worker-delivery-root --provider-event-log-ref github:check-run-events/aitrade --provider-event-log-root sha256:provider-delivery-worker-provider-event-root --metrics-ref metrics:provider-delivery/workers --audit-log-ref audit-log:provider-delivery/workers --audit-log-root sha256:provider-delivery-worker-audit-root --credential-ref env:PROVIDER_DELIVERY_WORKER_TOKEN --provider-credential-ref env:GITHUB_TOKEN --retention-until 2033-07-08T00:00:00Z --started-at 2026-07-08T05:15:00Z --completed-at 2026-07-08T05:15:01Z",
            "python -m trustai provider-delivery-worker-verify artifacts/provider-delivery-worker.json artifacts/github-check-run-delivery.json --service-attestation artifacts/provider-delivery-service-attestation.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json",
            "python -m unittest tests.test_provider_delivery_worker",
        ],
    },
    {
        "id": "provider-approval-production-authority-dossiers",
        "description": "Provider approval production authority dossiers bind Slack approval callbacks, provider webhook receipts, provider delivery authority, and provider operations authority to CI/CD approval production evidence, freshness windows, and production-claim limits.",
        "reference": "src/trustai/provider_approval_authority.py",
        "commands": [
            "python -m trustai provider-approval-authority artifacts/approval-request.json artifacts/approval-callback.json --webhook artifacts/github-provider-webhook.json --delivery-authority artifacts/provider-delivery-authority.json --operations-authority artifacts/provider-operations-authority.json --environment aitrade-prod --dossier-ref dossier:provider-approval-authority/github-prod --authority-ref authority:provider-approval/github-prod --producer-ref oidc:trustai.example/provider-approval-authority-worker --authority-evidence \"hosted-approval-callback-ingress,hosted-service,service:provider-approval/github-prod,sha256:provider-approval-hosted-ingress-authority,Hosted approval callback ingress and worker fleet export;issuer=TrustAI Cloud;subject=aitrade-prod provider approval callback fleet;source_uri=https://ops.example/trustai/provider-approval/github-prod;issued_at=2026-07-08T06:02:00Z;expires_at=2026-07-15T06:02:00Z\" --generated-at 2026-07-08T06:05:00Z --out artifacts/provider-approval-authority.json",
            "python -m trustai provider-approval-authority-verify artifacts/provider-approval-authority.json artifacts/approval-request.json artifacts/approval-callback.json --webhook artifacts/github-provider-webhook.json --delivery-authority artifacts/provider-delivery-authority.json --operations-authority artifacts/provider-operations-authority.json",
            "python -m unittest tests.test_provider_approval_authority",
        ],
    },
    {
        "id": "provider-delivery-production-authority-dossiers",
        "description": "Provider delivery production authority dossiers bind delivery service attestations, worker receipts, optional worker review bundles, retained payload replay status, and external provider posting authority evidence to freshness windows, missing coverage, and production-claim limits.",
        "reference": "src/trustai/provider_delivery_authority.py",
        "commands": [
            "python -m trustai provider-delivery-authority artifacts/provider-delivery-service-attestation.json --worker artifacts/provider-delivery-worker.json --worker-bundle artifacts/provider-delivery-worker-bundle.json --delivery artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json --environment aitrade-prod --dossier-ref dossier:provider-delivery-authority/github-prod --authority-ref authority:provider-delivery/github-prod --producer-ref oidc:trustai.example/provider-delivery-authority-worker --authority-evidence \"hosted-dispatch-worker-fleet,hosted-service,service:provider-delivery/github-prod,sha256:provider-delivery-hosted-fleet-authority,Hosted provider delivery dispatch worker fleet export;issuer=TrustAI Cloud;subject=aitrade-prod provider delivery dispatch fleet;source_uri=https://ops.example/trustai/provider-delivery/github-prod;issued_at=2026-07-08T05:40:00Z;expires_at=2026-07-15T05:40:00Z\" --generated-at 2026-07-08T05:45:00Z --out artifacts/provider-delivery-authority.json",
            "python -m trustai provider-delivery-authority-verify artifacts/provider-delivery-authority.json artifacts/provider-delivery-service-attestation.json --worker artifacts/provider-delivery-worker.json --worker-bundle artifacts/provider-delivery-worker-bundle.json --delivery artifacts/github-check-run-delivery.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json",
            "python -m unittest tests.test_provider_delivery_authority",
        ],
    },
    {
        "id": "provider-audit-correlations",
        "description": "Provider audit correlation receipts bind provider audit-log exports to TrustAI webhook or delivery receipts by source receipt hashes, matched audit event hashes, and non-secret provider criteria.",
        "reference": "src/trustai/provider_audit.py",
        "commands": [
            "python -m trustai provider-audit-correlation examples/webhooks/github-audit-log.json --webhook-receipt artifacts/github-provider-webhook.json --provider github",
            "python -m trustai provider-audit-verify artifacts/provider-audit-correlation.json --audit-log examples/webhooks/github-audit-log.json --webhook-receipt artifacts/github-provider-webhook.json",
            "python -m unittest tests.test_provider_audit",
        ],
    },
    {
        "id": "provider-audit-stream-receipts",
        "description": "Provider audit stream receipts bind provider-authenticated audit-log retrieval windows to endpoint hashes, cursor refs, redacted credentials, installation/lifecycle manifests, and optional audit correlations.",
        "reference": "src/trustai/provider_audit_stream.py",
        "commands": [
            "python -m trustai provider-audit-stream examples/webhooks/github-audit-log.json --provider github --stream-ref github:audit-log-stream:volelabs --endpoint-url https://api.github.com/orgs/volelabs/audit-log --credential-ref env:GITHUB_AUDIT_LOG_TOKEN --request-hash sha256:github-audit-log-request --response-status 200 --response-hash sha256:github-audit-log-response --actor-ref oidc:trustai.example/provider-audit-worker --window-start 2026-07-08T02:00:00Z --window-end 2026-07-08T02:10:00Z",
            "python -m trustai provider-audit-stream-verify artifacts/provider-audit-stream.json --audit-log examples/webhooks/github-audit-log.json --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --correlation artifacts/github-provider-audit-correlation.json",
            "python -m unittest tests.test_provider_audit_stream",
        ],
    },
    {
        "id": "provider-audit-worker-receipts",
        "description": "Provider audit worker receipts bind scheduled or hosted audit-log worker runs to stream receipts, correlation receipts, scheduler leases, checkpoints, lifecycle operations, and redacted provider credentials.",
        "reference": "src/trustai/provider_audit_worker.py",
        "commands": [
            "python -m trustai provider-audit-worker --stream-receipt artifacts/provider-audit-stream.json --correlation artifacts/github-provider-audit-correlation.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --lifecycle artifacts/provider-lifecycle.json --worker-ref worker:provider-audit/github --run-ref worker-run:provider-audit/github/2026-07-08T02:00:00Z --operation-kind stream_and_correlate --actor-ref oidc:trustai.example/provider-audit-worker --schedule-ref schedule:provider-audit/github/10m --cadence-seconds 600 --lease-ref lease:provider-audit/github/2026-07-08T02:00:00Z --checkpoint-ref checkpoint:provider-audit/github --credential-ref env:GITHUB_AUDIT_LOG_TOKEN --started-at 2026-07-08T02:10:00Z --completed-at 2026-07-08T02:12:00Z",
            "python -m trustai provider-audit-worker-verify artifacts/provider-audit-worker.json --stream-receipt artifacts/provider-audit-stream.json --correlation artifacts/github-provider-audit-correlation.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --lifecycle artifacts/provider-lifecycle.json",
            "python -m unittest tests.test_provider_audit_worker",
        ],
    },
    {
        "id": "provider-credential-custody-receipts",
        "description": "Provider credential custody receipts bind redacted provider credentials to vault/KMS custody metadata, policy hashes, rotation, revocation, quorum, audit roots, and provider source artifacts.",
        "reference": "src/trustai/provider_credential_custody.py",
        "commands": [
            "python -m trustai provider-credential-custody --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json --credential-ref env:GITHUB_AUDIT_LOG_TOKEN --credential-kind audit_log_token --custody-ref custody:github-audit-token:local --vault-ref vault:trustai/provider-audit --kms-provider TrustAIProviderCredentialVault --kms-endpoint https://vault.example/provider-credentials --key-ref kms:trustai/provider-audit-token --key-algorithm HMAC-SHA256 --policy-ref policy:provider-audit-token-custody-v0.1 --policy-hash sha256:provider-audit-token-custody-policy --rotation-ref rotation:github-audit-token:2026-07 --revocation-ref revocation:github-audit-token --audit-log-ref audit-log:trustai/provider-credentials --audit-log-root sha256:provider-credential-custody-root --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/provider-audit-worker --allowed-actor-ref oidc:trustai.example/provider-audit-worker --quorum-approver-ref oidc:trustai.example/security-admin --mode kms-attested --attestation-ref hsm-attestation:trustai/provider-audit-token/2026-07-08 --attestation-hash sha256:provider-audit-token-attestation --response-status 200 --response-hash sha256:provider-audit-token-vault-response",
            "python -m trustai provider-credential-custody-verify artifacts/provider-credential-custody.json --provider-installation artifacts/github-provider-installation.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json",
            "python -m unittest discover -s tests -p test_provider_credential_custody.py",
        ],
    },
    {
        "id": "provider-operations-service-attestations",
        "description": "Provider operations service attestations bind public ingress, OAuth/callback/audit workers, managed callback storage, vault/KMS, webhook signature/replay/dedup controls, scheduler lease/checkpoint, external-call policy, audit root, actor, redacted credentials, and provider source receipts.",
        "reference": "src/trustai/provider_operations_service.py",
        "commands": [
            "python -m trustai provider-operations-service-attestation --provider-installation artifacts/github-provider-installation.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-lifecycle-operation.json --audit-lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --credential-custody artifacts/provider-credential-custody.json --callback-store artifacts/provider-callback-store.json --callback-store-db .trustai/provider-callbacks.sqlite --audit-stream artifacts/provider-audit-stream.json --audit-correlation artifacts/github-provider-audit-correlation.json --environment aitrade-prod --service-ref provider-ops:trustai/github-prod --service-version 0.1.0 --service-image ghcr.io/trustai/provider-ops:0.1.0 --service-image-digest sha256:trustai-provider-ops-image --service-binary-hash sha256:trustai-provider-ops-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --public-ingress-ref ingress:trustai-example --oauth-worker-ref worker:provider-oauth/github --callback-worker-ref worker:provider-callbacks/github --audit-worker-ref worker:provider-audit/github --storage-ref postgres:provider-callbacks --vault-ref vault:trustai/provider-audit --kms-key-ref kms:trustai/provider-audit-token --mtls-policy-ref policy:provider-ops/mtls-required-v0.1 --auth-policy-ref policy:provider-ops/oidc-authz-v0.1 --webhook-signature-policy-ref policy:provider-ops/webhook-signature-v0.1 --replay-window-ref replay-window:provider-ops/5m --dedup-store-ref sqlite:provider-callbacks/dedup --rate-limit-policy-ref rate-limit:provider-ops/github --network-policy-ref netpol:provider-ops/deny-by-default --egress-policy-ref egress:provider-ops/provider-apis-only --scheduler-ref schedule:provider-audit/github/10m --lease-ref lease:provider-audit/github --checkpoint-ref checkpoint:provider-audit/github --external-call-policy-ref policy:provider-ops/external-calls-v0.1 --audit-log-ref audit-log:provider-ops/service --audit-log-root sha256:provider-ops-service-audit-root --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/provider-ops-operator --credential-ref env:PROVIDER_OPS_TOKEN --evidence-ref evidence:provider-ops/service --attested-at 2026-07-08T05:00:00Z --out artifacts/provider-operations-service-attestation.json",
            "python -m trustai provider-operations-service-verify artifacts/provider-operations-service-attestation.json --provider-installation artifacts/github-provider-installation.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-lifecycle-operation.json --audit-lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --credential-custody artifacts/provider-credential-custody.json --callback-store artifacts/provider-callback-store.json --callback-store-db .trustai/provider-callbacks.sqlite --audit-stream artifacts/provider-audit-stream.json --audit-correlation artifacts/github-provider-audit-correlation.json",
            "python -m unittest tests.test_provider_operations_service",
        ],
    },
    {
        "id": "provider-operations-production-authority-dossiers",
        "description": "Provider operations production authority dossiers bind provider operations service attestations to external callback infrastructure authority evidence, freshness windows, missing coverage, and production-claim limits.",
        "reference": "src/trustai/provider_operations_authority.py",
        "commands": [
            "python -m trustai provider-operations-authority artifacts/provider-operations-service-attestation.json --environment aitrade-prod --dossier-ref dossier:provider-operations-authority/github-prod --authority-ref authority:provider-operations/github-prod --producer-ref oidc:trustai.example/provider-operations-authority-worker --authority-evidence \"hosted-callback-worker-fleet,hosted-service,service:provider-ops/github-prod,sha256:provider-ops-hosted-fleet-authority,Hosted provider operations callback and audit worker fleet export;issuer=TrustAI Cloud;subject=aitrade-prod provider operations worker fleet;source_uri=https://ops.example/trustai/provider-ops/github-prod;issued_at=2026-07-08T05:30:00Z;expires_at=2026-07-15T05:30:00Z\" --generated-at 2026-07-08T05:35:00Z --out artifacts/provider-operations-authority.json",
            "python -m trustai provider-operations-authority-verify artifacts/provider-operations-authority.json artifacts/provider-operations-service-attestation.json",
            "python -m unittest tests.test_provider_operations_authority",
        ],
    },
    {
        "id": "provider-callback-store-manifests",
        "description": "Provider callback store manifests persist provider installations, inbound webhooks, outbound deliveries, audit correlations, and approval callbacks into indexed SQLite operational state with signed source-artifact bindings.",
        "reference": "src/trustai/provider_callback_store.py",
        "commands": [
            "python -m trustai provider-callback-store --db .trustai/provider-callbacks.sqlite --artifact artifacts/github-provider-installation.json --artifact artifacts/github-provider-webhook.json --artifact artifacts/github-provider-audit-correlation.json",
            "python -m trustai provider-callback-store-verify artifacts/provider-callback-store.json --db .trustai/provider-callbacks.sqlite",
            "python -m unittest tests.test_provider_callback_store",
        ],
    },
    {
        "id": "provider-ingress-manifests",
        "description": "Provider ingress manifests verify HTTPS callback ingress URLs, DNS/TLS bindings, network controls, provider signature schemes, and callback-store source bindings.",
        "reference": "src/trustai/provider_ingress.py",
        "commands": [
            "python -m trustai provider-ingress --ingress-base-url https://trustai.example --ingress-ref ingress:trustai-example --dns-name trustai.example --network-policy-ref network-policy:provider-callbacks --rate-limit-policy-ref rate-limit:provider-callbacks --provider-installation artifacts/github-provider-installation.json",
            "python -m trustai provider-ingress-verify artifacts/provider-ingress.json --provider-installation artifacts/github-provider-installation.json",
            "python -m unittest tests.test_provider_ingress",
        ],
    },
    {
        "id": "provider-callback-storage-manifests",
        "description": "Provider callback storage manifests verify Postgres-compatible request storage targets, SQLite migration bindings, HA topology, backup retention, encryption, network, and monitoring controls.",
        "reference": "src/trustai/provider_callback_storage.py",
        "commands": [
            "python -m trustai provider-callback-storage --storage-ref postgres:provider-callbacks --dsn-ref env:PROVIDER_CALLBACK_POSTGRES_DSN --schema-ref dbschema:provider-callbacks-v0.1 --migration-ref migration:provider-callbacks-sqlite-to-postgres-v0.1 --migration-hash sha256:provider-callback-storage-migration --primary-region us-west-2 --replica-region us-east-1 --backup-policy-ref backup:provider-callbacks-35d --retention-until 2033-07-08T00:00:00Z --encryption-key-ref kms:trustai/provider-callbacks --network-policy-ref network-policy:provider-callback-storage --monitoring-ref monitor:provider-callback-storage --failover-runbook-ref runbook:provider-callback-storage-failover --callback-store artifacts/provider-callback-store.json",
            "python -m trustai provider-callback-storage-verify artifacts/provider-callback-storage.json --callback-store artifacts/provider-callback-store.json",
            "python -m unittest tests.test_provider_callback_storage",
        ],
    },
    {
        "id": "provider-lifecycle-manifests",
        "description": "Provider lifecycle manifests bind OAuth callbacks, token exchange and storage, credential rotation, revocation, uninstall, provider audit-log stream, installation, ingress, and callback storage evidence.",
        "reference": "src/trustai/provider_lifecycle.py",
        "commands": [
            "python -m trustai provider-lifecycle --provider-installation artifacts/github-provider-installation.json --lifecycle-ref lifecycle:github-app:trustai-local --oauth-callback-url https://trustai.example/v0/provider-oauth/github/callback --authorization-ref oauth:github:authorization:local --token-exchange-ref oauth:github:token-exchange:local --token-store-ref secret:provider-token-store/github --refresh-policy-ref policy:provider-token-refresh --credential-rotation-ref rotation:github-app-private-key:2026-07 --revocation-endpoint https://api.github.com/app/installations/123456/access_tokens --revocation-ref revocation:github-installation:123456 --uninstall-ref uninstall:github-installation:123456 --audit-log-stream-ref github:audit-log-stream:volelabs",
            "python -m trustai provider-lifecycle-verify artifacts/provider-lifecycle.json --provider-installation artifacts/github-provider-installation.json",
            "python -m unittest tests.test_provider_lifecycle",
        ],
    },
    {
        "id": "provider-lifecycle-operation-receipts",
        "description": "Provider lifecycle operation receipts bind lifecycle manifests to recorded OAuth, token, credential, revocation, uninstall, and audit-stream provider response evidence.",
        "reference": "src/trustai/provider_lifecycle_operation.py",
        "commands": [
            "python -m trustai provider-lifecycle-operation --lifecycle artifacts/provider-lifecycle.json --operation-kind token_exchange --operation-ref oauth:github:token-exchange:local --provider-event-ref github:oauth-token-exchange:local --endpoint-url https://github.com/login/oauth/access_token --credential-ref env:GITHUB_APP_CLIENT_SECRET --token-ref secret:provider-token-store/github --request-hash sha256:github-token-exchange-request --response-status 200 --response-hash sha256:github-token-exchange-response --actor-ref oidc:trustai.example/provider-worker",
            "python -m trustai provider-lifecycle-operation-verify artifacts/provider-lifecycle-operation.json --lifecycle artifacts/provider-lifecycle.json",
            "python -m unittest tests.test_provider_lifecycle_operation",
        ],
    },
    {
        "id": "policy-engine-decision-receipts",
        "description": "Signed policy engine receipts bind policy decisions to proof packs, actions, and OPA/Cedar export artifacts.",
        "reference": "src/trustai/policy_engine.py",
        "commands": [
            "python -m trustai policy-engine-receipt examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --engine opa",
            "python -m trustai policy-engine-verify artifacts/policy-engine-receipt.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json",
        ],
    },
    {
        "id": "policy-backend-enforcement-receipts",
        "description": "Hosted OPA/Cedar backend enforcement receipts bind policy decisions to backend endpoint, request hash, response hash, redacted credentials, and policy-export evidence.",
        "reference": "src/trustai/policy_backend_enforcement.py",
        "commands": [
            "python -m trustai policy-backend-enforcement examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --backend-ref opa:trustai-runtime:prod --engine opa --endpoint-url https://opa.example/v1/data/trustai/runtime/allow --credential-ref env:OPA_BACKEND_TOKEN --request-hash sha256:policy-backend-request --response-status 200 --response-hash sha256:policy-backend-response --actor-ref oidc:trustai.example/runtime-policy --mode hosted-backend",
            "python -m trustai policy-backend-enforcement-verify artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json",
            "python -m unittest tests.test_policy_backend_enforcement",
        ],
    },
    {
        "id": "policy-backend-service-attestations",
        "description": "Policy backend service attestations bind hosted OPA/Cedar enforcement receipts to service image, bundle, mTLS/authn/z, tenant, resilience, decision-log, network, audit, and redacted credential evidence.",
        "reference": "src/trustai/policy_backend_service.py",
        "commands": [
            "python -m trustai policy-backend-service-attestation artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --environment aitrade-prod --service-ref policy-backend:trustai/opa-prod --service-version 0.1.0 --engine opa --backend-ref opa:trustai-runtime:prod --endpoint-url https://opa.example/v1/data/trustai/runtime/allow --service-image ghcr.io/trustai/policy-backend:0.1.0 --service-image-digest sha256:trustai-policy-backend-image --service-binary-hash sha256:trustai-policy-backend-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --mtls-policy-ref policy:policy-backend/mtls-required-v0.1 --auth-policy-ref policy:policy-backend/oidc-authz-v0.1 --tenant-isolation-ref tenant-isolation:aitrade/policy-backend --policy-sync-ref policy-sync:trustai/runtime-policy-bundle --admission-policy-ref admission:policy-backend/signed-bundles-only --rate-limit-policy-ref rate-limit:policy-backend/aitrade --circuit-breaker-ref circuit-breaker:policy-backend/opa --cache-store-ref redis:policy-backend/decision-cache --network-policy-ref netpol:policy-backend/deny-by-default --egress-policy-ref egress:policy-backend/kms-tsa-only --decision-log-ref decision-log:policy-backend/opa --decision-log-root sha256:policy-backend-decision-log-root --decision-log-retention-days 2555 --audit-log-ref audit-log:policy-backend/service --audit-log-root sha256:policy-backend-service-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/policy-backend-operator --credential-ref env:POLICY_BACKEND_SERVICE_TOKEN --evidence-ref evidence:policy-backend/service --attested-at 2026-07-04T04:02:00Z --out artifacts/policy-backend-service-attestation.json",
            "python -m trustai policy-backend-service-verify artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json",
            "python -m unittest tests.test_policy_backend_service",
        ],
    },
    {
        "id": "policy-backend-worker-receipts",
        "description": "Policy backend worker receipts bind individual scheduled OPA/Cedar backend operations to service attestations, enforcement receipts, scheduler leases, queue messages, request/response hashes, decision/audit roots, provider exports, and redacted credentials.",
        "reference": "src/trustai/policy_backend_worker.py",
        "commands": [
            "python -m trustai policy-backend-worker artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --mode hosted-worker --environment aitrade-prod --worker-ref worker:policy-backend/opa-enforcement --run-ref worker-run:policy-backend/opa/2026-07-04T04:05:00Z --operation-kind policy_enforcement --actor-ref oidc:trustai.example/policy-backend-worker --schedule-ref schedule:policy-backend/opa/continuous --cadence-seconds 30 --lease-ref lease:policy-backend/opa/2026-07-04T04:05:00Z --checkpoint-ref checkpoint:policy-backend/opa --checkpoint-hash sha256:policy-backend-worker-checkpoint --queue-ref queue:policy-backend/opa-enforcement --queue-message-ref queue-message:policy-backend/opa/action-123 --queue-message-hash sha256:policy-backend-worker-queue-message --backend-request-ref opa-request:policy-backend/opa/action-123 --decision-log-ref decision-log:policy-backend/opa --decision-log-root sha256:policy-backend-worker-decision-log-root --metrics-ref metrics:policy-backend/workers --audit-log-ref audit-log:policy-backend/service --audit-log-root sha256:policy-backend-worker-audit-root --retention-until 2033-07-04T00:00:00Z --credential-ref env:POLICY_BACKEND_SERVICE_TOKEN --backend-credential-ref env:OPA_BACKEND_TOKEN --started-at 2026-07-04T04:05:00Z --completed-at 2026-07-04T04:05:01Z",
            "python -m trustai policy-backend-worker-verify artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json",
            "python -m unittest tests.test_policy_backend_worker",
        ],
    },
    {
        "id": "policy-backend-provider-export-receipts",
        "description": "Policy backend provider export receipts bind verified OPA/Cedar worker operations to provider-native scheduler, queue, lease, backend, decision-log, and audit export records.",
        "reference": "src/trustai/policy_backend_provider.py",
        "commands": [
            "python -m trustai policy-backend-provider-export artifacts/policy-backend-provider-export-source.json artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --mode provider-export --environment aitrade-prod --provider aws-scheduler-sqs-dynamodb-s3-cloudtrail-opa --endpoint-url https://provider.example/aitrade/policy-backend/exports --credential-ref env:POLICY_BACKEND_PROVIDER_EXPORT_TOKEN --request-hash sha256:policy-backend-provider-export-request --response-status 200 --response-hash sha256:policy-backend-provider-export-response --actor-ref oidc:trustai.example/policy-backend-provider-exporter --exported-at 2026-07-04T04:06:00Z",
            "python -m trustai policy-backend-provider-export-verify artifacts/policy-backend-provider-export.json artifacts/policy-backend-provider-export-source.json artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json",
            "python -m unittest tests.test_policy_backend_provider",
        ],
    },
    {
        "id": "policy-backend-provider-export-review-bundles",
        "description": "Policy backend provider export review bundles package provider export receipts, provider exports, worker receipts, service attestations, enforcement receipts, policies, proof packs, decisions, and exports for offline third-party replay.",
        "reference": "src/trustai/policy_backend_provider_bundle.py",
        "commands": [
            "python -m trustai policy-backend-provider-export-bundle artifacts/policy-backend-provider-export.json artifacts/policy-backend-provider-export-source.json artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --environment aitrade-prod --reviewer-ref oidc:auditor.example/policy-backend-provider-reviewer --generated-at 2026-07-04T05:10:00Z --out artifacts/policy-backend-provider-export-bundle.json --markdown artifacts/policy-backend-provider-export-bundle.md",
            "python -m trustai policy-backend-provider-export-bundle-verify artifacts/policy-backend-provider-export-bundle.json",
            "python -m unittest tests.test_policy_backend_provider_bundle",
        ],
    },
    {
        "id": "policy-backend-production-authority-dossiers",
        "description": "Policy backend production authority dossiers bind provider export bundles and optional service review bundles to external OPA/Cedar backend authority evidence, freshness windows, missing requirement coverage, and chain-backed production-claim limits.",
        "reference": "src/trustai/policy_backend_authority.py",
        "commands": [
            "python -m trustai policy-backend-authority artifacts/policy-backend-provider-export-bundle.json --service-bundle artifacts/policy-backend-service-bundle.json --environment aitrade-prod --dossier-ref dossier:policy-backend-authority/lg-trace-001 --authority-ref authority:policy-backend/aitrade-prod --producer-ref oidc:trustai.example/policy-backend-authority-worker --authority-evidence \"opa-cedar-backend-fleet,hosted-service,service:policy-backend-fleet/aitrade-prod,sha256:policy-backend-fleet-authority,Hosted OPA/Cedar backend fleet deployment export;issuer=TrustAI Cloud;subject=aitrade-prod policy backend fleet;source_uri=https://ops.example/trustai/policy-backend/aitrade-prod;issued_at=2026-07-04T00:00:00Z;expires_at=2026-07-11T00:00:00Z\" --generated-at 2026-07-04T05:20:00Z --out artifacts/policy-backend-authority.json",
            "python -m trustai policy-backend-authority-verify artifacts/policy-backend-authority.json --provider-bundle artifacts/policy-backend-provider-export-bundle.json --service-bundle artifacts/policy-backend-service-bundle.json",
            "python -m unittest tests.test_policy_backend_authority",
        ],
    },
    {
        "id": "policy-backend-service-review-bundles",
        "description": "Policy backend service review bundles package service attestations, enforcement receipts, policy packs, runtime actions, proof packs, policy decisions, exports, and optional policy-engine receipts for offline third-party replay.",
        "reference": "src/trustai/policy_backend_service_bundle.py",
        "commands": [
            "python -m trustai policy-backend-service-bundle artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --environment aitrade-prod --reviewer-ref oidc:auditor.example/policy-backend-reviewer --generated-at 2026-07-04T05:00:00Z --out artifacts/policy-backend-service-bundle.json --markdown artifacts/policy-backend-service-bundle.md",
            "python -m trustai policy-backend-service-bundle-verify artifacts/policy-backend-service-bundle.json",
            "python -m unittest tests.test_policy_backend_service_bundle",
        ],
    },
    {
        "id": "signed-approval-callbacks",
        "description": "Signed provider callback artifacts and the local Slack callback endpoint verify provider signatures, replay windows, stored pending approval requests, and generated request bindings before becoming chain-backed approvals.",
        "reference": "src/trustai/approval_callback.py",
        "commands": [
            "python -m trustai approval-callback-build artifacts/slack-approval-request.json model_risk --approver model-risk@example.com --approved-at 2026-07-03T13:00:00Z",
            "python -m trustai approval-callback-verify artifacts/slack-approval-request.json artifacts/approval-callback.json",
            "python -m trustai approval-callback-append examples/aitrade/verification-contract.yaml artifacts/slack-approval-request.json artifacts/approval-callback.json --auto-register",
            "python -m unittest tests.test_approval_callback",
        ],
    },
    {
        "id": "underwriting-quote-receipts",
        "description": "Underwriting quote receipts bind consented insurer telemetry to quoted premiums, discounts, coverage terms, and underwriter references.",
        "reference": "src/trustai/underwriting_quote.py",
        "commands": [
            "python -m trustai underwriting-quote artifacts/insurer-risk-telemetry.json --underwriter ExampleUnderwriter --term-start 2026-07-08T00:00:00Z --term-end 2027-07-08T00:00:00Z --expires-at 2026-08-08T00:00:00Z",
            "python -m trustai underwriting-quote-verify artifacts/underwriting-quote.json --telemetry artifacts/insurer-risk-telemetry.json",
        ],
    },
    {
        "id": "actuarial-data-products",
        "description": "Signed actuarial product manifests bind anonymized consented corpus exports to longitudinal aggregates and privacy controls.",
        "reference": "src/trustai/actuarial.py",
        "commands": [
            "python -m trustai actuarial-verify artifacts/actuarial-corpus.json",
            "python -m trustai actuarial-product artifacts/actuarial-corpus.json --product-name TrustAIReliabilityBenchmark --publisher trustai-local --issued-at 2026-07-06T00:00:00Z",
            "python -m trustai actuarial-product-verify artifacts/actuarial-product.json --corpus artifacts/actuarial-corpus.json",
        ],
    },
    {
        "id": "insurer-partner-service-attestations",
        "description": "Insurer partner service attestations bind consented insurer telemetry and underwriting quote receipts to hosted insurer portal/API service hardening, partner authentication, policy-system workflow, request signing, data minimization, delivery logs, audit/access roots, metrics, alerting, actuarial product bindings, and redacted credentials.",
        "reference": "src/trustai/insurer_partner_service.py",
        "commands": [
            "python -m trustai insurer-partner-service-attestation artifacts/insurer-risk-telemetry.json artifacts/underwriting-quote.json --actuarial-product artifacts/actuarial-product.json --actuarial-corpus artifacts/actuarial-corpus.json --environment aitrade-prod --service-kind underwriting-integration --service-ref insurer-partner:trustai/underwriting-prod --service-version 0.1.0 --endpoint-url https://insurer.example/trustai/aitrade --partner-api-endpoint https://underwriter.example/api/v1/quotes --service-image ghcr.io/trustai/insurer-partner:0.1.0 --service-image-digest sha256:trustai-insurer-partner-image --service-binary-hash sha256:trustai-insurer-partner-binary --frontend-bundle-ref bundle:insurer-partner/underwriter-ui --frontend-bundle-hash sha256:trustai-insurer-partner-frontend --api-ref api:insurer-partner/v0 --queue-ref queue:insurer-partner/delivery --policy-system-ref policy-system:underwriter/bindings --partner-contract-ref partner-contract:underwriter/trustai-2026 --auth-provider-ref oidc:insurer-partner/idp --partner-auth-policy-ref policy:insurer-partner/partner-auth-v0.1 --rbac-policy-ref policy:insurer-partner/rbac-v0.1 --consent-policy-ref policy:insurer-partner/consent-v0.1 --data-minimization-policy-ref policy:insurer-partner/data-minimization-v0.1 --pii-redaction-policy-ref policy:insurer-partner/pii-redaction-v0.1 --tenant-isolation-ref tenant-isolation:insurer-partner/aitrade --rate-limit-policy-ref rate-limit:insurer-partner/underwriter --request-signing-ref sigv4:insurer-partner/underwriter --network-policy-ref netpol:insurer-partner/deny-by-default --egress-policy-ref egress:insurer-partner/underwriter-only --encryption-key-ref kms:insurer-partner/customer-data --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --audit-log-ref audit-log:insurer-partner/service --audit-log-root sha256:insurer-partner-audit-root --access-log-ref access-log:insurer-partner/sessions --access-log-root sha256:insurer-partner-access-root --delivery-log-ref delivery-log:insurer-partner/underwriter --delivery-log-root sha256:insurer-partner-delivery-root --metrics-ref metrics:insurer-partner/service --alert-policy-ref alert:insurer-partner/service --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/insurer-partner-operator --credential-ref env:INSURER_PARTNER_TOKEN --partner-credential-ref env:UNDERWRITER_API_TOKEN --evidence-ref evidence:insurer-partner/service --attested-at 2026-07-08T06:00:00Z --now 2026-07-09T00:00:00Z --out artifacts/insurer-partner-service-attestation.json",
            "python -m trustai insurer-partner-service-verify artifacts/insurer-partner-service-attestation.json artifacts/insurer-risk-telemetry.json artifacts/underwriting-quote.json --actuarial-product artifacts/actuarial-product.json --actuarial-corpus artifacts/actuarial-corpus.json --now 2026-07-09T00:00:00Z",
            "python -m unittest tests.test_insurer_partner_service",
        ],
    },
    {
        "id": "insurer-partner-worker-receipts",
        "description": "Insurer partner worker receipts bind consented telemetry and underwriting quote delivery runs to insurer partner service attestations, scheduler leases, checkpoints, partner API delivery logs, policy-system workflow hashes, audit/access roots, and redacted TrustAI and partner worker credentials.",
        "reference": "src/trustai/insurer_partner_worker.py",
        "commands": [
            "python -m trustai insurer-partner-worker artifacts/insurer-partner-service-attestation.json artifacts/insurer-risk-telemetry.json artifacts/underwriting-quote.json --actuarial-product artifacts/actuarial-product.json --actuarial-corpus artifacts/actuarial-corpus.json --mode partner-api-worker --environment aitrade-prod --worker-ref worker:insurer-partner/underwriting --run-ref worker-run:insurer-partner/underwriting/2026-07-08T06:05:00Z --operation-kind underwriting_quote_delivery --actor-ref oidc:trustai.example/insurer-partner-worker --schedule-ref schedule:insurer-partner/underwriting/5m --cadence-seconds 300 --lease-ref lease:insurer-partner/underwriting/2026-07-08T06:05:00Z --checkpoint-ref checkpoint:insurer-partner/underwriting --checkpoint-hash sha256:insurer-partner-worker-checkpoint --previous-cursor-ref underwriter:quotes/cursor/before --next-cursor-ref underwriter:quotes/cursor/after --queue-ref queue:insurer-partner/delivery --queue-message-ref queue-message:insurer-partner/underwriting/aitrade --destination-ref underwriter:example/api/v1/quotes --delivery-log-ref delivery-log:insurer-partner/underwriter --delivery-log-root sha256:insurer-partner-worker-delivery-root --partner-event-log-ref underwriter:event-log/quote-bindings --partner-event-log-root sha256:insurer-partner-worker-partner-event-root --policy-system-ref policy-system:underwriter/bindings --policy-workflow-ref policy-workflow:underwriter/bindings/aitrade --policy-workflow-hash sha256:insurer-partner-worker-policy-workflow --policy-binding-ref policy-binding:underwriter/aitrade --policy-binding-hash sha256:insurer-partner-worker-policy-binding --workflow-status bound --request-hash sha256:insurer-partner-worker-request --response-status 201 --response-hash sha256:insurer-partner-worker-response --metrics-ref metrics:insurer-partner/workers --audit-log-ref audit-log:insurer-partner/workers --audit-log-root sha256:insurer-partner-worker-audit-root --access-log-ref access-log:insurer-partner/workers --access-log-root sha256:insurer-partner-worker-access-root --credential-ref env:INSURER_PARTNER_WORKER_TOKEN --partner-credential-ref env:UNDERWRITER_WORKER_TOKEN --retention-until 2033-07-08T00:00:00Z --evidence-ref evidence:insurer-partner/worker --started-at 2026-07-08T06:05:00Z --completed-at 2026-07-08T06:06:00Z --next-run-at 2026-07-08T06:10:00Z --now 2026-07-09T00:00:00Z --out artifacts/insurer-partner-worker.json",
            "python -m trustai insurer-partner-worker-verify artifacts/insurer-partner-worker.json artifacts/insurer-partner-service-attestation.json artifacts/insurer-risk-telemetry.json artifacts/underwriting-quote.json --actuarial-product artifacts/actuarial-product.json --actuarial-corpus artifacts/actuarial-corpus.json --now 2026-07-09T00:00:00Z",
            "python -m unittest tests.test_insurer_partner_worker",
        ],
    },
    {
        "id": "insurer-partner-production-authority-dossiers",
        "description": "Insurer partner production authority dossiers bind insurer partner service attestations, worker receipts, optional worker review bundles, embedded source-artifact roots, frontend replay status, actuarial replay status, and external insurer API/authentication/policy-system/delivery-log authority evidence to freshness windows, missing coverage, and production-claim limits.",
        "reference": "src/trustai/insurer_partner_authority.py",
        "commands": [
            "python -m trustai insurer-partner-authority artifacts/insurer-partner-service-attestation.json --worker artifacts/insurer-partner-worker.json --worker-bundle artifacts/insurer-partner-worker-bundle.json --environment aitrade-prod --dossier-ref dossier:insurer-partner-authority/underwriter-prod --authority-ref authority:insurer-partner/underwriter-prod --producer-ref oidc:trustai.example/insurer-partner-authority-worker --authority-evidence \"credentialed-partner-api-calls,insurer,insurer:underwriter/api/aitrade,sha256:insurer-partner-live-api-authority,Live underwriter API authority export;issuer=Example AI Liability Underwriter;subject=aitrade-prod insurer partner API;source_uri=https://underwriter.example/audit/trustai/aitrade;issued_at=2026-07-08T06:20:00Z;expires_at=2026-07-15T06:20:00Z\" --generated-at 2026-07-08T06:25:00Z --out artifacts/insurer-partner-authority.json",
            "python -m trustai insurer-partner-authority-verify artifacts/insurer-partner-authority.json artifacts/insurer-partner-service-attestation.json --worker artifacts/insurer-partner-worker.json --worker-bundle artifacts/insurer-partner-worker-bundle.json",
            "python -m unittest tests.test_insurer_partner_authority",
        ],
    },
    {
        "id": "supervised-access-receipts",
        "description": "Supervised access receipts bind reviewer identity, purpose, expiry, proof packs, disclosures, static views, and insurer telemetry for third-party review sessions.",
        "reference": "src/trustai/supervised_access.py",
        "commands": [
            "python -m trustai supervised-access --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html --audience-type regulator --subject-ref oidc:regulator.example/supervisor-123 --organization ExampleSupervisor --role regulator_reviewer --expires-at 2026-12-31T00:00:00Z",
            "python -m trustai supervised-access-verify artifacts/supervised-access-receipt.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html",
        ],
    },
    {
        "id": "review-portal-service-attestations",
        "description": "Review portal service attestations bind supervised access receipts to hosted auditor/regulator portal service hardening, auth/session/RBAC, selective disclosure, tenant isolation, frontend integrity, audit roots, access logs, metrics, alerting, and redacted credentials.",
        "reference": "src/trustai/review_portal_service.py",
        "commands": [
            "python -m trustai review-portal-service-attestation artifacts/supervised-access-receipt.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html --regulator-acceptance artifacts/regulator-acceptance.json --eu-ai-act-document artifacts/eu-ai-act-technical-documentation.json --environment aitrade-prod --portal-kind regulator --service-ref review-portal:trustai/regulator-prod --service-version 0.1.0 --endpoint-url https://portal.example/reviews/aitrade --service-image ghcr.io/trustai/review-portal:0.1.0 --service-image-digest sha256:trustai-review-portal-image --service-binary-hash sha256:trustai-review-portal-binary --frontend-bundle-ref bundle:review-portal/regulator-ui --frontend-bundle-hash sha256:trustai-review-portal-frontend --api-ref api:review-portal/v0 --session-store-ref redis:review-portal/sessions --auth-provider-ref oidc:review-portal/idp --auth-policy-ref policy:review-portal/auth-v0.1 --rbac-policy-ref policy:review-portal/rbac-v0.1 --session-policy-ref policy:review-portal/session-v0.1 --selective-disclosure-policy-ref policy:review-portal/selective-disclosure-v0.1 --tenant-isolation-ref tenant-isolation:review-portal/aitrade --rate-limit-policy-ref rate-limit:review-portal/regulator --network-policy-ref netpol:review-portal/deny-by-default --egress-policy-ref egress:review-portal/kms-tsa-only --content-security-policy-ref csp:review-portal/regulator-v0.1 --encryption-key-ref kms:review-portal/session-store --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --audit-log-ref audit-log:review-portal/service --audit-log-root sha256:review-portal-service-audit-root --access-log-ref access-log:review-portal/sessions --access-log-root sha256:review-portal-access-log-root --metrics-ref metrics:review-portal/service --alert-policy-ref alert:review-portal/service --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/review-portal-operator --credential-ref env:REVIEW_PORTAL_TOKEN --evidence-ref evidence:review-portal/service --attested-at 2026-07-08T06:00:00Z --out artifacts/review-portal-service-attestation.json",
            "python -m trustai review-portal-service-verify artifacts/review-portal-service-attestation.json artifacts/supervised-access-receipt.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html --regulator-acceptance artifacts/regulator-acceptance.json --eu-ai-act-document artifacts/eu-ai-act-technical-documentation.json",
            "python -m unittest tests.test_review_portal_service",
        ],
    },
    {
        "id": "review-portal-production-authority-dossiers",
        "description": "Review portal production authority dossiers bind review portal service attestations to external hosted UI/session/account/access-log authority evidence, freshness windows, missing coverage, and production-claim limits.",
        "reference": "src/trustai/review_portal_authority.py",
        "commands": [
            "python -m trustai review-portal-authority artifacts/review-portal-service-attestation.json --environment aitrade-prod --dossier-ref dossier:review-portal-authority/regulator-prod --authority-ref authority:review-portal/regulator-prod --producer-ref oidc:trustai.example/review-portal-authority-worker --authority-evidence \"hosted-portal-worker-fleet,hosted-service,service:review-portal/regulator-prod,sha256:review-portal-hosted-service-authority,Hosted regulator review portal service export;issuer=TrustAI Cloud;subject=aitrade-prod regulator review portal;source_uri=https://ops.example/trustai/review-portal/regulator-prod;issued_at=2026-07-08T06:10:00Z;expires_at=2026-07-15T06:10:00Z\" --generated-at 2026-07-08T06:15:00Z --out artifacts/review-portal-authority.json",
            "python -m trustai review-portal-authority-verify artifacts/review-portal-authority.json artifacts/review-portal-service-attestation.json",
            "python -m unittest tests.test_review_portal_authority",
        ],
    },
    {
        "id": "regulator-acceptance-receipts",
        "description": "Regulator acceptance receipts bind named supervisory acknowledgement to proof packs, selective disclosures, EU AI Act documentation, and supervised access receipts.",
        "reference": "src/trustai/regulator_acceptance.py",
        "commands": [
            "python -m trustai regulator-acceptance --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --document artifacts/eu-ai-act-technical-documentation.json --supervised-access artifacts/supervised-access-receipt.json --supervised-view artifacts/regulator-view.html --regulator ExampleSupervisor --authority-ref EU-NCA:EXAMPLE --reviewer-ref oidc:regulator.example/supervisor-123",
            "python -m trustai regulator-acceptance-verify artifacts/regulator-acceptance.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --document artifacts/eu-ai-act-technical-documentation.json --supervised-access artifacts/supervised-access-receipt.json --supervised-view artifacts/regulator-view.html",
        ],
    },
    {
        "id": "selective-disclosure",
        "description": "Regulator packages reveal selected entries with inclusion proofs only.",
        "reference": "src/trustai/regulator.py",
        "commands": [
            "python -m trustai regulator-export artifacts/aitrade-proof-pack.json --state .trustai/demo/evidence-chain.json",
            "python -m trustai regulator-verify artifacts/regulator-disclosure.json",
        ],
    },
    {
        "id": "local-reexecution-runner",
        "description": "Local runner plans execute repeated eval commands with fixed seeds and produce verifiable runner evidence.",
        "reference": "src/trustai/reexecution_runner.py",
        "commands": [
            "python -m trustai reexecution-runner-run examples/aitrade/reexecution-runner-plan.json --contract examples/aitrade/verification-contract.yaml",
            "python -m trustai reexecution-runner-verify artifacts/reexecution-runner-evidence.json",
        ],
    },
    {
        "id": "reexecution-isolation-attestations",
        "description": "Re-execution isolation attestations bind runner evidence to container/kernel isolation controls, deterministic seeds, temperature, and runner audit-log evidence.",
        "reference": "src/trustai/reexecution_isolation.py",
        "commands": [
            "python -m trustai reexecution-isolation-attestation artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --isolation-ref isolation:aitrade/reexecution/2026-07-04 --runner-ref runner:trustai-reexecution/local --runner-provider TrustAILocalRunner --orchestrator kubernetes --container-runtime containerd --kernel linux-6.8 --namespace-mode private --cgroup-ref cgroup:trustai/reexecution/aitrade --seccomp-profile-hash sha256:trustai-reexecution-seccomp --network-mode disabled --filesystem-policy-ref fs-policy:trustai/reexecution/read-only-root --read-only-rootfs --egress-policy-ref egress-policy:deny-all --seed-policy recorded-or-fixed-seed --temperature 0 --entropy-source-ref entropy:fixed-seed-runner --audit-log-ref audit-log:reexecution/isolation --audit-log-root sha256:reexecution-isolation-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/reexecution-runner --credential-ref env:REEXECUTION_RUNNER_TOKEN --attested-at 2026-07-04T04:06:00Z",
            "python -m trustai reexecution-isolation-verify artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json",
            "python -m unittest tests.test_reexecution_isolation",
        ],
    },
    {
        "id": "reexecution-runner-service-attestations",
        "description": "Re-execution runner service attestations bind verified isolation evidence to hosted runner fleet, scheduler, queue, lease, checkpoint, custody, KMS/secrets, observability, and audit controls.",
        "reference": "src/trustai/reexecution_runner_service.py",
        "commands": [
            "python -m trustai reexecution-runner-service-attestation artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --service-ref runner-service:trustai/reexecution-prod --service-version 0.1.0 --runner-image ghcr.io/trustai/reexecution-runner:0.1.0 --runner-binary-hash sha256:trustai-reexecution-runner-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --scheduler-ref scheduler:reexecution/runner --schedule-cadence-seconds 60 --queue-ref queue:reexecution/runs --dead-letter-queue-ref queue:reexecution/runs-dlq --lease-store-ref postgres:reexecution/leases --checkpoint-store-ref postgres:reexecution/checkpoints --max-concurrency 12 --retry-policy-ref policy:reexecution/retry-v0.1 --isolation-profile-ref isolation-profile:reexecution/container-v0.1 --admission-policy-ref admission:reexecution/signed-plans-only --tenant-isolation-ref tenant-isolation:reexecution/aitrade --network-policy-ref netpol:reexecution/deny-by-default --egress-policy-ref egress-policy:deny-all --artifact-store-ref s3:trustai-reexecution-artifacts --result-store-ref s3:trustai-reexecution-results --idempotency-store-ref postgres:reexecution/idempotency --secret-store-ref vault:reexecution/secrets --kms-key-ref kms:example/reexecution-runner --metrics-ref metrics:reexecution/runner-service --alert-policy-ref alert:reexecution/runner-service --audit-log-ref audit-log:reexecution/runner-service --audit-log-root sha256:reexecution-runner-service-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/reexecution-runner-operator --credential-ref env:REEXECUTION_RUNNER_SERVICE_TOKEN --attested-at 2026-07-04T04:07:00Z",
            "python -m trustai reexecution-runner-service-verify artifacts/reexecution-runner-service-attestation.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json",
            "python -m unittest tests.test_reexecution_runner_service",
        ],
    },
    {
        "id": "reexecution-runner-worker-receipts",
        "description": "Re-execution runner worker receipts bind a verified runner service attestation to scheduled worker operations, leases, checkpoints, queue messages, job/result custody, runtime audit roots, request/response hashes, metrics, audit roots, and redacted worker credentials.",
        "reference": "src/trustai/reexecution_runner_worker.py",
        "commands": [
            "python -m trustai reexecution-runner-worker --service-attestation artifacts/reexecution-runner-service-attestation.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --mode hosted-worker --worker-ref worker:reexecution/runner --run-ref worker-run:reexecution/aitrade/2026-07-04T04:08:00Z --operation-kind reexecution_run --actor-ref oidc:trustai.example/reexecution-runner-worker --schedule-ref schedule:reexecution/runner/1m --cadence-seconds 60 --lease-ref lease:reexecution/runner/2026-07-04T04:08:00Z --checkpoint-ref checkpoint:reexecution/runner/aitrade --checkpoint-hash sha256:reexecution-runner-worker-checkpoint --queue-ref queue:reexecution/runs --job-ref job:reexecution/aitrade/2026-07-04T04:08:00Z --job-hash sha256:reexecution-runner-worker-job --artifact-manifest-ref s3:trustai-reexecution-artifacts/aitrade/2026-07-04/manifest.json --artifact-manifest-hash sha256:reexecution-runner-worker-artifacts --result-bundle-ref s3:trustai-reexecution-results/aitrade/2026-07-04/results.json --result-bundle-hash sha256:reexecution-runner-worker-results --isolation-audit-ref audit-log:reexecution/isolation/runner-worker --isolation-audit-root sha256:reexecution-runner-worker-isolation-audit-root --metrics-ref metrics:reexecution/runner-worker --audit-log-ref audit-log:reexecution/runner-worker --audit-log-root sha256:reexecution-runner-worker-audit-root --credential-ref env:REEXECUTION_RUNNER_WORKER_TOKEN --retention-until 2033-07-04T00:00:00Z --started-at 2026-07-04T04:08:00Z --completed-at 2026-07-04T04:09:00Z",
            "python -m trustai reexecution-runner-worker-verify artifacts/reexecution-runner-worker.json --service-attestation artifacts/reexecution-runner-service-attestation.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json",
            "python -m unittest tests.test_reexecution_runner_worker",
        ],
    },
    {
        "id": "reexecution-runner-production-authority-dossiers",
        "description": "Re-execution runner production authority dossiers bind verified runner service and worker evidence to production fleet, scheduler, queue, lease, container, kernel, audit, custody, KMS, freshness, and observability authority evidence.",
        "reference": "src/trustai/reexecution_runner_authority.py",
        "commands": [
            "python -m trustai reexecution-runner-authority artifacts/reexecution-runner-service-attestation.json --worker-receipt artifacts/reexecution-runner-worker.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --environment aitrade-prod --dossier-ref dossier:reexecution-runner-authority/aitrade-prod --authority-ref authority:reexecution-runner/prod --producer-ref oidc:trustai.example/reexecution-runner-authority-worker --authority-evidence 'production-runner-fleet,hosted-service,runner-fleet:trustai/reexecution-prod,sha256:reexecution-runner-prod-fleet,Hosted re-execution runner fleet export for production replay jobs;issuer=TrustAI Hosted Ops;subject=aitrade-prod re-execution runner fleet;source_uri=https://runner.example/audit/fleet/aitrade-prod;issued_at=2026-07-04T04:09:00Z;expires_at=2026-07-11T04:09:00Z' --generated-at 2026-07-04T04:10:00Z",
            "python -m trustai reexecution-runner-authority-verify artifacts/reexecution-runner-authority.json artifacts/reexecution-runner-service-attestation.json --worker-receipt artifacts/reexecution-runner-worker.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json",
            "python -m unittest tests.test_reexecution_runner_authority",
        ],
    },
    {
        "id": "distributional-reexecution",
        "description": "Repeated eval runs produce policy-bound distributional evidence with model/runtime pins, sandbox evidence, worst-case threshold checks, and confidence intervals.",
        "reference": "src/trustai/reexecution.py",
        "commands": [
            "python -m trustai reexecution-policy-verify examples/aitrade/reexecution-policy.json examples/aitrade/verification-contract.yaml artifacts/runner-runs/eval-results-runner-1.json artifacts/runner-runs/eval-results-runner-2.json artifacts/runner-runs/eval-results-runner-3.json --temperature 0",
            "python -m trustai reexecution-report examples/aitrade/verification-contract.yaml artifacts/runner-runs/eval-results-runner-1.json artifacts/runner-runs/eval-results-runner-2.json artifacts/runner-runs/eval-results-runner-3.json --policy examples/aitrade/reexecution-policy.json --temperature 0",
            "python -m trustai reexecution-verify artifacts/reexecution-report.json",
        ],
    },
    {
        "id": "cross-org-vendor-verification",
        "description": "Buyer manifests bind vendor proof packs to procurement-clause requirements.",
        "reference": "src/trustai/trust_network.py",
        "commands": [
            "python -m trustai trust-network-export artifacts/aitrade-proof-pack.json --vendor aitrade --buyer finserv-buyer",
            "python -m trustai trust-network-verify artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json",
        ],
    },
    {
        "id": "auditor-program-governance-receipts",
        "description": "Auditor program governance receipts bind certification-kit evidence, standards package evidence, board/operator references, and policy controls for accreditation program oversight.",
        "reference": "src/trustai/auditor_program_governance.py",
        "commands": [
            "python -m trustai auditor-program-governance artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --program-ref TRUSTAI-AUDITOR-0.1 --issued-at 2026-07-14T00:00:00Z",
            "python -m trustai auditor-program-governance-verify artifacts/auditor-program-governance.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json",
        ],
    },
    {
        "id": "auditor-program-sponsorship-receipts",
        "description": "Auditor program sponsorship receipts bind accepted standards-body ballot evidence to auditor program governance for externally sponsored accreditation oversight.",
        "reference": "src/trustai/auditor_program_sponsorship.py",
        "commands": [
            "python -m trustai auditor-program-sponsorship artifacts/auditor-program-governance.json artifacts/standards-body-ballot.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --sponsor-ref wg:trustai-proof-packs --issued-at 2026-07-25T04:00:00Z",
            "python -m trustai auditor-program-sponsorship-verify artifacts/auditor-program-sponsorship.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "auditor-accreditation-receipts",
        "description": "Auditor accreditation receipts bind credential issuance, score, scope, renewal, and revocation governance to a verified auditor certification kit.",
        "reference": "src/trustai/auditor_accreditation.py",
        "commands": [
            "python -m trustai auditor-accreditation artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --auditor-name ExampleAudit --auditor-ref oidc:auditor.example/reviewer-123 --auditor-organization ExampleAudit --score-percent 92 --issued-at 2026-07-15T00:00:00Z --expires-at 2027-07-15T00:00:00Z",
            "python -m trustai auditor-accreditation-verify artifacts/auditor-accreditation.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json",
        ],
    },
    {
        "id": "auditor-accreditation-countersignature-receipts",
        "description": "Auditor accreditation countersignature receipts bind active sponsor evidence to specific auditor accreditation operations and credential status.",
        "reference": "src/trustai/auditor_accreditation_countersignature.py",
        "commands": [
            "python -m trustai auditor-accreditation-countersignature artifacts/auditor-accreditation.json artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --operation issue --sponsor-actor-ref oidc:standards.example/accreditation-sponsor-1 --signed-at 2026-07-26T00:00:00Z",
            "python -m trustai auditor-accreditation-countersignature-verify artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "auditor-accreditation-signing-ceremony-receipts",
        "description": "Auditor accreditation signing ceremony receipts bind sponsor-countersigned accreditation operations to sponsor key, quorum, witness, authority, and signing policy evidence.",
        "reference": "src/trustai/auditor_accreditation_signing_ceremony.py",
        "commands": [
            "python -m trustai auditor-accreditation-signing-ceremony artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --mode sponsor-controlled --key-ref kms:lf-trustai/auditor-accreditation-signing --sponsor-operator-ref oidc:standards.example/accreditation-sponsor-1 --approver-ref oidc:standards.example/chair-1 --authority-ref minutes:trustai-wg/2026-07-26 --policy-ref policy:auditor-accreditation-signing-v0.1 --ceremony-at 2026-07-26T00:30:00Z",
            "python -m trustai auditor-accreditation-signing-ceremony-verify artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "auditor-accreditation-signing-audit-receipts",
        "description": "Auditor accreditation signing audit receipts bind sponsor signing ceremonies to public key publication, immutable audit log roots, retention, witnesses, and provider response evidence.",
        "reference": "src/trustai/auditor_accreditation_signing_audit.py",
        "commands": [
            "python -m trustai auditor-accreditation-signing-audit artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --mode provider-anchored --public-key-ref https://standards.example/keys/auditor-accreditation-signing.pub --public-key-fingerprint sha256:lf-trustai-auditor-accreditation-signing --actor-ref oidc:standards.example/accreditation-sponsor-1 --audit-log-ref audit-log:lf-trustai/signing/2026-07-26 --audit-log-root 8c93d55abc6b8425ace8b488ab53ff0ef0ac79d6231cdfe6d5b7dc0c5268eaa2 --audit-log-size 4 --response-status 201 --published-at 2026-07-26T00:45:00Z",
            "python -m trustai auditor-accreditation-signing-audit-verify artifacts/auditor-accreditation-signing-audit.json --signing-ceremony artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "auditor-accreditation-kms-enforcement-receipts",
        "description": "Auditor accreditation KMS enforcement receipts bind provider-anchored signing audits to sponsor-owned HSM/KMS attestation, key policy, dual-control quorum, public key publication, and immutable audit-log evidence.",
        "reference": "src/trustai/auditor_accreditation_kms_enforcement.py",
        "commands": [
            "python -m trustai auditor-accreditation-kms-enforcement artifacts/auditor-accreditation-signing-audit.json --signing-ceremony artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json --mode provider-enforced --attestation-ref hsm-attestation:lf-trustai/auditor-accreditation-signing/2026-07-26 --attestation-hash sha256:lf-trustai-hsm-attestation-20260726 --key-policy-ref key-policy:lf-trustai/auditor-accreditation-signing/v0.1 --key-policy-hash sha256:lf-trustai-auditor-accreditation-key-policy --actor-ref oidc:standards.example/accreditation-sponsor-1 --allowed-actor-ref oidc:standards.example/accreditation-sponsor-1 --quorum-required 2 --quorum-approver-ref oidc:standards.example/chair-1 --quorum-approver-ref oidc:standards.example/secretary-1 --response-status 200 --enforced-at 2026-07-26T01:00:00Z",
            "python -m trustai auditor-accreditation-kms-enforcement-verify artifacts/auditor-accreditation-kms-enforcement.json --signing-audit artifacts/auditor-accreditation-signing-audit.json --signing-ceremony artifacts/auditor-accreditation-signing-ceremony.json --countersignature artifacts/auditor-accreditation-countersignature.json --accreditation artifacts/auditor-accreditation.json --sponsorship artifacts/auditor-program-sponsorship.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --governance artifacts/auditor-program-governance.json --ballot artifacts/standards-body-ballot.json --submission artifacts/standards-body-submission.json --status-receipt artifacts/standards-body-status.json --verifier-release artifacts/verifier-release.json --conformance-report artifacts/verifier-conformance.json",
        ],
    },
    {
        "id": "auditor-credential-registry-receipts",
        "description": "Auditor credential registry receipts bind public credential publication, status, expiry, and revocation lookup metadata to a verified auditor accreditation receipt.",
        "reference": "src/trustai/auditor_credential_registry.py",
        "commands": [
            "python -m trustai auditor-credential-registry artifacts/auditor-accreditation.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --registry-name TrustAIAuditorRegistry --registry-endpoint https://auditors.example --publication-ref AUD-REG-2026-001 --published-at 2026-07-16T00:00:00Z",
            "python -m trustai auditor-credential-registry-verify artifacts/auditor-credential-registry.json --accreditation artifacts/auditor-accreditation.json --kit artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json",
        ],
    },
    {
        "id": "vendor-identity-receipts",
        "description": "Vendor identity receipts bind legal/vendor identity references to verified proof packs and accepted trust-network submissions.",
        "reference": "src/trustai/vendor_identity.py",
        "commands": [
            "python -m trustai vendor-identity --pack artifacts/aitrade-proof-pack.json --manifest artifacts/trust-network-manifest.json --vendor aitrade --legal-name 'Aitrade Labs Inc.' --subject-ref did:web:aitrade.example --issued-at 2026-07-10T00:00:00Z",
            "python -m trustai vendor-identity-verify artifacts/vendor-identity-receipt.json --pack artifacts/aitrade-proof-pack.json --manifest artifacts/trust-network-manifest.json",
        ],
    },
    {
        "id": "identity-provider-attestation-receipts",
        "description": "Identity provider attestations bind recorded Okta/Entra/ServiceNow exports to vendor identity receipts and proof-pack-backed agents.",
        "reference": "src/trustai/identity_provider_attestation.py",
        "commands": [
            "python -m trustai identity-attestation examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --provider okta --identity-id okta-agent-aitrade-risk",
            "python -m trustai identity-attestation-verify artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json",
        ],
    },
    {
        "id": "identity-provider-session-receipts",
        "description": "Identity provider session receipts bind Okta/Entra/ServiceNow session, token, and account events to identity-provider attestations, provider request/response hashes, session-log roots, audit roots, and redacted credentials.",
        "reference": "src/trustai/identity_provider_session.py",
        "commands": [
            "python -m trustai identity-session artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --mode provider-event-stream --environment aitrade-prod --provider-tenant-ref okta:example-org --session-ref okta-session:aitrade-risk/2026-07-12T02:00:00Z --event-ref okta-event:evt_20260712_aitrade_token_introspection --event-kind token_introspection --provider-event-id evt_20260712_aitrade_token_introspection --actor-ref oidc:trustai.example/identity-session-worker --endpoint-url https://okta.example/oauth2/v1/introspect --credential-ref env:OKTA_INTROSPECTION_TOKEN --request-hash sha256:identity-provider-session-request --response-status 200 --response-hash sha256:identity-provider-session-response --session-log-ref okta:system-log/query/aitrade-session --session-log-root sha256:identity-provider-session-log-root --audit-log-ref audit-log:identity-provider/session-worker --audit-log-root sha256:identity-provider-session-audit-root --session-started-at 2026-07-12T02:00:00Z --observed-at 2026-07-12T02:00:05Z --recorded-at 2026-07-12T02:00:06Z --retention-until 2033-07-12T00:00:00Z",
            "python -m trustai identity-session-verify artifacts/identity-provider-session.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json",
            "python -m unittest tests.test_identity_provider_session",
        ],
    },
    {
        "id": "identity-provider-lifecycle-operation-receipts",
        "description": "Identity provider lifecycle operation receipts bind Okta/Entra/ServiceNow account, app, token, session, and SCIM operations to identity-provider attestations, optional session receipts, provider request/response hashes, system-log roots, audit roots, and redacted credentials.",
        "reference": "src/trustai/identity_provider_lifecycle_operation.py",
        "commands": [
            "python -m trustai identity-lifecycle-operation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --mode hosted-lifecycle-worker --environment aitrade-prod --provider-tenant-ref okta:example-org --operation-ref okta-lifecycle:aitrade-risk/app-assignment/2026-07-12 --operation-kind app_assignment --provider-operation-id evt_20260712_aitrade_app_assignment --actor-ref oidc:trustai.example/identity-lifecycle-worker --target-state assigned --endpoint-url https://okta.example/api/v1/apps/app123/users --credential-ref env:OKTA_LIFECYCLE_TOKEN --request-hash sha256:identity-provider-lifecycle-request --response-status 200 --response-hash sha256:identity-provider-lifecycle-response --system-log-ref okta:system-log/query/aitrade-lifecycle --system-log-root sha256:identity-provider-lifecycle-system-log-root --audit-log-ref audit-log:identity-provider/lifecycle-worker --audit-log-root sha256:identity-provider-lifecycle-audit-root --requested-at 2026-07-12T02:01:00Z --completed-at 2026-07-12T02:01:02Z --recorded-at 2026-07-12T02:01:03Z --retention-until 2033-07-12T00:00:00Z --resulting-identity-record-hash sha256:identity-provider-lifecycle-resulting-record",
            "python -m trustai identity-lifecycle-operation-verify artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json",
            "python -m unittest tests.test_identity_provider_lifecycle_operation",
        ],
    },
    {
        "id": "identity-provider-lifecycle-worker-receipts",
        "description": "Identity provider lifecycle worker receipts bind source lifecycle operations to scheduler leases, checkpoints, queue propagation, account/session/token propagation roots, provider request/response hashes, audit roots, and redacted worker credentials.",
        "reference": "src/trustai/identity_provider_lifecycle_worker.py",
        "commands": [
            "python -m trustai identity-lifecycle-worker artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --mode hosted-worker --environment aitrade-prod --worker-ref worker:identity-provider/lifecycle/okta --run-ref worker-run:identity-provider/lifecycle/2026-07-12T02:01:05Z --operation-kind app_assignment_propagation --actor-ref oidc:trustai.example/identity-lifecycle-worker --schedule-ref schedule:identity-provider/lifecycle/1m --cadence-seconds 60 --lease-ref lease:identity-provider/lifecycle/2026-07-12T02:01:05Z --checkpoint-ref checkpoint:identity-provider/lifecycle/okta --checkpoint-hash sha256:identity-provider-lifecycle-worker-checkpoint --previous-cursor-ref okta:system-log/cursor/before-assignment --next-cursor-ref okta:system-log/cursor/after-assignment --queue-ref queue:identity-provider/lifecycle --queue-message-ref queue-message:identity-provider/lifecycle/app-assignment --destination-ref identity-provider:okta/example-org --propagation-log-ref propagation-log:identity-provider/lifecycle/okta --propagation-log-root sha256:identity-provider-lifecycle-worker-propagation-root --account-state-log-ref account-state-log:identity-provider/okta --account-state-log-root sha256:identity-provider-lifecycle-worker-account-root --session-revocation-log-ref session-revocation-log:identity-provider/okta --session-revocation-log-root sha256:identity-provider-lifecycle-worker-session-root --token-revocation-log-ref token-revocation-log:identity-provider/okta --token-revocation-log-root sha256:identity-provider-lifecycle-worker-token-root --request-hash sha256:identity-provider-lifecycle-worker-request --response-status 200 --response-hash sha256:identity-provider-lifecycle-worker-response --metrics-ref metrics:identity-provider/lifecycle-worker --audit-log-ref audit-log:identity-provider/lifecycle-worker --audit-log-root sha256:identity-provider-lifecycle-worker-audit-root --credential-ref env:OKTA_LIFECYCLE_WORKER_TOKEN --started-at 2026-07-12T02:01:05Z --completed-at 2026-07-12T02:01:07Z --next-run-at 2026-07-12T02:02:05Z --retention-until 2033-07-12T00:00:00Z --evidence-ref evidence:identity-provider/lifecycle-worker",
            "python -m trustai identity-lifecycle-worker-verify artifacts/identity-provider-lifecycle-worker.json artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json",
            "python -m unittest tests.test_identity_provider_lifecycle_worker",
        ],
    },
    {
        "id": "identity-provider-production-authority-dossiers",
        "description": "Identity provider production authority dossiers bind lifecycle worker receipts to live identity-provider event streams, token/session propagation, lifecycle APIs, provider audit exports, credential custody, scheduler/queue evidence, freshness windows, and production-claim limits.",
        "reference": "src/trustai/identity_provider_authority.py",
        "commands": [
            "python -m trustai identity-provider-authority artifacts/identity-provider-lifecycle-worker.json artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --mode provider-dossier --environment aitrade-prod --dossier-ref dossier:identity-provider-authority/okta-prod --authority-ref authority:identity-provider/okta-prod --producer-ref oidc:trustai.example/identity-provider-authority-worker --authority-evidence 'live-identity-provider-event-streams,identity-provider,okta:system-log/query/aitrade-agent-events,sha256:identity-provider-live-event-streams,Okta system-log export for governed agent lifecycle events;issuer=Okta;subject=aitrade-prod governed agent identity events;source_uri=https://okta.example/system-log/aitrade-agent-events;issued_at=2026-07-12T02:10:00Z;expires_at=2026-07-19T02:10:00Z' --generated-at 2026-07-12T02:12:00Z --now 2026-07-15T00:00:00Z",
            "python -m trustai identity-provider-authority-verify artifacts/identity-provider-authority.json artifacts/identity-provider-lifecycle-worker.json artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --now 2026-07-15T00:00:00Z",
            "python -m unittest tests.test_identity_provider_authority",
        ],
    },
    {
        "id": "procurement-clause-receipts",
        "description": "Procurement clause receipts bind buyer contract references to verified trust-network manifests and accepted vendor proof packs.",
        "reference": "src/trustai/procurement_clause.py",
        "commands": [
            "python -m trustai procurement-clause artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --contract-ref MSA-2026-AITRADE-001 --approver-ref procurement@example.com --effective-at 2026-07-11T00:00:00Z",
            "python -m trustai procurement-clause-verify artifacts/procurement-clause-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json",
        ],
    },
    {
        "id": "procurement-integration-receipts",
        "description": "Procurement integration receipts bind procurement clause and vendor identity receipts to procurement-system payloads and optional provider responses.",
        "reference": "src/trustai/procurement_integration.py",
        "commands": [
            "python -m trustai procurement-integration artifacts/procurement-clause-receipt.json artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --procurement-system servicenow --endpoint-base https://procurement.example --credential-ref env:PROCUREMENT_TOKEN",
            "python -m trustai procurement-integration-verify artifacts/procurement-integration-receipt.json --procurement-receipt artifacts/procurement-clause-receipt.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json",
        ],
    },
    {
        "id": "trust-network-registry-receipts",
        "description": "Trust-network registry receipts bind accepted vendor identity, identity-provider, procurement, and manifest evidence into a publishable registry payload.",
        "reference": "src/trustai/trust_network_registry.py",
        "commands": [
            "python -m trustai trust-network-registry artifacts/trust-network-manifest.json artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-name TrustAILocalRegistry --registry-endpoint https://registry.example --namespace finserv-buyer",
            "python -m trustai trust-network-registry-verify artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json",
        ],
    },
    {
        "id": "trust-network-registry-status-receipts",
        "description": "Trust-network registry status receipts bind suspension, revocation, dispute, and reactivation evidence to a signed registry publication receipt.",
        "reference": "src/trustai/trust_network_registry_status.py",
        "commands": [
            "python -m trustai trust-network-registry-status artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --status suspended --reason BuyerDispute --actor-ref oidc:buyer.example/procurement-reviewer",
            "python -m trustai trust-network-registry-status-verify artifacts/trust-network-registry-status.json --registry artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json",
        ],
    },
    {
        "id": "marketplace-template-verification",
        "description": "Marketplace catalogs verify reusable contract templates and policy packs by schema and content hash.",
        "reference": "src/trustai/marketplace.py",
        "commands": [
            "python -m trustai marketplace-export --contract-template examples/aitrade/verification-contract.yaml --policy-pack examples/aitrade/policy-pack.json --vertical trading --regulation SR-11-7",
            "python -m trustai marketplace-verify artifacts/marketplace-catalog.json",
        ],
    },
    {
        "id": "marketplace-distribution-receipts",
        "description": "Marketplace distribution receipts bind verified catalog revisions to selected assets, subscribers, channels, terms, and chain evidence.",
        "reference": "src/trustai/marketplace.py",
        "commands": [
            "python -m trustai marketplace-distribution artifacts/marketplace-catalog.json --channel marketplace-api --target https://marketplace.example/catalogs/trustai --subscriber finserv-buyer --distributed-at 2026-07-12T00:00:00Z",
            "python -m trustai marketplace-distribution-verify artifacts/marketplace-distribution.json --catalog artifacts/marketplace-catalog.json",
        ],
    },
    {
        "id": "marketplace-author-governance-receipts",
        "description": "Marketplace author governance receipts bind catalog and distribution evidence to author identity, onboarding, review, licensing, IP, entitlement, billing, payout, revocation, support, and audit metadata.",
        "reference": "src/trustai/marketplace_author.py",
        "commands": [
            "python -m trustai marketplace-author-governance artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --mode platform-governed --author-name ExampleAuditTemplates --author-ref did:web:templates.example --author-kind third-party --contact-ref mailto:templates@example.com --identity-provider okta --identity-subject okta:user/example-audit-templates --identity-assurance phishing-resistant-mfa --agreement-ref agreement:marketplace-author/EXAMPLE-2026-001 --terms-ref terms:trustai-marketplace-author-v0.1 --license-ref license:apache-2.0 --ip-attestation-ref ip-attestation:EXAMPLE-2026-001 --review-ticket-ref review:marketplace/EXAMPLE-2026-001 --review-policy-ref policy:marketplace-review-v0.1 --reviewer-ref oidc:trustai.example/marketplace-reviewer-1 --billing-mode entitlement-recorded --billing-account-ref billing:acct/example-audit --entitlement-policy-ref policy:marketplace-entitlements-v0.1 --payout-account-ref vault:payout/example-audit --revenue-share-bps 2500 --revocation-policy-ref policy:marketplace-revocation-v0.1 --support-contact-ref mailto:support@example.com --security-contact-ref mailto:security@example.com --audit-log-ref audit-log:marketplace/authors --audit-log-root sha256:marketplace-author-audit-root --retention-until 2033-07-12T00:00:00Z",
            "python -m trustai marketplace-author-verify artifacts/marketplace-author-governance.json --catalog artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --root .",
            "python -m unittest tests.test_marketplace_author",
        ],
    },
    {
        "id": "marketplace-settlement-receipts",
        "description": "Marketplace settlement receipts bind author governance to entitlement checks, invoices, revenue-share math, payout execution, tax custody, and settlement audit evidence.",
        "reference": "src/trustai/marketplace_settlement.py",
        "commands": [
            "python -m trustai marketplace-settlement artifacts/marketplace-author-governance.json --catalog artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --mode provider-settled --subscriber-ref oidc:buyer.example/procurement --entitlement-check-ref entitlement-check:marketplace/EXAMPLE-2026-001 --entitlement-checked-at 2026-07-12T02:00:00Z --period-start 2026-07-12T00:00:00Z --period-end 2026-08-12T00:00:00Z --invoice-ref invoice:marketplace/EXAMPLE-2026-001 --gross-amount-usd 1000 --tax-withholding-bps 1000 --invoice-status paid --payout-ref payout:marketplace/EXAMPLE-2026-001 --payout-provider-ref stripe:transfer/tr_EXAMPLE --payout-status settled --payout-executed-at 2026-07-12T02:30:00Z --tax-profile-ref tax-profile:example-audit/us --tax-document-custody-ref vault:tax-documents/example-audit/w9-2026 --tax-document-hash sha256:marketplace-tax-document-hash --audit-log-ref audit-log:marketplace/settlements --audit-log-root sha256:marketplace-settlement-audit-root --retention-until 2033-08-12T00:00:00Z",
            "python -m trustai marketplace-settlement-verify artifacts/marketplace-settlement.json --author-governance artifacts/marketplace-author-governance.json --catalog artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --root .",
            "python -m unittest tests.test_marketplace_settlement",
        ],
    },
    {
        "id": "trust-network-service-attestations",
        "description": "Trust-network service attestations bind registry, registry status, marketplace catalog, and marketplace distribution receipts to hosted identity federation, procurement sync, entitlement, revocation, publication-log, audit, metrics, actor, and redacted credential evidence.",
        "reference": "src/trustai/trust_network_service.py",
        "commands": [
            "python -m trustai trust-network-service-attestation artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --root . --environment aitrade-prod --service-kind registry-marketplace --service-ref trust-network:trustai/hosted-prod --service-version 0.1.0 --registry-endpoint https://registry.example --marketplace-endpoint https://marketplace.example/catalogs/trustai --service-image ghcr.io/trustai/trust-network-service:0.1.0 --service-image-digest sha256:trustai-trust-network-service-image --service-binary-hash sha256:trustai-trust-network-service-binary --frontend-bundle-ref bundle:trust-network/portal --frontend-bundle-hash sha256:trustai-trust-network-frontend --api-ref api:trust-network/v0 --registry-store-ref postgres:trustai/trust-network-registry --search-index-ref opensearch:trustai/trust-network-marketplace --entitlement-store-ref postgres:trustai/marketplace-entitlements --subscription-queue-ref queue:trust-network/subscriptions --auth-provider-ref oidc:trust-network/idp --vendor-auth-policy-ref policy:trust-network/vendor-auth-v0.1 --buyer-auth-policy-ref policy:trust-network/buyer-auth-v0.1 --subscriber-auth-policy-ref policy:trust-network/subscriber-auth-v0.1 --rbac-policy-ref policy:trust-network/rbac-v0.1 --identity-federation-policy-ref policy:trust-network/identity-federation-v0.1 --procurement-sync-policy-ref policy:trust-network/procurement-sync-v0.1 --entitlement-policy-ref policy:trust-network/entitlements-v0.1 --catalog-review-policy-ref policy:trust-network/catalog-review-v0.1 --revocation-policy-ref policy:trust-network/revocation-v0.1 --cache-invalidation-policy-ref policy:trust-network/cache-invalidation-v0.1 --tenant-isolation-ref tenant-isolation:trust-network/finserv-buyer --rate-limit-policy-ref rate-limit:trust-network/tenant --request-signing-ref sigv4:trust-network/service --network-policy-ref netpol:trust-network/deny-by-default --egress-policy-ref egress:trust-network/idp-procurement-marketplace-only --encryption-key-ref kms:trust-network/customer-data --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --registry-audit-log-ref audit-log:trust-network/registry --registry-audit-log-root sha256:trust-network-registry-audit-root --marketplace-audit-log-ref audit-log:trust-network/marketplace --marketplace-audit-log-root sha256:trust-network-marketplace-audit-root --access-log-ref access-log:trust-network/sessions --access-log-root sha256:trust-network-access-root --publication-log-ref publication-log:trust-network/registry-marketplace --publication-log-root sha256:trust-network-publication-root --metrics-ref metrics:trust-network/service --alert-policy-ref alert:trust-network/service --retention-until 2033-07-14T00:00:00Z --actor-ref oidc:trustai.example/trust-network-operator --credential-ref env:TRUST_NETWORK_SERVICE_TOKEN --marketplace-credential-ref env:MARKETPLACE_API_TOKEN --evidence-ref evidence:trust-network/service --attested-at 2026-07-14T06:00:00Z",
            "python -m trustai trust-network-service-verify artifacts/trust-network-service-attestation.json artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --root .",
            "python -m unittest tests.test_trust_network_service",
        ],
    },
    {
        "id": "trust-network-worker-receipts",
        "description": "Trust-network worker receipts bind hosted service attestations and source registry/marketplace receipts to scheduler leases, checkpoints, queue propagation, provider-owned ledger hashes, audit roots, redacted credentials, and chain evidence.",
        "reference": "src/trustai/trust_network_worker.py",
        "commands": [
            "python -m trustai trust-network-worker --service-attestation artifacts/trust-network-service-attestation.json artifacts/trust-network-registry.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --operation-kind marketplace_settlement_reconcile --mode hosted-worker --worker-ref worker:trust-network/marketplace-settlement-reconciler --run-ref worker-run:trust-network/marketplace-settlement/2026-07-12T03:05:00Z --actor-ref oidc:trustai.example/trust-network-worker --schedule-ref schedule:trust-network/marketplace-settlement/5m --cadence-seconds 300 --lease-ref lease:trust-network/marketplace-settlement/2026-07-12T03:05:00Z --checkpoint-ref checkpoint:trust-network/marketplace-settlement --queue-ref queue:trust-network/subscriptions --destination-ref marketplace:https://marketplace.example/catalogs/trustai --publication-log-ref publication-log:trust-network/registry-marketplace --publication-log-root sha256:trust-network-worker-publication-root --metrics-ref metrics:trust-network/workers --audit-log-ref audit-log:trust-network/workers --audit-log-root sha256:trust-network-worker-audit-root --credential-ref env:TRUST_NETWORK_WORKER_TOKEN --started-at 2026-07-12T03:05:00Z",
            "python -m trustai trust-network-worker-verify artifacts/trust-network-worker.json --service-attestation artifacts/trust-network-service-attestation.json artifacts/trust-network-registry.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root .",
            "python -m unittest tests.test_trust_network_worker",
        ],
    },
    {
        "id": "trust-network-production-authority-dossiers",
        "description": "Trust-network production authority dossiers bind hosted trust-network service attestations, worker receipts, optional worker review bundles, embedded source-artifact roots, marketplace asset/frontend replay status, and external hosted registry, marketplace, identity-provider, lifecycle-worker, settlement, revocation, callback, and observability authority evidence to freshness windows, missing coverage, and production-claim limits.",
        "reference": "src/trustai/trust_network_authority.py",
        "commands": [
            "python -m trustai trust-network-authority artifacts/trust-network-registry.json --service-attestation artifacts/trust-network-service-attestation.json --worker artifacts/trust-network-worker.json --worker-bundle artifacts/trust-network-worker-bundle.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root . --source-now 2026-07-15T00:00:00Z --mode network-dossier --environment aitrade-prod --dossier-ref dossier:trust-network-authority/registry-marketplace-prod --authority-ref authority:trust-network/registry-marketplace-prod --producer-ref oidc:trustai.example/trust-network-authority-worker --authority-evidence 'hosted-registry-marketplace-worker-fleet,hosted-service,trust-network:hosted/workers,sha256:trust-network-hosted-worker-fleet,Hosted trust-network worker fleet export;issuer=TrustAI Hosted Ops;subject=aitrade-prod trust-network;source_uri=https://trust-network.example/audit/workers;issued_at=2026-07-14T06:10:00Z;expires_at=2026-07-21T06:10:00Z' --generated-at 2026-07-14T06:15:00Z --now 2026-07-15T00:00:00Z",
            "python -m trustai trust-network-authority-verify artifacts/trust-network-authority.json artifacts/trust-network-registry.json --service-attestation artifacts/trust-network-service-attestation.json --worker artifacts/trust-network-worker.json --worker-bundle artifacts/trust-network-worker-bundle.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root . --source-now 2026-07-15T00:00:00Z --now 2026-07-15T00:00:00Z",
            "python -m unittest tests.test_trust_network_authority",
        ],
    },
)


@dataclass
class StandardsVerification:
    ok: bool
    errors: list[str]
    warnings: list[str]


def build_standards_submission(
    root: str | Path = ".",
    *,
    target_body: str = "ETSI/ISO/IEEE or Linux Foundation project",
    status: str = "draft",
) -> dict[str, Any]:
    root_path = Path(root)
    pyproject = _project_metadata(root_path)
    specs = [_spec_record(root_path, path) for path in sorted((root_path / "docs" / "specs").glob("*.md"))]
    body = {
        "schema": STANDARDS_SUBMISSION_SCHEMA,
        "generated_at": utc_now(),
        "status": status,
        "target_body": target_body,
        "project": pyproject,
        "scope": {
            "objective": "Portable, third-party-verifiable proof packs for autonomous agent behavior.",
            "license": pyproject.get("license", "Apache-2.0"),
            "neutrality": "Framework-neutral evidence format; verifier is independent of producer account access.",
        },
        "required_specs": list(REQUIRED_SPEC_PATHS),
        "specs": specs,
        "conformance_targets": list(CONFORMANCE_TARGETS),
        "submission_checklist": [
            "Publish proof-pack and verification-contract specifications.",
            "Publish WORM receipt and legal-hold verification format.",
            "Publish large-log tamper stress report format for roadmap-scale evidence-chain mutation tests.",
            "Publish offline verifier behavior and conformance commands.",
            "Publish trust authority receipt format for keyring/KMS/TSA verification evidence.",
            "Publish trust authority KMS enforcement receipt format for customer-controlled HSM attestation, key policy, timestamp policy, quorum, and audit-root evidence.",
            "Publish anchor provider receipt format for external/public chain-root anchoring evidence.",
            "Publish deployment manifest format for BYOC/self-hosted scaffold verification.",
            "Publish design-partner pilot dossier format for Phase 1 partner count, signed value, external scrutiny, and readiness/external-evidence separation.",
            "Publish TrustAI own compliance dossier format for SOC 2 Type II and ISO/IEC 42001 readiness/external-certification separation.",
            "Publish State of Agent Reliability report format for anonymized aggregate GTM publication evidence with source-product binding and publication-evidence separation.",
            "Publish roadmap phase scoreboard format for P1-P4 business milestone evidence references with readiness/external-evidence separation.",
            "Publish product scope decision format for proof-impact discipline checks and anti-focus decline controls.",
            "Publish collector topology manifest format for ingestion/MCP/control-plane verification.",
            "Publish MCP gateway production authority dossier format for proxy fleet, session auth, replay, immutable audit, scheduler, policy, network, KMS, and observability authority evidence."
            "Publish signed verifier release manifest and conformance-bound release verification commands.",
            "Publish Go verifier build attestation format for source-plan, recorded-build, and binary-attested verifier releases.",
            "Publish Go verifier CI release workflow controls for static binary builds, checksums, SBOM, provenance, and hosted build attestations.",
            "Publish standards-body submission receipt format for standards-track docket evidence.",
            "Publish standards-body status receipt format for docket acknowledgement and review-state evidence.",
            "Publish standards-body ballot receipt format for quorum, vote tally, and decision evidence.",
            "Publish signed approval callback format, pending request storage, and verification commands.",
            "Publish provider delivery receipt format for credentialed dispatch workers.",
            "Publish policy engine decision receipt format for OPA/Cedar backend evidence.",
            "Publish selective-disclosure package and EU AI Act technical-documentation mappings.",
            "Publish supervised access receipt format for credentialed third-party review sessions.",
            "Publish regulator acceptance receipt format for named supervisory acknowledgements.",
            "Publish underwriting quote receipt format for proof-pack-backed insurer premium credits.",
            "Publish insurer partner service attestation format for partner-authenticated portal/API and policy-system evidence.",
            "Publish signed actuarial product manifest format for consented longitudinal reliability data products.",
            "Publish auditor certification, auditor program governance, auditor program sponsorship, auditor accreditation, credential registry, and cross-org vendor trust-network manifest formats.",
            "Publish vendor identity receipt format for proof-pack and trust-network binding evidence.",
            "Publish identity provider attestation receipt format for recorded Okta/Entra/ServiceNow authentication evidence.",
            "Publish procurement clause receipt format for buyer contract adoption evidence.",
            "Publish procurement integration receipt format for buyer procurement-platform payload evidence.",
            "Publish trust-network registry receipt format for hosted cross-org publication evidence.",
            "Publish trust-network registry status receipt format for suspension, revocation, and dispute evidence.",
            "Publish marketplace catalog format for certified contract templates and policy packs.",
            "Publish marketplace distribution receipt format for chain-backed catalog publication evidence.",
            "Publish marketplace author governance receipt format for third-party author onboarding, review, entitlement, billing, payout, and revocation evidence.",
            "Publish marketplace settlement receipt format for entitlement checks, invoice, revenue-share, payout, and tax-custody evidence.",
            "Publish identity-provider production authority dossier format for live identity event streams, token/session propagation, lifecycle APIs, provider audit exports, credential custody, scheduler/queue evidence, and freshness-gated production claims.",
            "Publish trust-network service attestation format for hosted registry and marketplace evidence.",
            "Publish trust-network production authority dossier format for hosted registry, marketplace, identity-provider, settlement, revocation, callback, and observability authority evidence.",
            "Publish verifier public release authority dossier format for provider workflow, release API, artifact, transparency-log, audit-log, and credential-custody authority evidence.",
            "Publish verifier conformance report format and tamper-vector requirements.",
            "Publish distributional re-execution report, local runner evidence, and risk-class policy formats for nondeterministic agents.",
            "Keep producer and verifier roles separable.",
            "Document non-production local cryptography substitutions.",
        ],
    }
    return {**body, "package_id": content_hash(body)}


def verify_standards_submission(package: dict[str, Any], root: str | Path = ".") -> StandardsVerification:
    errors: list[str] = []
    warnings: list[str] = []
    root_path = Path(root)

    if package.get("schema") != STANDARDS_SUBMISSION_SCHEMA:
        errors.append(f"unsupported standards submission schema: {package.get('schema')}")

    body = without_keys(package, "package_id")
    expected_package_id = content_hash(body)
    if package.get("package_id") != expected_package_id:
        errors.append("package_id does not match canonical package body")

    specs = package.get("specs", [])
    if not isinstance(specs, list) or not specs:
        errors.append("standards submission must include spec records")
        specs = []
    by_path = {spec.get("path"): spec for spec in specs if isinstance(spec, dict)}
    for required_path in package.get("required_specs", REQUIRED_SPEC_PATHS):
        if required_path not in by_path:
            errors.append(f"required spec missing from package: {required_path}")

    for spec in specs:
        if not isinstance(spec, dict):
            errors.append("spec record must be an object")
            continue
        path_value = spec.get("path")
        if not isinstance(path_value, str) or not path_value:
            errors.append("spec path missing")
            continue
        spec_path = root_path / path_value
        if not spec_path.exists():
            errors.append(f"spec file missing from worktree: {path_value}")
            continue
        current = _spec_record(root_path, spec_path)
        for field in ("title", "content_hash", "line_count"):
            if spec.get(field) != current.get(field):
                errors.append(f"spec {path_value} {field} mismatch")

    targets = package.get("conformance_targets", [])
    if not isinstance(targets, list) or not targets:
        errors.append("conformance targets missing")
    else:
        for target in targets:
            reference = target.get("reference") if isinstance(target, dict) else None
            if reference and not (root_path / reference).exists():
                warnings.append(f"conformance target reference missing: {reference}")

    return StandardsVerification(ok=not errors, errors=errors, warnings=warnings)


def write_standards_submission(path: str | Path, package: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(package, indent=2, sort_keys=True), encoding="utf-8")


def write_standards_markdown(path: str | Path, package: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_standards_markdown(package), encoding="utf-8")


def render_standards_markdown(package: dict[str, Any]) -> str:
    specs = "\n".join(
        f"- `{spec['path']}`: {spec['title']} (`{spec['content_hash']}`)"
        for spec in package.get("specs", [])
    )
    targets = "\n".join(
        f"- `{target['id']}`: {target['description']}"
        for target in package.get("conformance_targets", [])
    )
    checklist = "\n".join(f"- {item}" for item in package.get("submission_checklist", []))
    project = package.get("project", {})
    return f"""# TrustAI Standards Submission Package

Package ID: `{package.get('package_id', '')}`

Status: {package.get('status', '')}

Target body: {package.get('target_body', '')}

Project: {project.get('name', 'trustai')} {project.get('version', '')}

## Scope

{package.get('scope', {}).get('objective', '')}

## Specification Manifest

{specs}

## Conformance Targets

{targets}

## Submission Checklist

{checklist}
"""


def load_standards_submission(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _project_metadata(root: Path) -> dict[str, Any]:
    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.exists():
        return {"name": "trustai", "version": "unknown", "license": "Apache-2.0"}
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    license_value = project.get("license", {})
    if isinstance(license_value, dict):
        license_value = license_value.get("text")
    return {
        "name": project.get("name", "trustai"),
        "version": project.get("version", "unknown"),
        "description": project.get("description"),
        "license": license_value or "Apache-2.0",
        "requires_python": project.get("requires-python"),
    }


def _spec_record(root: Path, path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    title = _title(text)
    relative = path.relative_to(root).as_posix()
    return {
        "path": relative,
        "title": title,
        "spec_id": relative.removeprefix("docs/specs/").removesuffix(".md"),
        "content_hash": content_hash({"path": relative, "text": text}),
        "line_count": len(text.splitlines()),
    }


def _title(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return "Untitled Specification"
