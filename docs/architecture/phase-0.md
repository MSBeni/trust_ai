# TrustAI Reference Architecture and Production Boundary

This implementation covers the executable local/reference slice of the uploaded
roadmap. It is a self-contained repository for proof generation, offline
verification, retained authority replay, and roadmap evidence review. The code is
organized so the current single-process Python reference can be split into Go
services, a Python eval/holdout orchestrator, and a TypeScript portal without
changing the signed artifact shapes.

## Components

| Component | Module | Purpose |
|---|---|---|
| Verification Contract DSL | `trustai.contracts` | Loads, validates, and hashes pre-registered contracts. |
| Evidence Chain | `trustai.chain`, `trustai.merkle` | Append-only signed log with Merkle inclusion proofs. |
| Agent Registry | `trustai.registry` | Records discovered agents and delegation edges. |
| OTel GenAI Ingest | `trustai.ingest` | Appends trace/span events as signed chain evidence. |
| MCP Gateway Reference | `trustai.mcp_gateway` | Captures tool-call transcripts as evidence. |
| Runtime Attestation | `trustai.runtime` | Checks high-risk actions against blast-radius policy. |
| Shadow Replay and Soak | `trustai.shadow` | Enforces temporal holdout and soak/drift checks. |
| Gate Engine | `trustai.gate` | Evaluates metric thresholds, holdout rules, and approvals. |
| Proof Pack Compiler | `trustai.proofpack` | Builds JSON proof packs and human-readable PDFs. |
| Offline Verifier | `trustai.verifier` | Verifies signatures, hashes, ordering, inclusion proofs, and holdout timing. |
| Consumption Exports | `trustai.cicd`, `trustai.compliance`, `trustai.insurer`, `trustai.auditor` | Produces CI/CD, Slack approval, compliance, insurer, and auditor artifacts. |
| CLI | `trustai.cli` | Runs all local workflows. |

## Trust Model

The developer MVP uses local HMAC signatures so the workflow can run without
network access, KMS, or third-party libraries. The signed payload shape is
explicit so it can be replaced by asymmetric KMS/HSM signatures:

- every evidence entry signs its canonical core;
- every proof pack signs its canonical body;
- every payload is content-addressed with SHA-256;
- every selected chain entry carries a Merkle inclusion proof.

The verifier treats local tampering as a hard failure. A modified contract,
metric result, chain entry, proof, decision, or signature invalidates the pack.

## Data Flow

```text
agent inventory + delegation
  -> agent.inventory.discovered / agent.delegation.evidenced entries
contract file
  -> verification_contract.registered chain entry
OTel GenAI events + MCP transcript
  -> otel_genai.event.ingested / mcp.tool_call.evidenced entries
runtime action
  -> runtime.attested chain entry
shadow replay + soak windows
  -> shadow_replay.completed / soak_report.completed entries
eval results
  -> eval.completed chain entry
  -> promotion_gate.decided chain entry
  -> proof pack JSON + PDF
  -> CI, compliance, insurer, auditor exports
  -> offline verifier
```

## Implemented Locally

- contract pre-registration;
- agent inventory and delegation evidence;
- OTel-style GenAI event ingestion;
- MCP transcript capture;
- temporal holdout and shadow replay;
- metric threshold gates;
- approval checks;
- runtime blast-radius attestation;
- soak reports and drift alarm handling;
- signed Merkle evidence chain;
- JSON proof packs with related evidence inclusion;
- PDF proof summary;
- offline verifier CLI;
- CI reports, provider API payloads, Slack approval request payloads, compliance, insurer, and auditor exports;
- aitrade reference example;
- BYOC Docker/Helm scaffold;
- tamper detection tests;
- KMS/TSA provider attestations, trust-authority KMS/HSM enforcement receipts, and anchor provider receipts with retained source replay;
- BYOC/self-hosted authority dossiers, Helm validation, Kubernetes release-state receipts, deployment image integrity receipts, Object Lock/WORM evidence, and air-gap install bundles;
- provider webhook/delivery/approval authority receipts, promotion status review bundles, and retained payload byte replay;
- policy backend service/provider/worker receipts and review bundles;
- self-serve onboarding, framework adapter, MCP gateway, review portal, insurer, regulator, standards, trust-network, marketplace, and auditor ecosystem reference receipts;
- retained external-evidence corpus with 72/72 authority units covered and zero remaining collection tasks.

## Current Production Authority Boundary

The current repo proves local implementation integrity and reference authority
logic. `trustai roadmap-audit` reports `local-reference-complete-with-external-
authority-deferred`: 26 roadmap requirements have local evidence, 6 are fully
implemented locally, and 20 are reference-attested because production claims need
fresh authority-owned exports.

Those deferred production inputs are not missing code paths; they are external
facts that cannot be honestly manufactured in a local repository:

- completed provider-owned GitHub/GitLab/Slack workflow, webhook, callback,
  delivery, release, artifact, audit-log, and credential-custody exports;
- customer, regulator, insurer, standards-body, identity-provider, KMS/HSM,
  cloud Object Lock, hosted-service, and marketplace authority exports;
- live hosted control-plane, collector, MCP gateway, review portal, insurer API,
  regulator portal, trust-network, and marketplace service operations;
- production tenant data-plane evidence such as scheduler/queue/lease exports,
  immutable audit logs, mTLS/network/KMS enforcement, backup/restore evidence,
  and WORM retention/legal-hold records;
- business milestone evidence for paying design partners, ARR, insurer pricing,
  regulator acceptance, procurement clauses, standards-track acceptance, and
  actuarial data product revenue.

The retained example corpus under `examples/aitrade/external-evidence/` models
that authority collection process with fresh, hash-bound source snapshots and
intake receipts. It is intentionally verifier-backed reference evidence; it is not a claim that those external production events have happened.

## Verification Gates

The repository keeps the boundary above executable through:

- `.github/workflows/python-ci.yml`, which rebuilds and verifies proof packs,
  roadmap audits, retained external evidence, roadmap evidence bundles, and
  clean-checkout smoke tests;
- `.github/workflows/go-verifier.yml`, which tests and cross-builds the
  dependency-free Go verifier source;
- `scripts/regenerate_retained_external_evidence.py --verify-only`, which
  checks retained authority coverage, source snapshots, intake receipts,
  readiness, production-replacement lifecycle and closure state, collection-run evidence, and bundle source counts;
- `tests/test_repository_ci.py`, `tests/test_roadmap_audit.py`, and
  `tests/test_external_evidence.py`, which guard the CI workflow, roadmap
  evidence hashes, retained authority counts, and strict production-readiness
  semantics.
