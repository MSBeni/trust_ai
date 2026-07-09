# Phase 0-2 Reference Architecture

This implementation covers a local, executable slice of the roadmap. It is a
single-process reference stack that can later be split into Go services, a Python
eval orchestrator, and a TypeScript portal.

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

## Implemented Now

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
- tamper detection tests.

## Deferred Production Work

- KMS/HSM signatures and RFC 3161 timestamp authority integration;
- network collector process, MCP proxy service, and ClickHouse/Postgres stores;
- SaaS/BYOC operator and object-lock storage controls;
- credentialed live posting to GitHub, GitLab, and Slack APIs;
- full React auditor/regulator portals;
- authenticated insurer API service;
- standards submission and certification program.
