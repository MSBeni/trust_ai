# Insurer Partner Production Authority Dossier v0.1

Status: draft reference format.

This specification defines the `trustai.insurer-partner-production-authority-dossier/0.1` artifact. The dossier binds signed insurer partner service attestations and worker receipts to external authority evidence for live insurer, underwriter, and policy-system operation.

The format separates local/reference insurer integration evidence from a production authority claim. A dossier may be partial. A production claim is valid only when every required production authority category is covered by fresh evidence.

## Artifact

A dossier is a JSON object with:

- `schema`: `trustai.insurer-partner-production-authority-dossier/0.1`.
- `dossier_id`: canonical hash of the dossier body excluding `dossier_id` and `signatures`.
- `mode`: one of `local-dossier`, `partner-dossier`, or `production-dossier`.
- `environment`: deployment environment label.
- `generated_at`: RFC3339 timestamp.
- `dossier_ref`, `authority_ref`, `producer_ref`: stable references for the dossier, production authority scope, and producer.
- `service_attestation_binding`: canonical binding to the insurer partner service attestation.
- `worker_receipt_bindings`: canonical bindings to insurer partner worker receipts.
- `required_production_authority`: the v0.1 requirement checklist.
- `authority_evidence`: supplied external authority evidence items.
- `summary`: derived coverage and freshness summary.
- `controls`: derived control statuses.
- `limitations`: human-readable non-claim statements.
- `signatures`: one or more signatures over `{dossier_id, insurer_partner_authority}`.

## Bindings

The service binding records service identity, endpoint, partner API endpoint, image and binary hashes, frontend bundle reference/hash, queue and policy-system references, underwriter and quote references, consent and telemetry metadata, actuarial product binding, partner-authentication controls, request-signing controls, delivery/audit/access log roots, retention, actor, and redacted TrustAI and partner credential references.

The worker binding records worker operation ID/hash, service attestation ID/hash, scheduler cadence, leases, checkpoints, queue messages, destination, partner delivery/event log roots, policy workflow and binding hashes, request/response hashes, audit/access roots, retention, and redacted worker credential references.

Verification recomputes every binding from supplied service and worker artifacts. If telemetry, underwriting quote, actuarial product/corpus, or frontend bundle sources are supplied, the verifier also replays the underlying service and worker checks.

## Production Authority Requirements

The v0.1 checklist contains:

- `credentialed-partner-api-calls`.
- `partner-owned-authentication-events`.
- `externally-operated-insurer-worker-fleet`.
- `live-underwriter-api-responses`.
- `policy-system-workflow-execution`.
- `immutable-partner-delivery-logs`.
- `production-scheduler-lease-storage`.
- `partner-credential-vault-kms`.
- `consent-pii-data-minimization-enforcement`.
- `actuarial-risk-data-publication`.
- `insurer-observability-alerting`.

Each evidence item contains `requirement_id`, `authority_kind`, `evidence_ref`, `evidence_hash`, `description`, optional `issuer`, `subject`, `source_uri`, `issued_at`, `expires_at`, and derived `evidence_id`. Evidence hashes must use `sha256:` references. Authority kinds must be accepted by the requirement.

## Verification

A conforming verifier must:

- Verify schema, canonical `dossier_id`, and at least one signature.
- Recompute service and worker bindings from supplied source artifacts.
- Verify service and worker source artifacts, including optional telemetry, underwriting quote, actuarial product/corpus, and frontend bundle replay when supplied.
- Verify every authority evidence id and hash reference.
- Recompute the summary from evidence.
- Warn for missing production authority requirements.
- Fail when `--require-complete` is set and any requirement is missing.
- Fail when `--require-fresh` is set and any evidence item lacks an unexpired `issued_at`/`expires_at` window.
- Fail when `mode` is `production-dossier` and any requirement is missing.
- Reject secret-like fields unless they are redacted objects or reference/hash/root fields.

## Chain Entry

Appending a valid dossier writes entry type `insurer.partner_authority_recorded`. The entry payload includes dossier identity, mode, environment, service and worker bindings, coverage summary, control summary, and compact authority evidence references.

## CLI

Reference commands:

```powershell
python -m trustai insurer-partner-authority artifacts/insurer-partner-service-attestation.json --worker artifacts/insurer-partner-worker.json --environment aitrade-prod --dossier-ref dossier:insurer-partner-authority/underwriter-prod --authority-ref authority:insurer-partner/underwriter-prod --producer-ref oidc:trustai.example/insurer-partner-authority-worker --authority-evidence "credentialed-partner-api-calls,insurer,insurer:underwriter/api/aitrade,sha256:insurer-partner-live-api-authority,Live underwriter API authority export;issuer=Example AI Liability Underwriter;subject=aitrade-prod insurer partner API;source_uri=https://underwriter.example/audit/trustai/aitrade;issued_at=2026-07-08T06:20:00Z;expires_at=2026-07-15T06:20:00Z" --generated-at 2026-07-08T06:25:00Z --out artifacts/insurer-partner-authority.json
python -m trustai insurer-partner-authority-verify artifacts/insurer-partner-authority.json artifacts/insurer-partner-service-attestation.json --worker artifacts/insurer-partner-worker.json
python -m trustai insurer-partner-authority-append artifacts/insurer-partner-authority.json artifacts/insurer-partner-service-attestation.json --worker artifacts/insurer-partner-worker.json --state .trustai/insurer-partner-authority-demo/evidence-chain.json --tenant insurer-partner-authority-local --out artifacts/insurer-partner-authority-entry.json
```

## Limits

This artifact proves signed binding, coverage accounting, freshness windows, and strict production-claim gates. It does not itself prove live insurer operation. Production operation still requires fresh external evidence from the actual insurer API, identity provider, policy system, scheduler/queue/lease stores, immutable delivery logs, KMS/vault custody, and operated worker infrastructure.
