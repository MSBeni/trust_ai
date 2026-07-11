# Insurer Partner Production Authority Dossier v0.1

Status: draft reference format.

This specification defines the `trustai.insurer-partner-production-authority-dossier/0.1` artifact. The dossier binds signed insurer partner service attestations, worker receipts, and optional worker review bundles to external authority evidence for live insurer, underwriter, and policy-system operation.

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
- `worker_bundle_bindings`: optional worker review bundle IDs/hashes, embedded source artifact roots, frontend replay status, actuarial replay status, telemetry and underwriting quote hashes, and service/worker linkage.
- `required_production_authority`: the v0.1 requirement checklist.
- `authority_evidence`: supplied external authority evidence items.
- `summary`: derived coverage and freshness summary.
- `controls`: derived control statuses.
- `limitations`: human-readable non-claim statements.
- `signatures`: one or more signatures over `{dossier_id, insurer_partner_authority}`.

## Bindings

The service binding records service identity, endpoint, partner API endpoint, image and binary hashes, frontend bundle reference/hash, queue and policy-system references, underwriter and quote references, consent and telemetry metadata, actuarial product binding, partner-authentication controls, request-signing controls, delivery/audit/access log roots, retention, actor, and redacted TrustAI and partner credential references.

The worker binding records worker operation ID/hash, service attestation ID/hash, scheduler cadence, leases, checkpoints, queue messages, destination, partner delivery/event log roots, policy workflow and binding hashes, request/response hashes, audit/access roots, retention, and redacted worker credential references.

The worker bundle binding records worker review bundle ID/hash, service and worker receipt hashes, telemetry and underwriting quote hashes, embedded source artifact roots, frontend bundle replay status, actuarial product/corpus replay status, and the policy binding/underwriting fields needed for offline insurer or auditor review.

Verification recomputes every binding from supplied service, worker, and worker-bundle artifacts. If telemetry, underwriting quote, actuarial product/corpus, or frontend bundle sources are supplied, the verifier also replays the underlying service and worker checks. If worker bundles are supplied, the verifier also verifies each bundle and rejects bundles that do not reference the supplied service attestation and worker receipt hashes.

If service, worker, worker-bundle, telemetry, underwriting quote, actuarial, or frontend sources are omitted, verification may warn that source hashes were not replayed, but it still rejects incomplete signed bindings with missing attestation schemas, source schema/type lists, frontend artifact hashes, consent and risk fields, delivery/audit/access log refs, policy workflow/binding hashes, replay-status fields, source-artifact roots, or worker control summaries.

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

Each evidence item contains `requirement_id`, `authority_kind`, `evidence_ref`, `evidence_hash`, `description`, optional `issuer`, `subject`, `source_uri`, `issued_at`, `expires_at`, derived `source_context`, and derived `evidence_id`. Evidence hashes must use `sha256:` references. Authority kinds must be accepted by the requirement. The derived `source_context` binds each external authority row to the service attestation id/hash, environment, service ref, partner API endpoint, underwriter, quote, telemetry, consent, frontend, actuarial product, worker operation IDs/hashes/run refs, policy binding hashes, worker bundle IDs/hashes, and bundled source roots recorded in the dossier.

## Verification

A conforming verifier must:

- Verify schema, canonical `dossier_id`, and at least one signature.
- Recompute service and worker bindings from supplied source artifacts.
- Verify service and worker source artifacts, including optional telemetry, underwriting quote, actuarial product/corpus, and frontend bundle replay when supplied.
- Verify supplied worker review bundles and compare their service, worker, telemetry, source-artifact, frontend replay, and actuarial replay bindings to the dossier.
- Verify every authority evidence id, hash reference, and derived source-context binding.
- Recompute the summary from evidence.
- Recompute controls from service, worker, bundle, evidence, and summary bindings.
- Warn for missing production authority requirements.
- Fail when `--require-complete` is set and any requirement is missing.
- Fail when `--require-fresh` is set and any evidence item lacks an unexpired `issued_at`/`expires_at` window.
- Fail when `mode` is `production-dossier` and any requirement is missing.
- Reject secret-like fields unless they are redacted objects or reference/hash/root fields.

## Chain Entry

Appending a valid dossier writes entry type `insurer.partner_authority_recorded`. The entry payload includes dossier identity, mode, environment, service, worker, and worker-bundle bindings, coverage summary, control summary, and compact authority evidence references.

## CLI

Reference commands:

```powershell
python -m trustai insurer-partner-authority artifacts/insurer-partner-service-attestation.json --worker artifacts/insurer-partner-worker.json --worker-bundle artifacts/insurer-partner-worker-bundle.json --environment aitrade-prod --dossier-ref dossier:insurer-partner-authority/underwriter-prod --authority-ref authority:insurer-partner/underwriter-prod --producer-ref oidc:trustai.example/insurer-partner-authority-worker --authority-evidence "credentialed-partner-api-calls,insurer,insurer:underwriter/api/aitrade,sha256:insurer-partner-live-api-authority,Live underwriter API authority export;issuer=Example AI Liability Underwriter;subject=aitrade-prod insurer partner API;source_uri=https://underwriter.example/audit/trustai/aitrade;issued_at=2026-07-08T06:20:00Z;expires_at=2026-07-15T06:20:00Z" --generated-at 2026-07-08T06:25:00Z --out artifacts/insurer-partner-authority.json
python -m trustai insurer-partner-authority-verify artifacts/insurer-partner-authority.json artifacts/insurer-partner-service-attestation.json --worker artifacts/insurer-partner-worker.json --worker-bundle artifacts/insurer-partner-worker-bundle.json
python -m trustai insurer-partner-authority-append artifacts/insurer-partner-authority.json artifacts/insurer-partner-service-attestation.json --worker artifacts/insurer-partner-worker.json --worker-bundle artifacts/insurer-partner-worker-bundle.json --state .trustai/insurer-partner-authority-demo/evidence-chain.json --tenant insurer-partner-authority-local --out artifacts/insurer-partner-authority-entry.json
```

## Limits

This artifact proves signed source-context binding for each authority evidence row, coverage accounting, freshness windows, and strict production-claim gates. It does not itself prove live insurer operation. Production operation still requires fresh external evidence from the actual insurer API, identity provider, policy system, scheduler/queue/lease stores, immutable delivery logs, KMS/vault custody, and operated worker infrastructure.
