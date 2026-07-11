# Provider Delivery Production Authority Dossier v0.1

Status: draft v0.1

This specification defines a signed TrustAI dossier that binds provider delivery service attestations, worker receipts, and optional worker review bundles to explicit production-authority evidence for credentialed external Slack, GitHub, and GitLab posting.

## Purpose

Provider delivery service attestations and worker receipts can prove local/reference dispatch controls, source delivery binding, queue metadata, idempotency, request hashes, response summaries, and redacted credential references. They do not by themselves prove a continuously operated production dispatch service with live credentials and provider-owned event exports.

A provider delivery production authority dossier records that boundary. It binds the signed delivery service attestation, one or more signed worker receipts, and optional offline worker review bundles to a checklist of external authority evidence. Verifiers can reject incomplete or stale production claims while still accepting partial provider dossiers as useful evidence.

## Schema

`trustai.provider-delivery-production-authority-dossier/0.1`

Required top-level fields:

- `schema`: schema identifier.
- `mode`: one of `local-dossier`, `provider-dossier`, or `production-dossier`.
- `environment`: deployment environment the dossier describes.
- `generated_at`: RFC 3339 dossier generation timestamp.
- `dossier_ref`: stable dossier reference.
- `authority_ref`: stable authority reference for the production delivery surface.
- `producer_ref`: identity that produced the dossier.
- `service_attestation_binding`: canonical binding to the delivery service attestation hash, service refs, dispatch controls, security refs, observability, actor, and redacted credential refs.
- `worker_receipt_bindings`: canonical bindings to worker operation IDs, worker receipt hashes, scheduler/lease/checkpoint refs, queue/DLQ/idempotency refs, provider request/response hashes, delivery/provider/audit log roots, and redacted worker/provider credential refs.
- `worker_bundle_bindings`: canonical bindings to optional worker review bundle IDs/hashes, embedded source-artifact roots, retained payload artifact replay status, and service/worker linkage.
- `required_production_authority`: the v0.1 production authority checklist.
- `authority_evidence`: external evidence references for covered checklist items.
- `summary`: computed coverage and freshness summary.
- `controls`: verification controls and statuses.
- `dossier_id`: canonical hash of the unsigned dossier body.
- `signatures`: detached signatures over `dossier_id` and the unsigned body.

## Production Authority Requirements

The v0.1 checklist covers:

- Continuously operated provider delivery dispatch worker fleets.
- Production provider credentials under vault/KMS custody and rotation controls.
- Live network egress to Slack/GitHub/GitLab provider APIs from operated infrastructure.
- Real `http-dispatch` or recorded-response artifacts from external provider calls.
- Provider-owned delivery, check, message, or event exports retrieved from provider APIs.
- Production scheduler, queue, DLQ, lease, checkpoint, and idempotency stores.
- Retry, dead-letter, deduplication, and idempotent dispatch controls.
- Tenant egress policy, provider rate-limit enforcement, and request signing controls.
- Production delivery logs, worker audit logs, metrics, alerts, and provider event roots.
- Immutable provider delivery, worker, response, and audit retention.
- Provider operations authority or equivalent hosted callback/credential control evidence.

## Verification

A verifier MUST:

1. Recompute `dossier_id` from the unsigned body.
2. Verify at least one dossier signature.
3. Verify the delivery service attestation signature and canonical binding when the service source is supplied.
4. Verify each delivery worker receipt signature and canonical binding when worker sources are supplied.
5. Verify each supplied worker review bundle and reject bundles that do not reference the supplied service attestation and worker receipt hashes.
6. Recompute the production authority summary from `authority_evidence`.
7. Validate every authority evidence item has an accepted requirement ID, authority kind, hash ref, and stable evidence ID.
8. Validate freshness metadata when `require_fresh` is set.
9. Reject `production-dossier` mode unless every production authority requirement is covered.
10. Reject secret-like fields unless they are redacted references or hash/root references.

If raw delivery, payload, provider response, provider audit correlation, provider operations service, or worker bundle sources are omitted, the verifier MAY still accept the signed service/worker/bundle binding and MUST emit warnings that source hashes were not replayed. It MUST still reject incomplete signed bindings with missing service schemas, source-type lists, security or observability references, worker scheduler/dispatch/audit fields, source delivery hashes, worker bundle source-artifact roots, or bundle replay-status fields.

## CLI

- `provider-delivery-authority`: write a signed dossier.
- `provider-delivery-authority-verify`: verify a signed dossier.
- `provider-delivery-authority-append`: append a verified dossier to an evidence chain.

## Chain Entry

`provider.delivery_authority_recorded`

The chain payload includes the dossier ID/hash, mode, environment, authority references, service attestation binding, worker receipt bindings, worker bundle bindings, coverage summary, control summary, and authority evidence references.

## Limits

This dossier is an authority evidence manifest, not a live provider API client. It does not fetch provider state. A production claim is only as strong as the external evidence hashes and retained source artifacts supplied to independent verifiers.
