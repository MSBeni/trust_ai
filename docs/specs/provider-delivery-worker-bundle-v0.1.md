# Provider Delivery Worker Bundle v0.1

Provider delivery worker bundles are self-contained offline review artifacts for
one signed provider delivery worker receipt and the source evidence needed to
replay it. They package the worker receipt with its provider delivery service
attestation, provider delivery receipt, optional retained payload artifact bytes,
optional provider operations service attestation, optional retained provider response artifact,
and optional provider audit correlation plus provider audit-log export. The
schema is `trustai.provider-delivery-worker-bundle/0.1`.

## Contents

- `mode`: one of `offline-review`, `auditor-review`, or `regulator-review`.
- `environment`, `generated_at`, `reviewer_ref`, and `bundle_ref`: review
  context and bundle identity.
- `source`: compact IDs and hashes for the worker operation, delivery receipt,
  provider, service attestation, dispatch run, response status, and optional
  provider response/audit evidence.
- `sources`: embedded parsed source objects. Required sources are
  `worker_receipt`, `service_attestation`, and `delivery`; optional sources are
  `payload`, `provider_operations_service`, `provider_response`,
  `provider_audit_correlation`, and `provider_audit_log`.
- `source_artifacts`: embedded raw JSON source bytes as base64, plus byte
  SHA-256, canonical content hash, expected content hash, media type, size, and
  artifact ID for each embedded source.
- `summary`: source artifact count, artifact hash roots, source object hashes,
  provider response replay status, provider audit replay status, retained
  payload artifact replay status, and worker control summary.
- `controls`: derived bundle controls for offline worker replay, embedded byte
  binding, retained payload artifact replay, optional provider response replay,
  optional provider audit-log replay, and raw-secret scanning.
- `bundle_id` and `signatures`: canonical bundle hash and detached signatures.

## Verification

`trustai provider-delivery-worker-bundle-verify` checks:

1. Schema, canonical `bundle_id`, and at least one valid signature.
2. Review mode, reviewer ref, and RFC 3339 generation timestamp.
3. Embedded source object shape and required source presence.
4. Full provider delivery worker receipt replay using only embedded source
   objects, including retained delivery payload artifact replay from embedded
   payload bytes when the delivery receipt records `payload_artifact`, plus
   optional provider response and provider audit-log replay.
5. Embedded raw JSON source artifact byte hashes, sizes, canonical content
   hashes, artifact IDs, and one-to-one binding to embedded parsed source
   objects.
6. Bundle `source`, `summary`, and `controls` are recomputed from embedded
   sources.
7. Secret-like source fields are redacted references or hash/root/ref metadata.

Tampering with either parsed source objects or embedded source bytes invalidates
the bundle. When `payload_artifact` is present, the verifier recomputes its
recorded path, byte SHA-256, size, content hash, and payload hash from the
embedded payload bytes. The verifier does not need the original local source
paths.

## CLI

```powershell
python -m trustai provider-delivery-worker-bundle artifacts/provider-delivery-worker.json artifacts/github-check-run-delivery.json --service-attestation artifacts/provider-delivery-service-attestation.json --payload artifacts/github-check-run-payload.json --provider-operations-service artifacts/provider-operations-service-attestation.json --provider-response artifacts/provider-response.json --provider-audit-correlation artifacts/provider-audit-correlation.json --provider-audit-log artifacts/provider-audit-log.json --reviewer-ref oidc:auditor.example/provider-delivery-reviewer --generated-at 2026-07-08T05:17:00Z --out artifacts/provider-delivery-worker-bundle.json --markdown artifacts/provider-delivery-worker-bundle.md
python -m trustai provider-delivery-worker-bundle-verify artifacts/provider-delivery-worker-bundle.json
python -m trustai provider-delivery-worker-bundle-render artifacts/provider-delivery-worker-bundle.json --out artifacts/provider-delivery-worker-bundle.md
python -m trustai provider-delivery-worker-bundle-extract artifacts/provider-delivery-worker-bundle.json --out-dir artifacts/provider-delivery-worker-bundle-sources
python -m trustai provider-delivery-worker-bundle-append artifacts/provider-delivery-worker-bundle.json --state .trustai/provider-delivery-worker-bundle-demo/evidence-chain.json --tenant provider-delivery-worker-bundle-local --out artifacts/provider-delivery-worker-bundle-entry.json
```

## Limits

This bundle proves offline replay against embedded evidence. It does not claim
live provider API posting, live provider-owned audit export retrieval, production
credential custody, or continuously operated dispatch/audit worker fleets beyond
the evidence embedded in the bundle.