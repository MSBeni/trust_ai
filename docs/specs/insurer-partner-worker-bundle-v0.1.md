# Insurer Partner Worker Bundle v0.1

Insurer partner worker bundles are self-contained offline review artifacts for
one signed insurer partner worker receipt and the source evidence needed to
replay it. They package the worker receipt with its insurer partner service
attestation, consented insurer risk telemetry, underwriting quote, optional
actuarial product/corpora, and frontend bundle bytes when the service
attestation binds a frontend artifact. The schema is
`trustai.insurer-partner-worker-bundle/0.1`.

## Contents

- `mode`: one of `offline-review`, `underwriter-review`, or `auditor-review`.
- `environment`, `generated_at`, `reviewer_ref`, and `bundle_ref`: review
  context and bundle identity.
- `verification_options`: point-in-time replay settings, including `now`.
- `source`: compact IDs and hashes for the worker operation, service
  attestation, telemetry, quote, underwriter, destination, response status, and
  policy binding evidence.
- `sources`: embedded parsed JSON source objects. Required sources are
  `worker_receipt`, `service_attestation`, `telemetry`, and
  `underwriting_quote`; optional sources are `actuarial_product` and
  `actuarial_corpora`.
- `source_artifacts`: embedded raw source bytes as base64, plus byte SHA-256,
  canonical content hash, expected content hash, media type, size, and artifact
  ID for each embedded source. Frontend bundles are byte-bound by SHA-256.
- `summary`: source artifact count, artifact hash roots, source object hashes,
  frontend bundle replay status, actuarial corpus count, and worker control
  summary.
- `controls`: derived bundle controls for offline worker replay, embedded byte
  binding, frontend bundle replay, actuarial replay, underwriting review, and
  raw-secret scanning.
- `bundle_id` and `signatures`: canonical bundle hash and detached signatures.

## Verification

`trustai insurer-partner-worker-bundle-verify` checks:

1. Schema, canonical `bundle_id`, and at least one valid signature.
2. Review mode, reviewer ref, and RFC 3339 generation timestamp.
3. Embedded source object shape and required source presence.
4. Full insurer partner worker receipt replay using only embedded source objects
   and extracted frontend bundle bytes when the service attestation binds them.
5. Embedded source artifact byte hashes, sizes, content hashes, artifact IDs,
   and one-to-one binding to embedded parsed source objects.
6. Bundle `source`, `summary`, and `controls` are recomputed from embedded
   sources.
7. Secret-like source fields are redacted references or hash/root/ref metadata.

Tampering with either parsed source objects or embedded source bytes invalidates
the bundle. The verifier does not need the original local source paths.

## CLI

```powershell
python -m trustai insurer-partner-worker-bundle artifacts/insurer-partner-worker.json artifacts/insurer-partner-service-attestation.json artifacts/insurer-risk-telemetry.json artifacts/underwriting-quote.json --actuarial-product artifacts/actuarial-product.json --actuarial-corpus artifacts/actuarial-corpus.json --frontend-bundle artifacts/insurer-partner.bundle.js --mode underwriter-review --environment aitrade-prod --reviewer-ref oidc:underwriter.example/trustai-reviewer --generated-at 2026-07-09T00:00:00Z --now 2026-07-09T00:00:00Z --out artifacts/insurer-partner-worker-bundle.json --markdown artifacts/insurer-partner-worker-bundle.md
python -m trustai insurer-partner-worker-bundle-verify artifacts/insurer-partner-worker-bundle.json
python -m trustai insurer-partner-worker-bundle-render artifacts/insurer-partner-worker-bundle.json --out artifacts/insurer-partner-worker-bundle.md
python -m trustai insurer-partner-worker-bundle-extract artifacts/insurer-partner-worker-bundle.json --out-dir artifacts/insurer-partner-worker-bundle-sources
python -m trustai insurer-partner-worker-bundle-append artifacts/insurer-partner-worker-bundle.json --state .trustai/insurer-partner-worker-bundle-demo/evidence-chain.json --tenant insurer-partner-worker-bundle-local --out artifacts/insurer-partner-worker-bundle-entry.json
```

## Limits

This bundle proves offline replay against embedded underwriting and worker
evidence. It does not claim credentialed partner API calls, externally operated
insurer integration worker fleets, policy-system execution, immutable
partner-owned delivery logs, or production scheduler/lease storage beyond the
evidence embedded in the bundle.
