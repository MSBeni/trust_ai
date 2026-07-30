# Promotion Status Review Bundle v0.1

A promotion status review bundle is a self-contained, signed artifact for
offline review of CI/CD promotion gate evidence. It packages a promotion status
receipt with the proof pack, provider-native status payload, optional delivery
receipt, and retained delivery artifact bytes needed to replay the receipt
without access to the original checkout paths.

## Schema

The bundle uses schema `trustai.promotion-status-review-bundle/0.1`.

Top-level fields:

- `bundle_id`: canonical hash of the bundle body without `bundle_id` and
  `signatures`.
- `mode`: `offline-review`, `auditor-review`, or `regulator-review`.
- `environment`: optional environment or provider context.
- `generated_at`: RFC3339 bundle generation timestamp.
- `reviewer_ref`: reviewer identity or review workflow reference.
- `bundle_ref`: stable reviewer-facing bundle reference.
- `source`: normalized summary of the receipt, proof pack, provider payload,
  provider target, proof-pack reference, delivery receipt, and pass status.
- `sources`: embedded parsed source objects: promotion status receipt, proof
  pack, provider payload, and optional provider delivery receipt.
- `source_artifacts`: raw source bytes encoded as base64, with byte SHA-256,
  size, media type, canonical content hash, artifact type, and artifact ID.
- `summary`: source object hashes, source artifact roots, replay flags, provider
  target binding, proof-pack reference binding, pass status, and receipt control
  summary.
- `controls`: replay controls for offline status verification, source byte
  binding, provider target binding, provider proof-pack reference binding,
  provider delivery replay, and retained delivery artifact replay.
- `limitations`: explicit production-claim limits.
- `signatures`: one or more detached signatures over `bundle_id` and body.

## Required Embedded Sources

Every bundle must embed:

- `receipt`: a `trustai.promotion-status/0.1` receipt;
- `proof_pack`: the TrustAI proof pack referenced by the receipt; and
- `payload`: the GitHub/GitLab provider status payload referenced by the
  receipt.

If the receipt references a provider delivery binding, the bundle embeds:

- `delivery`: the provider delivery receipt;
- `delivery_payload_artifact` when the delivery receipt records a retained
  payload artifact separate from the payload source; and
- `delivery_response_artifact` when the delivery receipt records retained
  provider response bytes.

When the delivery payload artifact is the same file as the provider payload, the
bundle may use the embedded `payload` artifact for retained payload replay.

## Verification

`promotion-status-bundle-verify` checks:

- bundle schema, mode, timestamp, reviewer reference, bundle ID, and signature;
- embedded source object types and supported source names;
- source artifact IDs, byte SHA-256 values, byte sizes, media types, base64
  content, and canonical content hashes;
- proof pack offline verification;
- promotion status receipt replay against the embedded proof pack, verifier
  result, provider payload, optional delivery receipt, and retained delivery
  artifact bytes;
- provider-native GitHub/GitLab status shape, concrete repository/project commit
  target binding, and proof-pack URL/correlation binding;
- delivery payload and response artifact replay when the delivery receipt binds
  those artifacts; and
- summary and controls recomputation from the embedded sources.

Tampering with the proof pack, provider payload conclusion/state, repository or
project commit reference, proof-pack URL, GitHub external ID, receipt signature,
delivery payload hash, retained response artifact bytes, or any embedded source
artifact causes verification to fail.

## Chain Entry

Verified bundles append `promotion.status_review_bundle.attested` entries with:

- bundle ID and bundle hash;
- mode, environment, generated timestamp, reviewer reference, and bundle ref;
- source summary;
- bundle summary; and
- replay control summary.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai promotion-status-bundle artifacts/promotion-status.json artifacts/aitrade-proof-pack.json artifacts/github-check-run-payload.json --delivery artifacts/github-check-run-delivery.json --delivery-response-artifact artifacts/github-check-run-response.json --reviewer-ref oidc:auditor.example/cicd-reviewer --generated-at 2026-07-04T00:02:00Z --out artifacts/promotion-status-review-bundle.json --markdown artifacts/promotion-status-review-bundle.md
python -m trustai promotion-status-bundle-verify artifacts/promotion-status-review-bundle.json
python -m trustai promotion-status-bundle-render artifacts/promotion-status-review-bundle.json --out artifacts/promotion-status-review-bundle.md
python -m trustai promotion-status-bundle-extract artifacts/promotion-status-review-bundle.json --out-dir artifacts/promotion-status-review-bundle-sources
python -m trustai promotion-status-bundle-append artifacts/promotion-status-review-bundle.json --state .trustai/promotion-status-review/evidence-chain.json --tenant promotion-status-review --out artifacts/promotion-status-review-bundle-entry.json
```

## Limits

This bundle proves offline replay of a promotion status receipt and the source
artifacts supplied to it. It does not prove that GitHub, GitLab, or Slack
displayed, retained, or externally audited the promotion status unless paired
with provider-owned webhook, audit-log, callback, delivery, and production
authority evidence.
