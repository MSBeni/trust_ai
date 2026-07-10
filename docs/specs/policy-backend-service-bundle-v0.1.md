# Policy Backend Service Bundle v0.1

Policy backend service bundles are self-contained offline review artifacts for
one signed OPA/Cedar policy backend service attestation and the source evidence
needed to replay it. They package the service attestation with its hosted
backend enforcement receipt, policy pack, runtime action, proof pack, policy
decision, policy export, and optional policy engine receipt. The schema is
`trustai.policy-backend-service-bundle/0.1`.

## Contents

- `mode`: one of `offline-review`, `auditor-review`, or `regulator-review`.
- `environment`, `generated_at`, `reviewer_ref`, and `bundle_ref`: review
  context and bundle identity.
- `source`: compact IDs and hashes for the service attestation, enforcement
  receipt, OPA/Cedar backend, policy pack, runtime action, decision outcome,
  decision-log root, and audit-log root.
- `sources`: embedded parsed source objects. Required sources are
  `service_attestation`, `enforcement`, `policy_pack`, `runtime_action`,
  `proof_pack`, `policy_decision`, and `policy_export`; `policy_engine_receipt`
  is optional and included when the service attestation was built with one.
- `source_artifacts`: embedded raw JSON source bytes as base64, plus byte
  SHA-256, canonical content hash, expected content hash, media type, size, and
  artifact ID for each embedded source.
- `summary`: source artifact count, artifact hash roots, source object hashes,
  policy-engine receipt replay status, service control summary, and enforcement
  control summary.
- `controls`: derived bundle controls for offline service replay, embedded byte
  binding, optional policy-engine replay, hosted backend endpoint binding,
  decision/audit-root review, and raw-secret scanning.
- `bundle_id` and `signatures`: canonical bundle hash and detached signatures.

## Verification

`trustai policy-backend-service-bundle-verify` checks:

1. Schema, canonical `bundle_id`, and at least one valid signature.
2. Review mode, reviewer ref, and RFC 3339 generation timestamp.
3. Embedded source object shape and required source presence.
4. Full policy backend service attestation replay using only embedded source
   objects, including enforcement, policy, action, proof pack, decision, policy
   export, and optional policy-engine receipt replay.
5. Embedded raw JSON source artifact byte hashes, sizes, canonical content
   hashes, artifact IDs, and one-to-one binding to embedded parsed source
   objects.
6. Bundle `source`, `summary`, and `controls` are recomputed from embedded
   sources.
7. Secret-like source fields are redacted references or hash/root/ref metadata.

Tampering with either parsed source objects or embedded source bytes invalidates
the bundle. The verifier does not need the original local source paths.

## CLI

```powershell
python -m trustai policy-backend-service-bundle artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --environment aitrade-prod --reviewer-ref oidc:auditor.example/policy-backend-reviewer --generated-at 2026-07-04T05:00:00Z --out artifacts/policy-backend-service-bundle.json --markdown artifacts/policy-backend-service-bundle.md
python -m trustai policy-backend-service-bundle-verify artifacts/policy-backend-service-bundle.json
python -m trustai policy-backend-service-bundle-render artifacts/policy-backend-service-bundle.json --out artifacts/policy-backend-service-bundle.md
python -m trustai policy-backend-service-bundle-extract artifacts/policy-backend-service-bundle.json --out-dir artifacts/policy-backend-service-bundle-sources
python -m trustai policy-backend-service-bundle-append artifacts/policy-backend-service-bundle.json --state .trustai/policy-backend-service-bundle-demo/evidence-chain.json --tenant policy-backend-service-bundle-local --out artifacts/policy-backend-service-bundle-entry.json
```

## Limits

This bundle proves offline replay against embedded evidence. It does not claim
live OPA/Cedar backend operation, production scheduler authority, live vault/KMS
credential custody, or immutable provider-owned decision/audit log retrieval
beyond the evidence embedded in the bundle.
