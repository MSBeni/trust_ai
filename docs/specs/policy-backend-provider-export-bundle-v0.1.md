# Policy Backend Provider Export Bundle v0.1

Policy backend provider export bundles package a signed provider-export receipt
with every JSON source needed to replay it offline. They are intended for
auditors, regulators, insurers, and internal model-risk reviewers who need to
verify provider-native OPA/Cedar evidence without access to the original local
workspace. The schema is `trustai.policy-backend-provider-export-bundle/0.1`.

## Contents

- `mode`: one of `offline-review`, `auditor-review`, or `regulator-review`.
- `environment`, `generated_at`, `reviewer_ref`, and `bundle_ref`: review
  context.
- `source`: provider receipt id/hash, provider export hash/ref, worker
  operation id/hash, run ref, service attestation id, enforcement id, backend,
  endpoint, decision hash, decision-log root, and audit-log root.
- `sources`: parsed JSON source objects for provider receipt, provider export,
  worker receipt, service attestation, enforcement receipt, policy pack,
  runtime action, proof pack, policy decision, policy export, and optional
  policy engine receipt.
- `source_artifacts`: raw embedded source bytes, original path, media type,
  byte size, SHA-256, canonical content hash, expected content hash, and
  artifact id.
- `summary`: source artifact roots, source object hashes, provider record
  roots, provider control summary, worker control summary, and policy-engine
  replay status.
- `controls`: offline replay, byte binding, policy engine receipt replay,
  provider record-root review, worker operation binding, provider export source
  binding, and raw secret scan status.
- `bundle_id` and `signatures`: canonical bundle hash and detached signatures.

## Verification

`trustai policy-backend-provider-export-bundle-verify` checks:

1. Schema, canonical `bundle_id`, and at least one valid signature.
2. Supported mode, reviewer ref, and RFC 3339 generation timestamp.
3. Required embedded source objects are present and unsupported source keys are
   rejected.
4. Embedded provider-export receipt replays against the embedded provider
   export, worker receipt, service attestation, enforcement receipt, policy
   pack, runtime action, proof pack, policy decision, policy export, and
   optional policy engine receipt.
5. Source artifact ids, SHA-256 hashes, byte sizes, base64 payloads, parsed
   JSON, canonical content hashes, and embedded source-object hashes all match.
6. Source, summary, and control sections are deterministic recomputations from
   embedded sources.
7. Secret-like fields are redacted references or allowed hash/root/ref metadata,
   never raw tokens, passwords, cookies, client secrets, private keys, or
   authorization material.

## CLI

```powershell
python -m trustai policy-backend-provider-export-bundle artifacts/policy-backend-provider-export.json artifacts/policy-backend-provider-export-source.json artifacts/policy-backend-worker.json artifacts/policy-backend-service-attestation.json artifacts/policy-backend-enforcement.json examples/aitrade/policy-pack.json examples/aitrade/runtime-action.json --pack artifacts/aitrade-proof-pack.json --decision artifacts/policy-decision.json --export artifacts/policy-export.json --policy-engine-receipt artifacts/policy-engine-receipt.json --environment aitrade-prod --reviewer-ref oidc:auditor.example/policy-backend-provider-reviewer --generated-at 2026-07-04T05:10:00Z --out artifacts/policy-backend-provider-export-bundle.json --markdown artifacts/policy-backend-provider-export-bundle.md
python -m trustai policy-backend-provider-export-bundle-verify artifacts/policy-backend-provider-export-bundle.json
python -m trustai policy-backend-provider-export-bundle-render artifacts/policy-backend-provider-export-bundle.json --out artifacts/policy-backend-provider-export-bundle.md
python -m trustai policy-backend-provider-export-bundle-extract artifacts/policy-backend-provider-export-bundle.json --out-dir artifacts/policy-backend-provider-export-bundle-sources
python -m trustai policy-backend-provider-export-bundle-append artifacts/policy-backend-provider-export-bundle.json --state .trustai/policy-backend-provider-export-bundle-demo/evidence-chain.json --tenant policy-backend-provider-export-bundle-local --out artifacts/policy-backend-provider-export-bundle-entry.json
```

## Chain Entry

`trustai policy-backend-provider-export-bundle-append` verifies the bundle and
appends a `policy_backend.provider_export_bundle_exported` evidence-chain entry
with the bundle id/hash, review context, source summary, deterministic bundle
summary, and control summary.

## Limits

This bundle is self-contained for offline replay of supplied JSON evidence. It
does not call live cloud APIs and does not prove continuous production operation
unless the embedded provider export and receipts were generated from
provider-owned production scheduler, queue, lease, backend, decision-log,
audit-log, credential-custody, and immutable retention systems.
