# Policy Backend Production Authority Dossier v0.1

Policy backend production authority dossiers bind a verified policy backend
provider export review bundle, plus optional independently verified service
review bundles, to an explicit external-authority checklist for OPA/Cedar
production operation. They are intended for auditors, insurers,
regulators, model-risk teams, and customer security reviewers who need to see
which live authority categories are covered, fresh, missing, or intentionally
deferred. The schema is
`trustai.policy-backend-production-authority-dossier/0.1`.

## Contents

- `mode`: one of `local-dossier`, `provider-dossier`, or
  `production-dossier`.
- `environment`, `generated_at`, `dossier_ref`, `authority_ref`, and
  `producer_ref`: production authority context.
- `provider_bundle_binding`: provider export bundle id/hash, mode, reviewer,
  provider receipt hash, provider export hash/ref, worker operation hash,
  service attestation id, enforcement id, backend, engine, endpoint, decision
  hash, decision-log root, audit-log root, source artifact roots, provider
  record roots, and policy-engine replay status.
- `service_bundle_bindings`: optional service review bundle ids/hashes,
  service attestation and enforcement hashes, backend, engine, endpoint,
  policy/action/decision bindings, decision and audit roots, embedded source
  artifact roots, and policy-engine replay status.
- `required_production_authority`: the v0.1 checklist for continuously
  operated OPA/Cedar backend fleets, scheduler/queue/lease exports, decision
  and audit retention, credential custody, KMS/HSM control, mTLS/authz,
  tenant isolation, policy bundle supply chain, drift monitoring, provider
  export freshness, and WORM/object-lock retention.
- `authority_evidence`: external evidence references with accepted authority
  kind, evidence ref, `sha256:` evidence hash, issuer, subject, source URI,
  issued time, expiry time, and deterministic `evidence_id`.
- `summary`: required, covered, missing, evidence, and freshness-window counts
  plus covered and missing requirement ids.
- `controls`: provider bundle replay, provider bundle binding, optional service
  review bundle binding, authority evidence manifesting, freshness-window
  tracking, complete live authority status, and production claim limiting.
- `dossier_id` and `signatures`: canonical dossier hash and detached
  signatures.

## Verification

`trustai policy-backend-authority-verify` checks:

1. Schema, canonical `dossier_id`, and at least one valid signature.
2. Supported mode, RFC 3339 generation timestamp, and required refs.
3. Provider bundle binding presence and every non-null provider binding field
   emitted by the v0.1 builder. When `--provider-bundle` is supplied, the
   binding must also replay exactly through
   `policy-backend-provider-export-bundle-verify`.
4. Optional service bundle bindings and every non-null service binding field
   emitted by the v0.1 builder. When `--service-bundle` is supplied, each
   binding must also replay exactly through
   `policy-backend-service-bundle-verify` plus linkage to the provider bundle
   service attestation, enforcement, backend, endpoint, engine, and decision
   hash. Omitted sources may produce replay warnings, but they must not permit
   partial provider or service binding summaries.
5. The required production authority checklist exactly matches v0.1.
6. Every authority evidence item uses a known requirement id, accepted
   authority kind, non-empty reference and description, and `sha256:` hash.
7. Evidence ids, summary, controls, freshness metadata, and redacted
   secret-like fields are deterministic and valid.
8. `--require-complete` turns missing checklist coverage into a verification
   error.
9. `--require-fresh` turns missing, not-yet-issued, or expired freshness
   windows into verification errors.
10. `production-dossier` mode is rejected unless every production authority
   requirement is covered.

## CLI

```powershell
python -m trustai policy-backend-authority artifacts/policy-backend-provider-export-bundle.json --service-bundle artifacts/policy-backend-service-bundle.json --environment aitrade-prod --dossier-ref dossier:policy-backend-authority/lg-trace-001 --authority-ref authority:policy-backend/aitrade-prod --producer-ref oidc:trustai.example/policy-backend-authority-worker --authority-evidence "opa-cedar-backend-fleet,hosted-service,service:policy-backend-fleet/aitrade-prod,sha256:policy-backend-fleet-authority,Hosted OPA/Cedar backend fleet deployment export;issuer=TrustAI Cloud;subject=aitrade-prod policy backend fleet;source_uri=https://ops.example/trustai/policy-backend/aitrade-prod;issued_at=2026-07-04T00:00:00Z;expires_at=2026-07-11T00:00:00Z" --generated-at 2026-07-04T05:20:00Z --out artifacts/policy-backend-authority.json
python -m trustai policy-backend-authority-verify artifacts/policy-backend-authority.json --provider-bundle artifacts/policy-backend-provider-export-bundle.json --service-bundle artifacts/policy-backend-service-bundle.json
python -m trustai policy-backend-authority-append artifacts/policy-backend-authority.json --provider-bundle artifacts/policy-backend-provider-export-bundle.json --service-bundle artifacts/policy-backend-service-bundle.json --state .trustai/policy-backend-authority-demo/evidence-chain.json --tenant policy-backend-authority-local --out artifacts/policy-backend-authority-entry.json
```

## Chain Entry

`trustai policy-backend-authority-append` verifies the dossier and appends a
`policy_backend.production_authority_recorded` evidence-chain entry with the
dossier id/hash, production authority refs, provider bundle binding, service
bundle bindings, coverage summary, control summary, and authority evidence
references.

## Limits

This dossier is a signed checklist and binding artifact. It does not call live
cloud APIs, fetch provider exports, or independently operate OPA/Cedar
backends. It can support a production authority claim only when every required
authority category is covered by fresh external evidence and the dossier is
verified with complete and fresh requirements enabled.
