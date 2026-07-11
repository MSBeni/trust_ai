# Provider Operations Production Authority Dossier v0.1

Provider operations production authority dossiers bind a signed provider
operations service attestation to an explicit live-authority checklist for
provider-hosted Slack/GitHub/GitLab callback and lifecycle operations. They are
intended for auditors, model-risk teams, insurers, and customer security
reviewers who need to distinguish local/reference callback evidence from fresh
external proof of continuously operated provider infrastructure. The schema is
`trustai.provider-operations-production-authority-dossier/0.1`.

## Contents

- `mode`: one of `local-dossier`, `provider-dossier`, or
  `production-dossier`.
- `environment`, `generated_at`, `dossier_ref`, `authority_ref`, and
  `producer_ref`: production authority context.
- `service_attestation_binding`: provider operations service attestation
  id/hash, source hash, source schemas, service ref, provider, image and
  binary hashes, replica/AZ details, public ingress, OAuth/callback/audit
  worker refs, callback storage, vault/KMS, scheduler, lease, checkpoint,
  network/security controls, audit root, retention, actor, credential ref, and
  evidence refs.
- `required_production_authority`: the v0.1 checklist for hosted callback
  worker fleets, live public ingress, provider-owned vault/KMS, managed HA
  callback storage, provider audit infrastructure, credentialed external
  provider calls, webhook signature/replay/dedup controls, OAuth/app lifecycle,
  scheduler/lease/checkpoint exports, network/egress/rate-limit enforcement,
  and immutable callback/audit retention.
- `authority_evidence`: external evidence references with accepted authority
  kind, evidence ref, `sha256:` evidence hash, issuer, subject, source URI,
  issued time, expiry time, derived `source_context`, and deterministic
  `evidence_id`.
- `summary`: required, covered, missing, evidence, and freshness-window counts
  plus covered and missing requirement ids.
- `controls`: derived service attestation replay, service binding, authority
  evidence manifesting, freshness-window tracking, complete live authority
  status, and production claim limiting.
- `dossier_id` and `signatures`: canonical dossier hash and detached
  signatures.

Each authority evidence item carries a derived `source_context` tying the external authority row to the service attestation id/hash, environment, service/provider refs, public ingress, worker refs, storage/vault/KMS refs, scheduler/lease/checkpoint refs, webhook/replay/dedup/rate-limit/network/egress controls, audit root, retention, actor, credential ref, and evidence refs recorded in `service_attestation_binding`.

## Verification

`trustai provider-operations-authority-verify` checks:

1. Schema, canonical `dossier_id`, and at least one valid signature.
2. Supported mode, RFC 3339 generation timestamp, and required refs.
3. Service attestation binding presence and, when service source arguments are
   supplied, exact replay through `provider-operations-service-verify`.
4. The required production authority checklist exactly matches v0.1.
5. Every authority evidence item uses a known requirement id, accepted
   authority kind, non-empty reference and description, and `sha256:` hash.
6. Evidence ids, per-evidence `source_context`, summary, controls, freshness
   metadata, and redacted secret-like fields are deterministic and valid.
7. `--require-complete` turns missing checklist coverage into a verification
   error.
8. `--require-fresh` turns missing, not-yet-issued, or expired freshness
   windows into verification errors.
9. `production-dossier` mode is rejected unless every production authority
   requirement is covered.

If the provider operations service source is omitted, verification may warn that
source hashes were not replayed, but it still rejects incomplete signed service
bindings with missing attestation schemas, source schema/type lists, service
replica details, ingress/worker/storage/vault/KMS refs, scheduler/lease/checkpoint
refs, security/network/egress/rate-limit controls, audit refs, retention,
actor/credential refs, or evidence refs.

## CLI

```powershell
python -m trustai provider-operations-authority artifacts/provider-operations-service-attestation.json --environment aitrade-prod --dossier-ref dossier:provider-operations-authority/github-prod --authority-ref authority:provider-operations/github-prod --producer-ref oidc:trustai.example/provider-operations-authority-worker --authority-evidence "hosted-callback-worker-fleet,hosted-service,service:provider-ops/github-prod,sha256:provider-ops-hosted-fleet-authority,Hosted provider operations callback and audit worker fleet export;issuer=TrustAI Cloud;subject=aitrade-prod provider operations worker fleet;source_uri=https://ops.example/trustai/provider-ops/github-prod;issued_at=2026-07-08T05:30:00Z;expires_at=2026-07-15T05:30:00Z" --generated-at 2026-07-08T05:35:00Z --out artifacts/provider-operations-authority.json
python -m trustai provider-operations-authority-verify artifacts/provider-operations-authority.json artifacts/provider-operations-service-attestation.json
python -m trustai provider-operations-authority-append artifacts/provider-operations-authority.json artifacts/provider-operations-service-attestation.json --state .trustai/provider-operations-authority-demo/evidence-chain.json --tenant provider-operations-authority-local --out artifacts/provider-operations-authority-entry.json
```

## Chain Entry

`trustai provider-operations-authority-append` verifies the dossier and appends
a `provider.operations_authority_recorded` evidence-chain entry with the
dossier id/hash, production authority refs, service attestation binding,
coverage summary, control summary, and compact authority evidence references including `source_context`.

## Limits

This dossier is a signed checklist and binding artifact. It proves source-context-bound authority evidence rows, derived control status, coverage accounting, freshness windows, and strict production-claim gates. It does not fetch live Slack/GitHub/GitLab APIs, operate hosted workers, call vault/KMS services, or prove managed Postgres/HA storage by itself. It can support a production authority claim only when every required authority category is covered by fresh external evidence and verified with complete and fresh requirements enabled.
