# Identity Provider Production Authority Dossier v0.1

Status: draft
Schema: `trustai.identity-provider-production-authority-dossier/0.1`
Entry type: `identity.provider_authority_recorded`

## Purpose

An identity-provider production authority dossier binds a verified `identity-provider-lifecycle-worker` receipt to explicit external production-authority evidence. It is the bridge between local/reference identity lifecycle receipts and a production claim for live Okta, Entra, ServiceNow, or equivalent identity-provider event streams, token/session propagation, lifecycle APIs, provider audit exports, credential custody, and scheduler or queue operation.

The dossier records what external authority evidence exists, which categories are missing, and whether the supplied evidence is fresh at verification time. `local-dossier` and `provider-dossier` modes are allowed for local/reference evidence and partial provider exports, but they do not claim live production authority. A production claim requires `mode` set to `production-dossier` and complete fresh evidence for every required category.

## Modes

- `local-dossier`: local or reference authority evidence only.
- `provider-dossier`: provider evidence is present, but production authority is not fully claimed.
- `production-dossier`: every required production authority category must have fresh acceptable evidence.

## Required Production Authority Categories

The verifier checks this required checklist exactly. Each category can be covered by one or more authority evidence records.

| Requirement ID | Expected authority kinds | Purpose |
| --- | --- | --- |
| `live-identity-provider-event-streams` | `identity-provider`, `provider-api` | Live provider-owned account, app, session, token, and lifecycle event streams. |
| `token-session-propagation` | `identity-provider`, `provider-api` | Token, session, and account propagation records for governed agents. |
| `account-app-lifecycle-apis` | `identity-provider`, `provider-api` | Account, app assignment, SCIM sync, token revocation, and session revocation lifecycle API exports. |
| `provider-system-log-retention` | `identity-provider`, `provider-api`, `cloud-object-lock` | Provider-native system-log retention, cursor, and replay exports. |
| `immutable-identity-audit-logs` | `identity-provider`, `cloud-object-lock`, `customer` | Immutable identity-provider lifecycle worker and provider audit logs. |
| `credential-custody-and-kms` | `kms-hsm`, `identity-provider`, `provider-api` | Identity-provider lifecycle credential custody and KMS/HSM enforcement evidence. |
| `scheduler-queue-lease-checkpoint` | `hosted-service`, `provider-api` | Production scheduler, queue, lease, checkpoint, cursor, and dead-letter provider exports. |
| `identity-inventory-reconciliation` | `identity-provider`, `provider-api`, `customer` | Agent inventory reconciliation against identity-provider records and trust-network identity receipts. |
| `propagation-response-replay` | `identity-provider`, `provider-api`, `customer` | Retained request/response replay for lifecycle propagation operations. |
| `tenant-network-and-access-controls` | `hosted-service`, `provider-api`, `identity-provider` | Tenant network, admin access, breakglass, and rate-limit controls for identity lifecycle workers. |

## Dossier Fields

A dossier contains:

- `schema`: `trustai.identity-provider-production-authority-dossier/0.1`.
- `mode`, `environment`, `generated_at`, `dossier_ref`, `authority_ref`, and `producer_ref`.
- `worker_binding`: content hash and core provider, source operation, identity, worker, scheduler, propagation, response, observability, credential, and source-control references from the lifecycle worker receipt.
- `required_production_authority`: the exact requirement list above.
- `authority_evidence`: authority evidence records supplied by the producer.
- `summary`: covered, missing, fresh, stale, and missing-freshness counts.
- `controls`: passed, deferred, and failed claim controls.
- `limitations`: non-production and missing-live-authority disclaimers.
- `dossier_id`: canonical hash of the dossier body without signatures.
- `signatures`: one or more signatures over the dossier id and body.

## Authority Evidence Records

Each `authority_evidence` record must contain:

- `requirement_id`: one of the required production authority category ids.
- `authority_kind`: an allowed external authority kind for that category.
- `evidence_ref`: stable external reference such as a provider export id, system-log cursor, hosted service audit URI, object-lock root, KMS/HSM custody record, or customer-owned ledger pointer.
- `evidence_hash`: hash or immutable root for the external evidence.
- `description`: human-readable evidence description.

Optional metadata fields are `issuer`, `subject`, `source_uri`, `issued_at`, and `expires_at`. Freshness checks use `issued_at` and `expires_at`. Evidence without both timestamps is accepted for non-strict verification but counted as missing freshness.

CLI evidence strings use:

```text
requirement_id,authority_kind,evidence_ref,evidence_hash,description[;issuer=value;subject=value;source_uri=value;issued_at=value;expires_at=value]
```

## Verification Rules

A verifier must:

1. Verify the schema, canonical `dossier_id`, and at least one valid signature.
2. Verify `mode`, `environment`, `dossier_ref`, `authority_ref`, `producer_ref`, and RFC3339 timestamps.
3. Re-verify the bound identity-provider lifecycle worker receipt against the supplied lifecycle operation, identity-provider attestation, optional identity-provider session receipt, identity payload, vendor identity receipt, trust-network manifest, and proof packs.
4. Compare the dossier `worker_binding` content hashes to the supplied source documents.
5. Require the `required_production_authority` checklist to match this specification exactly.
6. Reject evidence with unknown requirement ids or disallowed authority kinds.
7. Reject malformed evidence references, hashes, and timestamp windows.
8. Count missing, stale, and fresh evidence. With `--require-complete`, every requirement id must be covered. With `--require-fresh`, every covered evidence item must include a valid current freshness window.
9. Reject `production-dossier` mode unless all requirements are covered with fresh evidence.
10. Reject raw secrets in the dossier. Secret-bearing fields must be redacted references such as `env:`, `vault:`, `kms:`, or content hashes.

## CLI Examples

Create a provider dossier with partial production authority evidence:

```powershell
python -m trustai identity-provider-authority artifacts/identity-provider-lifecycle-worker.json artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --mode provider-dossier --environment aitrade-prod --dossier-ref dossier:identity-provider-authority/okta-prod --authority-ref authority:identity-provider/okta-prod --producer-ref oidc:trustai.example/identity-provider-authority-worker --authority-evidence "live-identity-provider-event-streams,identity-provider,okta:system-log/query/aitrade-agent-events,sha256:identity-provider-live-event-streams,Okta system-log export for governed agent lifecycle events;issuer=Okta;subject=aitrade-prod governed agent identity events;source_uri=https://okta.example/system-log/aitrade-agent-events;issued_at=2026-07-12T02:10:00Z;expires_at=2026-07-19T02:10:00Z" --authority-evidence "credential-custody-and-kms,kms-hsm,kms:identity-provider/lifecycle-worker-token,sha256:identity-provider-kms-custody,KMS/HSM custody export for the identity lifecycle worker credential;issuer=Example KMS;subject=identity lifecycle worker credential custody;source_uri=https://kms.example/audit/identity-provider/lifecycle-worker;issued_at=2026-07-12T02:11:00Z;expires_at=2026-07-19T02:11:00Z" --generated-at 2026-07-12T02:12:00Z --now 2026-07-15T00:00:00Z --out artifacts/identity-provider-authority.json
```

Verify and append the dossier:

```powershell
python -m trustai identity-provider-authority-verify artifacts/identity-provider-authority.json artifacts/identity-provider-lifecycle-worker.json artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --now 2026-07-15T00:00:00Z
python -m trustai identity-provider-authority-append artifacts/identity-provider-authority.json artifacts/identity-provider-lifecycle-worker.json artifacts/identity-provider-lifecycle-operation.json artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --vendor-identity artifacts/vendor-identity-receipt.json --manifest artifacts/trust-network-manifest.json --pack artifacts/aitrade-proof-pack.json --identity-session artifacts/identity-provider-session.json --now 2026-07-15T00:00:00Z --state .trustai/identity-provider-authority-demo/evidence-chain.json --tenant identity-provider-authority-local --out artifacts/identity-provider-authority-entry.json
```

## Production Claim Limits

This specification makes production identity-provider authority auditable, but it does not manufacture live provider evidence. A `local-dossier` or `provider-dossier` may prove the local receipt graph and document missing authority. A real production claim requires current external evidence from provider-owned event streams, lifecycle APIs, immutable audit exports, token/session propagation logs, KMS/HSM custody records, scheduler and lease stores, and monitored hosted worker fleets.