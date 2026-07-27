# TrustAI Self-Serve Onboarding Production Authority Dossier v0.1

Status: draft

## Purpose

The self-serve onboarding receipt proves the local SDK/gateway quickstart path.
This production authority dossier covers the next layer: evidence that a hosted
PLG onboarding service actually creates accounts, binds identities, provisions
SDK or gateway access, meters usage, enforces quotas, and retains audit logs.

The dossier is intentionally separate from the local receipt. A verifier can
accept local onboarding proof without accepting a hosted production claim.

## Schema

`trustai.self-serve-onboarding-production-authority-dossier/0.1`

## Modes

- `local-dossier`: local/reference authority evidence only.
- `provider-dossier`: retained provider evidence rows are recorded, but the
  dossier does not claim complete production authority.
- `production-dossier`: complete and fresh authority coverage is required.

## Production Authority Checklist

Each checklist item accepts one or more authority kinds:

- `hosted-account-creation-service`: hosted signup, tenant creation, and first
  agent registration service evidence. Kinds: `hosted-service`, `provider-api`.
- `production-identity-federation`: SSO/OIDC, MFA, and signup session evidence.
  Kinds: `identity-provider`, `hosted-service`, `provider-api`.
- `billing-plan-entitlement`: billing setup, trial conversion, entitlement, and
  customer acceptance evidence. Kinds: `hosted-service`, `provider-api`,
  `customer`.
- `usage-metering-quota-enforcement`: usage metering, quota enforcement, and
  evidence-volume accounting exports. Kinds: `hosted-service`, `provider-api`.
- `support-slo-operations`: support operations, onboarding SLOs, and escalation
  evidence. Kinds: `hosted-service`, `customer`.
- `tenant-isolation-rbac`: tenant isolation, RBAC, organization membership, and
  authorization evidence. Kinds: `identity-provider`, `hosted-service`,
  `provider-api`.
- `gateway-sdk-provisioning-replay`: SDK key provisioning, MCP gateway setup
  replay, and quickstart completion evidence. Kinds: `hosted-service`, `ci-run`,
  `provider-api`.
- `onboarding-audit-retention`: immutable onboarding audit logs, access logs,
  and retention evidence. Kinds: `hosted-service`, `cloud-object-lock`,
  `provider-api`.

## Bound Source

The dossier embeds an `onboarding_source` binding derived from a verified
`trustai.self-serve-onboarding/0.1` receipt:

- receipt id and canonical hash
- onboarding, tenant, agent, requester, environment, SDK scope, and gateway mode
- source-artifact count
- quickstart step and replay counts
- derived control summary

Each authority evidence row embeds a reduced `source_context` so the row is
bound to the exact onboarding receipt it is supporting.

## Verification Rules

Verifiers must:

- recompute `dossier_id` from the canonical body
- verify at least one dossier signature
- replay the supplied self-serve onboarding receipt and match `onboarding_source`
- reject unsupported modes, requirements, authority kinds, and source contexts
- canonicalize `sha256:` evidence hashes to lowercase and reject malformed
  digests
- recompute every authority `evidence_id`
- recompute the coverage summary and controls
- enforce complete checklist coverage when `--require-complete` is used
- enforce issued/expires freshness windows when `--require-fresh` is used
- reject `production-dossier` claims unless authority coverage is complete and
  fresh

## Evidence Chain Entry

Appending a valid dossier writes entry type:

`onboarding.self_serve.production_authority_recorded`

The payload records the dossier id/hash, mode, environment, onboarding receipt
binding, authority evidence count, coverage counts, freshness counts, and
control summary.

## CLI

```powershell
python -m trustai self-serve-onboarding-authority artifacts/self-serve-onboarding.json --root . --dossier-ref dossier:self-serve-authority/aitrade-prod --authority-ref authority:self-serve/aitrade-prod --producer-ref oidc:trustai.example/self-serve-authority-worker --authority-evidence "hosted-account-creation-service,hosted-service,service:self-serve/signup-prod,sha256:<64-hex>,Hosted signup export;issuer=TrustAI Cloud;subject=aitrade self-serve onboarding;source_uri=https://ops.example/trustai/self-serve/signup-prod;issued_at=2026-07-13T00:10:00Z;expires_at=2026-07-20T00:10:00Z" --out artifacts/self-serve-onboarding-authority.json
python -m trustai self-serve-onboarding-authority-verify artifacts/self-serve-onboarding-authority.json artifacts/self-serve-onboarding.json --root .
python -m trustai self-serve-onboarding-authority-append artifacts/self-serve-onboarding-authority.json artifacts/self-serve-onboarding.json --root . --state .trustai/self-serve-authority/evidence-chain.json --tenant self-serve-authority-local --out artifacts/self-serve-onboarding-authority-entry.json
```

## Limits

This dossier strengthens the proof surface for hosted self-serve onboarding, but
retained provider-dossier examples are still not live production evidence.
Actual production claims require fresh provider-owned hosted service,
identity-provider, billing, metering, support, quota, and audit-log exports.
