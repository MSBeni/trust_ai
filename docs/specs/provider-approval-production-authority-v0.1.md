# Provider Approval Production Authority Dossier v0.1

## Purpose

The provider approval production authority dossier binds Slack approval callbacks, GitHub/GitLab webhook receipts, provider delivery authority, and provider operations authority into a single CI/CD promotion-gate approval claim. It covers the roadmap gap where local callbacks and provider webhook receipts exist, but live production credentials, public ingress, provider-owned delivery logs, and callback audit evidence remain external authority.

The dossier is intentionally an authority wrapper. It does not store raw Slack, GitHub, GitLab, OAuth, or webhook secrets. It stores hashes, ids, redacted references, and freshness windows that an offline verifier can replay from supplied artifacts.

## Schema

`trustai.provider-approval-production-authority-dossier/0.1`

A dossier contains:

- `dossier_id`: canonical hash of the dossier body.
- `mode`: one of `local-dossier`, `provider-dossier`, or `production-dossier`.
- `environment`: deployment environment covered by the authority claim.
- `dossier_ref`, `authority_ref`, `producer_ref`: stable references for the dossier, authority system, and producer identity.
- `source_binding`: hashes and selected fields from the approval request, approval callback, provider webhook receipts, provider delivery authority dossier, and provider operations authority dossier.
- `required_production_authority`: fixed v0.1 checklist.
- `authority_evidence`: external evidence refs, canonical lowercase `sha256:` hashes with 64 hex characters, issuer/subject metadata, freshness windows, derived `source_context`, and derived evidence IDs.
- `summary`: covered and missing production authority categories.
- `controls`: deterministic control outcomes derived from the body.
- `signatures`: detached signatures over `{dossier_id, provider_approval_authority}`.

## Required Production Authority Categories

1. `hosted-approval-callback-ingress`
2. `slack-interaction-signature-replay`
3. `github-gitlab-webhook-signature-replay`
4. `pending-request-storage-and-dedup`
5. `provider-delivery-authority`
6. `provider-operations-authority`
7. `production-provider-credentials`
8. `immutable-approval-audit-logs`
9. `scheduler-queue-retry-idempotency`
10. `tenant-network-egress-controls`
11. `reviewer-identity-and-rbac`

Each authority evidence item carries a derived `source_context` tying the external authority row to the approval request hash, proof-pack/contract IDs, approval callback ID/hash, reviewer role/action/team fields, provider webhook receipt IDs/hashes/delivery IDs/payload hashes, and the provider delivery and provider operations authority dossier IDs/hashes/summaries recorded in `source_binding`.

## Evidence Bundle

`trustai.provider-approval-authority-evidence-bundle/0.1` records the external authority rows before they are bound into a concrete provider approval authority dossier. The bundle contains a mode (`authority-export`, `offline-review`, or `production-export`), environment, bundle/issuer/subject/authority refs, the fixed v0.1 production authority checklist, normalized authority evidence rows, summary counts, deterministic controls, a canonical `bundle_id`, and detached signatures.

A `production-export` bundle must cover every required production authority category, carry live non-placeholder `source_uri` values, and have fresh `issued_at`/`expires_at` windows at verification time. `provider-approval-authority` accepts `--authority-evidence-bundle` and rebinds those rows to the approval request, approval callback, provider webhook, provider delivery authority, and provider operations authority source context before producing a dossier. This keeps authority evidence collection reusable while preserving dossier-level replay binding.

Bundle verification rejects mismatched bundle hashes, bad signatures, unknown requirements, invalid authority kinds, malformed evidence hashes, stale or missing freshness windows under `--require-fresh`, incomplete coverage under `--require-complete`, placeholder source URIs in production mode, control/summary tamper, and raw secret-like fields.

## Verification Rules

A verifier MUST reject a dossier when:

- `dossier_id` does not match the canonical body hash.
- No signature verifies.
- The approval callback does not verify against the supplied approval request.
- A supplied provider webhook receipt fails signature, id, or shape verification.
- A supplied provider delivery or operations authority dossier fails verification.
- `source_binding` is missing required nested IDs, hashes, replay metadata, webhook verification fields, or authority dossier summary fields, or it does not match supplied source artifacts.
- `required_production_authority`, `summary`, or `controls` do not match the v0.1 rules.
- Any authority evidence item has an unknown requirement, invalid authority kind, invalid hash/ref, bad freshness window, mismatched `evidence_id`, or `source_context` that does not match `source_binding`.
- `production-dossier` mode is used without a callback, at least one provider webhook receipt, provider delivery authority, provider operations authority, and complete fresh evidence for every required category.
- Raw secret-like values appear instead of hashes, ids, roots, or redacted references.

`provider-dossier` and `local-dossier` modes may verify with warnings. They do not claim live production Slack/GitHub/GitLab approval authority.

## CLI

```powershell
python -m trustai provider-approval-authority-evidence-bundle --mode authority-export --environment aitrade-prod --bundle-ref bundle:provider-approval-authority/github-prod/2026-07-08 --issuer-ref authority:trustai-provider-authority --subject-ref approval-authority:aitrade-prod/github --authority-ref authority:provider-approval/github-prod --authority-evidence "hosted-approval-callback-ingress,hosted-service,service:provider-approval/github-prod,sha256:885a0bf2251c53237892f9bfbc7d44ec52bd5a86317aaa51669cadf321f66441,Hosted approval callback ingress and worker fleet export;issuer=TrustAI Cloud;subject=aitrade-prod provider approval callback fleet;source_uri=https://authority.trustai.ai/provider-approval/github-prod/hosted-approval-callback-ingress;issued_at=2026-07-08T06:02:00Z;expires_at=2026-07-15T06:02:00Z" --generated-at 2026-07-08T06:04:00Z --require-fresh --now 2026-07-08T06:05:00Z --out artifacts/provider-approval-authority-evidence-bundle.json
python -m trustai provider-approval-authority-evidence-bundle-verify artifacts/provider-approval-authority-evidence-bundle.json --require-fresh --now 2026-07-08T06:05:00Z
python -m trustai provider-approval-authority-evidence-bundle-append artifacts/provider-approval-authority-evidence-bundle.json --require-fresh --now 2026-07-08T06:05:00Z --state .trustai/provider-approval-authority-demo/evidence-chain.json --tenant provider-approval-authority-local --out artifacts/provider-approval-authority-evidence-bundle-entry.json
python -m trustai provider-approval-authority artifacts/approval-request.json artifacts/approval-callback.json --webhook artifacts/github-provider-webhook.json --delivery-authority artifacts/provider-delivery-authority.json --operations-authority artifacts/provider-operations-authority.json --environment aitrade-prod --dossier-ref dossier:provider-approval-authority/github-prod --authority-ref authority:provider-approval/github-prod --producer-ref oidc:trustai.example/provider-approval-authority-worker --authority-evidence-bundle artifacts/provider-approval-authority-evidence-bundle.json --generated-at 2026-07-08T06:05:00Z --out artifacts/provider-approval-authority.json
python -m trustai provider-approval-authority-verify artifacts/provider-approval-authority.json artifacts/approval-request.json artifacts/approval-callback.json --webhook artifacts/github-provider-webhook.json --delivery-authority artifacts/provider-delivery-authority.json --operations-authority artifacts/provider-operations-authority.json
python -m trustai provider-approval-authority-append artifacts/provider-approval-authority.json artifacts/approval-request.json artifacts/approval-callback.json --webhook artifacts/github-provider-webhook.json --delivery-authority artifacts/provider-delivery-authority.json --operations-authority artifacts/provider-operations-authority.json --state .trustai/provider-approval-authority-demo/evidence-chain.json --tenant provider-approval-authority-local --out artifacts/provider-approval-authority-entry.json
```

## Production Claim Limit

A signed provider approval authority dossier is not proof that TrustAI operates live credentialed CI/CD integrations. It proves that the local approval callback, webhook, delivery authority, operations authority, and external authority records are hash-bound, source-context-bound, and offline-verifiable. A live production claim requires `production-dossier` mode plus fresh external records for every checklist category.
