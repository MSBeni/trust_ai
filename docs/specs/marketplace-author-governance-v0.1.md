# Marketplace Author Governance Receipt v0.1

Marketplace author governance receipts bind a verified TrustAI marketplace
catalog, and optionally a marketplace distribution receipt, to author
onboarding, identity assurance, review approval, licensing, IP attestation,
entitlement, billing, payout, revocation, support, and audit-log evidence.
They provide local, chain-appendable evidence for the roadmap's certified
third-party-authored contract templates and policy packs.

## Schema

`schema`: `trustai.marketplace-author-governance/0.1`

Top-level fields:

- `governance_id`: canonical hash of the author governance body.
- `mode`: `local-reference`, `platform-governed`, or `partner-governed`.
- `issued_at`: receipt issuance timestamp.
- `catalog`: source catalog id, hash, schema, publisher, status, asset count,
  and aggregate summary.
- `distribution`: optional source distribution id, hash, channel, subscriber,
  and selected asset count.
- `author`: author name, stable subject reference, author kind, organization,
  and contact reference.
- `identity`: identity-provider subject, assurance level, and onboarding
  status.
- `agreements`: author agreement, terms, license, and IP-attestation
  references.
- `review`: marketplace review ticket, policy, reviewer, role, and status.
- `assets`: governed marketplace assets selected from the source catalog with
  content hashes and certification metadata.
- `billing`: billing mode, billing account, entitlement policy, redacted
  payout account reference, revenue share, and tax-form reference.
- `operations`: revocation policy, support/security contacts, and supporting
  evidence references.
- `audit_log`: immutable author-governance audit log reference, root hash, and
  retention timestamp.
- `source_artifacts`: catalog and optional distribution source hashes.
- `controls`: summarized author, review, licensing, billing, distribution, and
  support/revocation control status.
- `limitations`: non-production and redaction boundaries.
- `signatures`: detached local signature over `governance_id` and body.

## Verification

`marketplace-author-verify` checks:

- author governance schema, canonical id, and signature.
- supported governance mode, author kind, and billing mode.
- approved identity onboarding and review status for governed modes.
- required author, identity, agreement, review, operations, and audit fields.
- governed asset uniqueness, supported asset type, and content hash presence.
- source catalog validity and selected asset bindings when the catalog is
  supplied.
- optional distribution validity and source-artifact hash binding when supplied.
- billing account, entitlement policy, redacted payout account reference, and
  `0..10000` revenue-share basis points for billed modes.
- SHA-256 audit-log root reference and retention timestamp after `issued_at`.
- absence of unredacted secret-like fields such as tokens, passwords,
  credentials, or private keys.

If the source catalog or distribution is omitted, the verifier checks the
signed receipt binding and emits a warning that source artifacts were not
supplied.

## Chain Evidence

`marketplace-author-append` emits a
`marketplace.author.governance_attested` entry containing:

- governance id and governance hash.
- mode and issued timestamp.
- catalog and optional distribution bindings.
- author, identity, review, asset, billing, operations, and audit-log metadata.
- source artifact hashes.
- control-status summary.

This gives marketplace operators, buyers, auditors, and authors a
tamper-evident record that a catalog revision was published with governed
third-party author, entitlement, billing, payout, and revocation evidence
without exposing raw marketplace credentials, payout account data, or tax
documents.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai marketplace-author-governance artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --root . --mode platform-governed --author-name "Example Audit Templates" --author-ref did:web:templates.example --author-kind third-party --author-organization "Example Audit LLP" --contact-ref mailto:templates@example.com --identity-provider okta --identity-subject okta:user/example-audit-templates --identity-assurance phishing-resistant-mfa --onboarding-status approved --agreement-ref agreement:marketplace-author/EXAMPLE-2026-001 --terms-ref terms:trustai-marketplace-author-v0.1 --license-ref license:apache-2.0 --ip-attestation-ref ip-attestation:EXAMPLE-2026-001 --review-ticket-ref review:marketplace/EXAMPLE-2026-001 --review-policy-ref policy:marketplace-review-v0.1 --reviewer-ref oidc:trustai.example/marketplace-reviewer-1 --billing-mode entitlement-recorded --billing-account-ref billing:acct/example-audit --entitlement-policy-ref policy:marketplace-entitlements-v0.1 --payout-account-ref vault:payout/example-audit --revenue-share-bps 2500 --tax-form-ref tax-form:w9/example-audit-2026 --revocation-policy-ref policy:marketplace-revocation-v0.1 --support-contact-ref mailto:support@example.com --security-contact-ref mailto:security@example.com --audit-log-ref audit-log:marketplace/authors --audit-log-root sha256:marketplace-author-audit-root --retention-until 2033-07-12T00:00:00Z --evidence-ref evidence:marketplace/author-review --issued-at 2026-07-12T01:00:00Z --out artifacts/marketplace-author-governance.json
python -m trustai marketplace-author-verify artifacts/marketplace-author-governance.json --catalog artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --root .
python -m trustai marketplace-author-append artifacts/marketplace-author-governance.json --catalog artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --root . --state .trustai/marketplace-author-demo/evidence-chain.json --tenant marketplace-author-local --out artifacts/marketplace-author-governance-entry.json
python -m trustai chain-verify --state .trustai/marketplace-author-demo/evidence-chain.json --tenant marketplace-author-local
```

Marketplace entitlement, invoice, payout, and tax-custody settlement evidence is
covered by `docs/specs/marketplace-settlement-v0.1.md`. Production marketplace
author governance still needs hosted identity-provider events, signed agreement
storage, immutable review artifacts, continuously operated revocation
propagation, and external provider callbacks beyond these signed
local/reference receipts.
