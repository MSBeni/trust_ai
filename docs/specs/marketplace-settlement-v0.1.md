# Marketplace Settlement Receipt v0.1

Marketplace settlement receipts bind a signed marketplace author governance
receipt to entitlement checks, invoice amounts, author revenue share, payout
execution, tax-document custody, and immutable settlement audit evidence. They
provide local, chain-appendable evidence for marketplace billing and payout
operations without exposing raw payout account data, tax documents, provider
credentials, or subscriber proof-pack payloads.

## Schema

`schema`: `trustai.marketplace-settlement/0.1`

Top-level fields:

- `settlement_id`: canonical hash of the settlement body.
- `mode`: `local-reference`, `recorded-provider-response`, or
  `provider-settled`.
- `issued_at`: receipt issuance timestamp.
- `settlement`: settlement reference, subscriber reference, covered period,
  and currency.
- `governance`: source marketplace author governance id, hash, schema, author,
  catalog, distribution, billing, and asset-count binding.
- `entitlement`: entitlement check reference, policy reference, decision,
  timestamp, and settled asset ids.
- `invoice`: invoice reference, status, gross amount, and per-asset line items.
- `revenue_share`: author revenue-share basis points, author gross amount, and
  platform amount.
- `tax`: tax profile, jurisdiction, tax form reference, withholding basis
  points and amount, tax-document custody reference, and document hash.
- `payout`: payout reference, provider reference, status, executed timestamp,
  payout amount, redacted payout account reference, optional transfer trace,
  and optional redacted idempotency-key reference.
- `audit_log`: immutable settlement audit log reference, root hash, and
  retention timestamp.
- `source_artifacts`: author governance, catalog, and distribution source
  hashes when supplied.
- `controls`: source binding, entitlement, invoice/revenue share, payout, and
  tax custody control status.
- `operations`: supporting evidence references.
- `limitations`: non-production and redaction boundaries.
- `signatures`: detached local signature over `settlement_id` and body.

## Verification

`marketplace-settlement-verify` checks:

- settlement schema, canonical id, and signature.
- supported settlement, entitlement, invoice, and payout modes/statuses.
- settlement period ordering and required timestamps.
- entitlement decision, policy, check reference, and settled asset ids.
- invoice line items sum to the gross amount.
- revenue share, tax withholding, and payout amounts match deterministic
  settlement math:
  - author gross = gross amount * author governance revenue share bps / 10000.
  - platform amount = gross amount - author gross.
  - tax withholding = author gross * tax withholding bps / 10000.
  - payout amount = author gross - tax withholding.
- redacted payout account and idempotency-key references.
- tax form, tax-document custody reference, and SHA-256 document hash.
- audit root as a SHA-256 reference and retention after `issued_at`.
- absence of unredacted secret-like fields.
- source author governance validity when supplied, including catalog and
  distribution replay when those sources are supplied.
- governance, entitlement policy, payout account, tax form, asset, and
  `source_artifacts` binding against supplied sources.

If source author governance, catalog, or distribution artifacts are omitted,
the verifier checks the signed receipt binding and emits warnings that source
hashes were not replayed.

## Chain Evidence

`marketplace-settlement-append` emits a
`marketplace.billing.settlement_recorded` entry containing:

- settlement id and settlement hash.
- mode and issued timestamp.
- settlement, governance, entitlement, invoice, revenue-share, tax, payout, and
  audit-log metadata.
- source artifact hashes.
- control-status summary.

This gives marketplace operators, buyers, authors, auditors, and procurement
teams a tamper-evident record that marketplace entitlements, invoices, payouts,
tax custody, and author revenue-share calculations were recorded against a
specific author governance receipt.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai marketplace-settlement artifacts/marketplace-author-governance.json --catalog artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --root . --mode provider-settled --settlement-ref settlement:marketplace/EXAMPLE-2026-001 --subscriber-ref oidc:buyer.example/procurement --entitlement-check-ref entitlement-check:marketplace/EXAMPLE-2026-001 --entitlement-decision allowed --entitlement-checked-at 2026-07-12T02:00:00Z --period-start 2026-07-12T00:00:00Z --period-end 2026-08-12T00:00:00Z --invoice-ref invoice:marketplace/EXAMPLE-2026-001 --gross-amount-usd 1000 --tax-withholding-bps 1000 --invoice-status paid --payout-ref payout:marketplace/EXAMPLE-2026-001 --payout-provider-ref stripe:transfer/tr_EXAMPLE --payout-status settled --payout-executed-at 2026-07-12T02:30:00Z --payout-trace-ref trace:marketplace-payout/EXAMPLE-2026-001 --idempotency-key-ref vault:idempotency/marketplace/EXAMPLE-2026-001 --tax-profile-ref tax-profile:example-audit/us --tax-jurisdiction US --tax-document-custody-ref vault:tax-documents/example-audit/w9-2026 --tax-document-hash sha256:marketplace-tax-document-hash --audit-log-ref audit-log:marketplace/settlements --audit-log-root sha256:marketplace-settlement-audit-root --retention-until 2033-08-12T00:00:00Z --evidence-ref evidence:marketplace/settlement --issued-at 2026-07-12T03:00:00Z --out artifacts/marketplace-settlement.json
python -m trustai marketplace-settlement-verify artifacts/marketplace-settlement.json --author-governance artifacts/marketplace-author-governance.json --catalog artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --root .
python -m trustai marketplace-settlement-append artifacts/marketplace-settlement.json --author-governance artifacts/marketplace-author-governance.json --catalog artifacts/marketplace-catalog.json --distribution artifacts/marketplace-distribution.json --root . --state .trustai/marketplace-settlement-demo/evidence-chain.json --tenant marketplace-settlement-local --out artifacts/marketplace-settlement-entry.json
python -m trustai chain-verify --state .trustai/marketplace-settlement-demo/evidence-chain.json --tenant marketplace-settlement-local
```

Production marketplace settlement still needs continuously operated hosted
settlement workers, provider-owned payment events, immutable invoice and payout
logs, live tax-document custody, revocation propagation, and external provider
callbacks beyond this signed local/reference receipt.
