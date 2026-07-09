# Underwriting Quote Receipt v0.1

TrustAI insurer telemetry is useful only if underwriters can turn it into a
verifiable pricing decision. The underwriting quote receipt is a signed,
offline-verifiable artifact that binds consented proof-pack risk telemetry to a
quoted premium, discount, coverage limit, term, and underwriter reference.

This v0.1 receipt does not claim live insurer binding authority, admitted-carrier
pricing, or partner authentication. It models the verification shape for the
roadmap's insurance ratchet: proof packs can become underwriting evidence, and a
premium credit can be proved without trusting a screenshot or portal claim.

## Schema

`schema`: `trustai.underwriting-quote/0.1`

Required top-level fields:

- `quote_id`: canonical hash of the quote body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{quote_id, quote}`.
- `issued_at`: RFC3339 quote issue timestamp.
- `expires_at`: RFC3339 quote expiry timestamp.
- `underwriter`: underwriter name, mode, and production replacement note.
- `applicant_risk`: selected risk summary from insurer telemetry.
- `quote`: product, currency, coverage limit, base premium, discount percent,
  quoted premium, policy term, status, and discount reason.
- `risk_evidence`: canonical hash of the source insurer telemetry, telemetry
  schema, consent id/status, proof-pack id, contract id, and chain root.
- `controls`: implemented-reference and planned-production controls.
- `limitations`: explicit non-production claims.

## Discount Schedule

The local deterministic schedule is intentionally simple and auditable:

- gate outcome must be `passed`;
- `low` risk tier with score `>= 90`: 15% credit;
- `low` risk tier below 90: 10% credit;
- `medium` risk tier: 5% credit;
- `high` risk tier or failed gate: no credit.

Production underwriters should replace this schedule with signed partner API
responses and policy-system references while preserving the same verification
bindings.

## Verification

`trustai underwriting-quote-verify` checks:

- quote schema and canonical `quote_id`;
- detached quote signature;
- issued/expiry and policy-term time windows;
- numeric premium, discount, and coverage fields;
- quoted premium equals base premium minus discount;
- consented telemetry schema and active consent status;
- proof-pack id and telemetry hash binding;
- optional source telemetry consistency when `--telemetry` is supplied.

`trustai underwriting-quote-append` first verifies the receipt, then appends
`insurer.underwriting_quote.issued` to an evidence chain. The appended entry
records the quote id/hash, underwriter, applicant risk summary, quote terms,
risk evidence, and limitations.

## Example Commands

```powershell
python -m trustai insurer-export artifacts/aitrade-proof-pack.json --consent-id aitrade-underwriting-consent-20260704 --require-consent --state .trustai/demo/evidence-chain.json --tenant aitrade-local --out artifacts/insurer-risk-telemetry.json
python -m trustai underwriting-quote artifacts/insurer-risk-telemetry.json --underwriter "Example AI Liability Underwriter" --coverage-limit-usd 1000000 --base-premium-usd 25000 --term-start 2026-07-08T00:00:00Z --term-end 2027-07-08T00:00:00Z --issued-at 2026-07-08T00:00:00Z --expires-at 2026-08-08T00:00:00Z --out artifacts/underwriting-quote.json
python -m trustai underwriting-quote-verify artifacts/underwriting-quote.json --telemetry artifacts/insurer-risk-telemetry.json --now 2026-07-09T00:00:00Z
python -m trustai underwriting-quote-append artifacts/underwriting-quote.json --state .trustai/underwriting-demo/evidence-chain.json --tenant underwriting-local --out artifacts/underwriting-quote-entry.json
python -m trustai chain-verify --state .trustai/underwriting-demo/evidence-chain.json --tenant underwriting-local
```

## Production Notes

A production insurer integration should add:

- underwriter partner identity and credentialed API authentication;
- signed insurer response payloads or mTLS-backed response receipts;
- policy-system quote references and binding-status transitions;
- jurisdiction/product constraints for admitted and surplus lines;
- revocation, requote, and bind/decline evidence entries;
- disclosure rules for customer consent and underwriter data retention.

The receipt is not insurance advice and does not bind coverage. It proves the
pricing evidence chain that a real underwriter integration must preserve.
