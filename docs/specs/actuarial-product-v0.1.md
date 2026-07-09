# Actuarial Product v0.1

The actuarial product manifest turns one or more anonymized actuarial corpus
exports into a signed, offline-verifiable data product for insurer,
regulator, and longitudinal reliability consumers. It is the local reference
shape for the roadmap's Phase 4 actuarial data product.

## Schema

`schema`: `trustai.actuarial-product/0.1`

Top-level fields:

- `product_id`: canonical hash of the product body.
- `issued_at`: product publication timestamp.
- `product`: name, publisher, audience, allowed uses, and production boundary.
- `reporting_period`: explicit period or source-corpus timestamp range.
- `privacy_controls`: minimum record count, consent requirement, source salt
  hashes, and direct-identifier exclusion policy.
- `source_corpora`: corpus ids, hashes, schemas, consent state, anonymization
  salt hashes, and aggregate summaries.
- `aggregate`: merged incident, demotion, rollback, risk tier, and risk class
  counts across all source records.
- `longitudinal`: ordered source-corpus points for trend analysis.
- `limitations`: local-reference limitations.
- `signatures`: detached local signature over `product_id` and product body.

## Verification

`actuarial-product-verify` checks:

- product schema, canonical `product_id`, and signature.
- source corpus bindings by `corpus_id`, canonical corpus hash, consent state,
  anonymization salt hash, and aggregate summary when corpora are supplied.
- merged aggregate and longitudinal summaries against supplied source corpora.
- minimum-record privacy threshold and all-active-consent requirement.

If source corpora are omitted, the verifier checks the signed product binding
and emits a warning that source artifacts were not supplied.

## Chain Evidence

`actuarial-product-append` writes an `actuarial.product.published` entry with:

- product id and product hash.
- source corpus bindings.
- privacy controls.
- aggregate and longitudinal summaries.
- publication limitations.

This creates tamper-evident evidence that an actuarial product was published
from specific anonymized and consent-bound corpus artifacts.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai actuarial-verify artifacts/actuarial-corpus.json
python -m trustai actuarial-product artifacts/actuarial-corpus.json --product-name "TrustAI reliability benchmark" --publisher trustai-local --issued-at 2026-07-06T00:00:00Z --out artifacts/actuarial-product.json
python -m trustai actuarial-product-verify artifacts/actuarial-product.json --corpus artifacts/actuarial-corpus.json
python -m trustai actuarial-product-append artifacts/actuarial-product.json --corpus artifacts/actuarial-corpus.json --state .trustai/actuarial-demo/evidence-chain.json --tenant actuarial-local --out artifacts/actuarial-product-entry.json
```

Production actuarial products still require privacy review, customer consent
terms, re-identification risk controls, partner authentication, retention
limits, and contractual restrictions on redistribution.
