# Actuarial Corpus v0.1

The actuarial corpus is an anonymized, consent-aware data product for AI
liability underwriting and longitudinal reliability analysis. It converts
verified proof packs and related lifecycle evidence into pseudonymous records
without exposing raw agent names, pack ids, or contract ids.

## Schema

`schema`: `trustai.actuarial-corpus/0.1`

Top-level fields:

- `corpus_id`: canonical hash of the corpus body.
- `generated_at`: export timestamp.
- `record_count`: number of proof-pack records included.
- `anonymization`: hash method and salt hash.
- `consent`: consent id, scope, active statuses, and whether active consent was
  required.
- `records`: pseudonymous actuarial records.
- `aggregate`: corpus-level incident, demotion, rollback, risk tier, and risk
  class counts.

## Record Shape

Each record includes:

- pseudonymous pack, contract, and agent ids.
- non-identifying risk class and framework fields.
- gate outcome, risk score, risk tier, failed-check count, holdout result, and
  approval status.
- evidence chain root and framework mapping list.
- lifecycle summary from the evidence chain: incident count, demotion count,
  rollback count, maximum incident severity, and incident types.

The export intentionally does not include raw prompts, trace payloads, tool
arguments, agent names, contract ids, approver identities, or customer names.

## Consent

`trustai actuarial-export --require-consent` checks the same consent grants as
`insurer-export`, using `proof-pack-risk-telemetry` scope. If consent is missing,
expired, revoked, or constrained away from the pack or contract, export fails
closed.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai actuarial-export artifacts/aitrade-proof-pack.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local --consent-id aitrade-underwriting-consent-20260704 --require-consent --now 2026-07-05T00:00:00Z --out artifacts/actuarial-corpus.json
python -m trustai actuarial-verify artifacts/actuarial-corpus.json
```

Use `docs/specs/actuarial-product-v0.1.md` for the signed product manifest that binds one or more corpora into a publishable longitudinal data product. The local corpus is a reference artifact. Production data products still need
customer consent terms, privacy review, re-identification risk controls, partner
authentication, retention limits, and contractual restrictions on redistribution.
