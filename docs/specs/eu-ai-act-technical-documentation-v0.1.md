# EU AI Act Technical Documentation v0.1

The EU AI Act technical-documentation artifact turns a proof pack and optional
regulator disclosure into a signed, reviewable package for high-risk AI system
documentation workflows.

## Schema

`schema`: `trustai.eu-ai-act-technical-documentation/0.1`

Top-level fields:

- `document_id`: canonical hash of the documentation body.
- `issued_at`: generation timestamp.
- `title`: human-readable title.
- `regulatory_basis`: declared regulatory basis for the package.
- `source_artifacts`: proof pack and regulator disclosure identifiers.
- `sections`: generated documentation sections.
- `signatures`: detached signature over `document_id` and the document body.

## Required Sections

The generator emits these sections:

- `system_description`: governed agent version, environment, contract hash, and
  freeze fingerprint.
- `intended_purpose`: operating scope, risk class, blast-radius limits, and
  approvals.
- `risk_classification`: operator-assessed high-risk category and rationale.
- `data_and_holdout`: freeze boundary, holdout policy, and gate holdout result.
- `performance_and_robustness`: metric checks, soak evidence, and gate outcome.
- `human_oversight`: required sign-offs, gate approvals, and runtime policy
  decisions.
- `logging_and_traceability`: source artifact ids, tree roots, evidence counts,
  and chain entry references.
- `post_market_monitoring`: runtime attestations, policy decisions, incidents,
  demotions, and rollbacks.
- `conformity_assessment_support`: offline verification commands and known
  limitations.

Each section contains evidence references with entry id, entry type, index,
timestamp, and payload hash.

## Verification

The offline verifier checks:

- supported schema.
- canonical `document_id`.
- detached signature.
- presence of every required section.
- optional source proof-pack id match.
- optional regulator-disclosure id match.

When source artifacts are provided to `eu-ai-act-verify`, the verifier first
verifies the proof pack and regulator disclosure before checking the generated
document.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai eu-ai-act-export artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --operator aitrade --out artifacts/eu-ai-act-technical-documentation.json --markdown artifacts/eu-ai-act-technical-documentation.md
python -m trustai eu-ai-act-verify artifacts/eu-ai-act-technical-documentation.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json
```

The Markdown output is a human-readable companion. The JSON artifact is the
signed source of truth.
