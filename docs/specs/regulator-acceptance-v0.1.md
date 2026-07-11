# Regulator Acceptance Receipt v0.1

This specification defines a local-reference receipt for recording that a named
regulator or supervisor accepted, conditionally accepted, rejected, or requested
remediation for a disclosed TrustAI evidence package. It turns the roadmap's
"regulator accepts packs" milestone into a portable, signed artifact that can be
verified without access to a hosted TrustAI account.

## Schema

`schema`: `trustai.regulator-acceptance/0.1`

Required top-level fields:

- `acceptance_id`: canonical hash of the receipt body.
- `issued_at`: RFC3339 timestamp for the acknowledgement.
- `regulator`: reviewer organization, authority reference, reviewer reference,
  local attestation mode, and production replacement note.
- `decision`: outcome, accepted boolean, examination reference, observations,
  and conditions.
- `review_scope`: purpose, framework, optional review period, source artifact
  names, and offline verification requirement.
- `source_artifacts`: canonical hash records for the proof pack, regulator
  disclosure, EU AI Act technical documentation, and optional supervised-access
  receipt. Source records deep-copy nested source summaries so acceptance
  artifacts cannot mutate supplied source objects in memory.
- `controls`: local-reference and planned-production controls.
- `signatures`: detached local HMAC signature over the acceptance id and body.

Allowed `decision.outcome` values:

- `accepted`
- `accepted_with_observations`
- `accepted_with_conditions`
- `needs_remediation`
- `rejected`

The first three outcomes set `decision.accepted` to `true`; the last two remain
verifiable receipts but surface verifier warnings.

## Verification

`trustai regulator-acceptance-verify` checks:

- schema, canonical `acceptance_id`, and receipt signature;
- required regulator identity and examination references;
- accepted flag consistency with the outcome;
- review period timestamp ordering when a period is supplied;
- required source artifacts are present;
- optional deep source verification for:
  - proof pack,
  - regulator disclosure,
  - EU AI Act technical documentation,
  - supervised-access receipt.

When source artifacts are supplied, the verifier checks every recorded source
summary field against the supplied artifacts, delegates to the existing
artifact-specific verifiers, and enforces acceptance-level bindings: regulator
reviewer identity and organization must match the supervised-access reviewer,
the supervised-access audience must be `regulator`, and supervised-access
issuance must fall inside the acceptance review period when one is declared.

## Evidence Chain Entry

`trustai regulator-acceptance-append` first verifies the receipt, then appends
`regulator.acceptance.recorded` to an evidence chain. The entry payload records
the acceptance id, acceptance hash, regulator, decision, review scope, source
artifact references, and limitations.

## Reference Commands

```powershell
python -m trustai regulator-acceptance --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --document artifacts/eu-ai-act-technical-documentation.json --supervised-access artifacts/supervised-access-receipt.json --supervised-view artifacts/regulator-view.html --regulator "Example Supervisor" --authority-ref EU-NCA:EXAMPLE --reviewer-ref oidc:regulator.example/supervisor-123 --examination-ref EXAM-2026-TRUSTAI-001 --accepted-at 2026-07-10T00:00:00Z --review-period-start 2026-07-08T00:00:00Z --review-period-end 2026-07-10T00:00:00Z --out artifacts/regulator-acceptance.json
python -m trustai regulator-acceptance-verify artifacts/regulator-acceptance.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --document artifacts/eu-ai-act-technical-documentation.json --supervised-access artifacts/supervised-access-receipt.json --supervised-view artifacts/regulator-view.html
python -m trustai regulator-acceptance-append artifacts/regulator-acceptance.json --state .trustai/regulator-acceptance-demo/evidence-chain.json --tenant regulator-acceptance-local --out artifacts/regulator-acceptance-entry.json
```

## Production Boundary

This local receipt models the acceptance-evidence shape. Production deployments
still need authority-authenticated reviewer sessions, regulator-controlled
signing keys or signed examination letters, retention policy for official
acknowledgements, and legal review of what constitutes binding acceptance in
each jurisdiction.
