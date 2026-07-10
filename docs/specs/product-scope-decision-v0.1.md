# Product Scope Decision v0.1

## Purpose

Product scope decisions record TrustAI's roadmap discipline test for incoming feature requests. The roadmap's rule is: does this make the proof stronger, cheaper to produce, or more widely accepted? If not, decline. The same receipt also screens requests against explicit anti-focus categories: observability dashboard, trace-viewer UX, agent framework or orchestrator, guardrails/content-safety company, eval library, general MLOps/model registry, insurer risk bearing, consumer product, and non-evidence analytics.

The receipt is not a product-management system. It is a signed, portable record that a request was accepted, deferred, or declined against the proof-first scope rule.

## Schema

Schema ID: `trustai.product-scope-decision/0.1`

Required top-level fields:

- `schema`: the schema ID.
- `generated_at`: RFC 3339 timestamp.
- `decision_ref`: stable decision reference.
- `requester_ref`: request source reference.
- `reviewer_ref`: reviewer identity.
- `feature`: title and summary only.
- `decision`: `accept`, `defer`, or `decline`.
- `proof_impacts`: sorted unique values from `proof-strength`, `cheaper-production`, and `wider-acceptance`.
- `anti_focus_flags`: sorted unique anti-focus categories.
- `rationale`: concise decision rationale.
- `discipline_test`: preserved proof-impact and anti-focus rules.
- `source_artifacts`: repository-relative source bindings with `sha256` and `size_bytes`.
- `controls`: status records for each product-scope control.
- `limitations`: explicit limits for this receipt.
- `decision_id`: canonical content hash of the unsigned body.
- `signatures`: detached signatures over `{decision_id, product_scope_decision}`.

## Verification Rules

Verifiers must reject a decision when:

- `decision_id` does not match the canonical unsigned body.
- no signature verifies over `{decision_id, product_scope_decision}`.
- timestamps, decision values, feature fields, or rationale are malformed.
- `proof_impacts` or `anti_focus_flags` are not sorted unique canonical values.
- `discipline_test` does not preserve proof-impact and anti-focus rules.
- required source artifacts are missing, unexpected, duplicated, or hash-mismatched.
- controls do not match the verifier-recomputed control set.
- any control has status `failed`.

Declined decisions may pass when they have no proof impact or match anti-focus categories, because declining is the required roadmap outcome.

## Controls

The control set is:

- `discipline-test-recorded`: no-impact requests must be declined.
- `accept-requires-proof-impact`: accepted requests require a positive proof impact.
- `anti-focus-requires-decline`: anti-focus requests must be declined.
- `neutrality-preserved`: TrustAI must not become an agent framework or orchestrator.
- `observability-dashboard-competition-avoided`: TrustAI must not compete on dashboard or trace-viewer UX.
- `insurer-risk-bearing-avoided`: TrustAI must not hold insurance risk.
- `consumer-scope-avoided`: TrustAI must not build consumer products.
- `roadmap-scope-source-bound`: roadmap coverage and audit sources are hash-bound.
- `proof-surface-source-bound`: proof-pack, verifier, gate, and contract sources are hash-bound.
- `raw-private-request-data-excluded`: private request bodies and confidential strategy documents are excluded.

## Chain Entry

Appending a verified decision emits entry type `trustai.product_scope.decision.attested` with:

- decision id, hash, ref, and decision
- feature title
- proof impacts and anti-focus flags
- control status summary

## CLI

```powershell
python -m trustai product-scope-decision --root . --decision-ref scope:request/proof-pack-regulator-export --requester-ref product:gtm --reviewer-ref oidc:trustai.example/product --feature-title "Regulator export evidence" --feature-summary "Add a portable regulator export that strengthens third-party proof review." --decision accept --proof-impact proof-strength --proof-impact wider-acceptance --out artifacts/product-scope-decision.json
python -m trustai product-scope-decision-verify artifacts/product-scope-decision.json --root .
python -m trustai product-scope-decision-append artifacts/product-scope-decision.json --root . --state .trustai/product-scope-demo/evidence-chain.json --tenant product-scope-local --out artifacts/product-scope-decision-entry.json
```