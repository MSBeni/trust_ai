# Product Scope Production Authority Dossier v0.1

## Purpose

Product scope decisions prove that an individual feature request was accepted, deferred, or declined against TrustAI's proof-first discipline test. A product scope authority dossier records the operating evidence that this discipline is enforced outside a single local receipt: governance adoption, product-council enforcement, anti-focus decline retention, customer-pressure exception review, and recurring roadmap discipline audits.

The dossier does not claim production completeness unless it is in `production-dossier` mode and every operating authority checklist item has fresh accepted evidence.

## Schema

Schema ID: `trustai.product-scope-production-authority-dossier/0.1`

Required top-level fields:

- `schema`: the schema ID.
- `mode`: `local-dossier`, `governance-dossier`, or `production-dossier`.
- `environment`: environment or operating scope.
- `generated_at`: RFC 3339 timestamp.
- `dossier_ref`: stable dossier reference.
- `authority_ref`: operating authority reference.
- `producer_ref`: worker, person, or identity that produced the dossier.
- `decision_source`: canonical binding to a verified `trustai.product-scope-decision/0.1` receipt.
- `required_operating_authority`: the verifier's product-scope operating authority checklist.
- `authority_evidence`: accepted authority rows.
- `summary`: verifier-derived coverage and authority-kind counts.
- `controls`: verifier-derived authority controls.
- `limitations`: explicit limits for non-production modes.
- `dossier_id`: canonical content hash of the unsigned body.
- `signatures`: detached signatures over `{dossier_id, product_scope_authority}`.

## Operating Authority Checklist

The checklist is:

- `company-governance-adoption`: company governance adoption of the proof-strength scope discipline.
- `product-council-enforcement`: product council enforcement and exception approval evidence.
- `anti-focus-decline-ledger`: anti-focus decline ledger and non-proof feature rejection evidence.
- `customer-pressure-exception-review`: customer-pressure exception review and refusal evidence.
- `ongoing-roadmap-discipline`: ongoing roadmap discipline audit and CI/source review evidence.

Accepted authority kinds are intentionally narrow: `customer` and `ci-run`. These match the roadmap's requirement that product-scope discipline be proven by external operating evidence, not just local code.

## Verification Rules

Verifiers must reject a dossier when:

- `dossier_id` does not match the canonical unsigned body.
- no signature verifies over `{dossier_id, product_scope_authority}`.
- mode, timestamps, references, or evidence rows are malformed.
- `decision_source` does not match the supplied product-scope decision receipt.
- the supplied product-scope decision receipt does not verify.
- `required_operating_authority`, `summary`, or `controls` do not match verifier recomputation.
- an authority row uses an unsupported requirement or authority kind.
- an authority row has a non-canonical `sha256:` evidence hash or a mismatched `evidence_id`.
- an authority row is not bound to the source decision context.
- `require_complete` is set and any checklist item is uncovered.
- `require_fresh` is set and any authority row lacks a fresh `issued_at` / `expires_at` window.
- `mode` is `production-dossier` and any checklist item is uncovered or evidence freshness is stale or missing.

## Chain Entry

Appending a verified dossier emits entry type `trustai.product_scope.production_authority.attested` with:

- dossier id, hash, refs, mode, and environment
- source decision id, ref, decision, and feature title
- authority evidence count
- covered and required checklist counts
- freshness counts
- control status summary

## CLI

```powershell
python -m trustai product-scope-authority artifacts/product-scope-decision.json --root . --mode governance-dossier --environment aitrade-prod --dossier-ref dossier:product-scope-authority/aitrade-prod --authority-ref authority:product-scope/aitrade-prod --producer-ref oidc:trustai.example/product-scope-authority-worker --authority-evidence "company-governance-adoption,customer,governance:product-council/scope-charter,sha256:0000000000000000000000000000000000000000000000000000000000000000,Product council charter adopting the proof discipline question.;issuer=TrustAI Product Council;subject=product scope discipline;source_uri=https://governance.example/trustai/product-scope/charter;issued_at=2026-07-21T00:10:00Z;expires_at=2026-07-28T00:10:00Z" --out artifacts/product-scope-authority.json
python -m trustai product-scope-authority-verify artifacts/product-scope-authority.json artifacts/product-scope-decision.json --root .
python -m trustai product-scope-authority-append artifacts/product-scope-authority.json artifacts/product-scope-decision.json --root . --state .trustai/product-scope-authority/evidence-chain.json --tenant product-scope-authority --out artifacts/product-scope-authority-entry.json
```
