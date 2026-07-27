# Design Partner Production Authority Dossier v0.1

## Purpose

The design-partner pilot dossier proves local Phase 1 readiness and can bind redacted partner contracts, payment evidence, and external scrutiny events. A design partner production authority dossier records the external authority needed before TrustAI can claim that Phase 1 exit criteria have been achieved in production: customer-paid pilot acceptance, regulator or supervisor scrutiny survival, and insurer underwriting review.

The dossier stores references, hashes, source URIs, and freshness windows. It does not store raw customer contracts, payment records, regulator files, insurer files, or private proof packs.

## Schema

Schema ID: `trustai.design-partner-production-authority-dossier/0.1`

Required top-level fields:

- `schema`: the schema ID.
- `mode`: `local-dossier`, `partner-dossier`, or `production-dossier`.
- `environment`: environment or operating scope.
- `generated_at`: RFC 3339 timestamp.
- `dossier_ref`: stable dossier reference.
- `authority_ref`: external authority reference.
- `producer_ref`: worker, person, or identity that produced the dossier.
- `pilot_source`: canonical binding to a verified `trustai.design-partner-pilot/0.1` dossier.
- `required_external_authority`: the verifier's Phase 1 external authority checklist.
- `authority_evidence`: accepted customer, regulator, and insurer authority rows.
- `summary`: verifier-derived coverage and authority-kind counts.
- `controls`: verifier-derived authority controls.
- `limitations`: explicit limits for non-production modes.
- `dossier_id`: canonical content hash of the unsigned body.
- `signatures`: detached signatures over `{dossier_id, design_partner_authority}`.

## External Authority Checklist

The checklist is:

- `customer-paid-pilot-acceptance`: customer authority evidence for signed paid design partner pilots.
- `regulator-or-supervisor-scrutiny-survival`: regulator or supervisor authority evidence that a proof pack survived external scrutiny.
- `insurer-underwriting-review`: insurer authority evidence that proof-pack telemetry was consumed for risk review or pricing.

These authority kinds match the roadmap's Phase 1 exit criteria: paying design partners, proof-pack survival with an external party, and the insurer demand-generator wedge.

## Verification Rules

Verifiers must reject a dossier when:

- `dossier_id` does not match the canonical unsigned body.
- no signature verifies over `{dossier_id, design_partner_authority}`.
- mode, timestamps, references, or evidence rows are malformed.
- `pilot_source` does not match the supplied design-partner pilot dossier.
- the supplied design-partner pilot dossier does not verify.
- `required_external_authority`, `summary`, or `controls` do not match verifier recomputation.
- an authority row uses an unsupported requirement or authority kind.
- an authority row has a non-canonical `sha256:` evidence hash or mismatched `evidence_id`.
- an authority row is not bound to the source pilot dossier context.
- `require_complete` is set and any checklist item is uncovered.
- `require_fresh` is set and any authority row lacks a fresh `issued_at` / `expires_at` window.
- `mode` is `production-dossier` and the source pilot dossier does not prove Phase 1 exit metrics: at least three partners, at least `$250,000` evidence-bound signed pilot value, and at least one evidence-bound survived external scrutiny event.
- `mode` is `production-dossier` and any customer, regulator, or insurer checklist item is uncovered or stale.

## Chain Entry

Appending a verified dossier emits entry type `trustai.design_partner.production_authority.attested` with:

- dossier id, hash, refs, mode, and environment
- source pilot dossier id, ref, mode, partner count, signed value, and exit-readiness status
- authority evidence count
- covered and required checklist counts
- freshness counts
- control status summary

## CLI

```powershell
python -m trustai design-partner-authority artifacts/design-partner-pilot.json --root . --mode partner-dossier --environment aitrade-prod --dossier-ref dossier:design-partner-authority/phase1 --authority-ref authority:design-partner/phase1 --producer-ref oidc:trustai.example/design-partner-authority-worker --authority-evidence "customer-paid-pilot-acceptance,customer,customer:bank-a/paid-pilot-acceptance,sha256:0000000000000000000000000000000000000000000000000000000000000000,Customer acceptance and payment evidence.;issuer=Bank A;subject=TrustAI paid pilot;source_uri=https://customer.example/bank-a/pilot/acceptance;issued_at=2026-07-21T00:10:00Z;expires_at=2026-12-31T00:00:00Z" --out artifacts/design-partner-authority.json
python -m trustai design-partner-authority-verify artifacts/design-partner-authority.json artifacts/design-partner-pilot.json --root .
python -m trustai design-partner-authority-append artifacts/design-partner-authority.json artifacts/design-partner-pilot.json --root . --state .trustai/design-partner-authority/evidence-chain.json --tenant design-partner-authority --out artifacts/design-partner-authority-entry.json
```
