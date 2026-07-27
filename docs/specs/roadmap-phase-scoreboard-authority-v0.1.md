# Roadmap Phase Scoreboard Production Authority Dossier v0.1

## Purpose

The roadmap phase scoreboard records P1-P4 exit criteria as signed, hash-bound milestone evidence. A roadmap phase scoreboard production authority dossier records the external authority needed before the scoreboard can be treated as production-complete: CI/source audit evidence, regulator acceptance, insurer pricing, standards-track progress, and customer/procurement market acceptance.

The dossier stores references, hashes, source URIs, and freshness windows. It does not store raw contracts, ARR ledgers, regulator correspondence, insurer pricing files, standards-body filings, customer procurement files, or private proof packs.

## Schema

Schema ID: `trustai.roadmap-phase-scoreboard-production-authority-dossier/0.1`

Required top-level fields:

- `schema`: the schema ID.
- `mode`: `local-dossier`, `scoreboard-dossier`, or `production-dossier`.
- `environment`: environment or operating scope.
- `generated_at`: RFC 3339 timestamp.
- `dossier_ref`: stable dossier reference.
- `authority_ref`: external authority reference.
- `producer_ref`: worker, person, or identity that produced the dossier.
- `scoreboard_source`: canonical binding to a verified `trustai.roadmap-phase-scoreboard/0.1` scoreboard.
- `required_external_authority`: the verifier's roadmap scoreboard external authority checklist.
- `authority_evidence`: accepted CI, regulator, insurer, standards-body, and customer authority rows.
- `summary`: verifier-derived coverage and authority-kind counts.
- `controls`: verifier-derived authority controls.
- `limitations`: explicit limits for non-production modes.
- `dossier_id`: canonical content hash of the unsigned body.
- `signatures`: detached signatures over `{dossier_id, phase_scoreboard_authority}`.

## External Authority Checklist

The checklist is:

- `ci-scoreboard-source-audit`: CI authority evidence that roadmap scoreboard sources and retained artifacts were audited.
- `regulator-phase-acceptance`: regulator or supervisor authority evidence for accepted proof-pack or phase evidence.
- `insurer-phase-pricing-acceptance`: insurer authority evidence for pricing or underwriting on proof-pack-backed agents.
- `standards-track-recognition`: standards-body authority evidence for proof-pack spec standards-track progress.
- `customer-procurement-market-acceptance`: customer authority evidence for procurement clauses, paying customers, or market acceptance.

These authority kinds match the roadmap's P1-P4 definition of done and the unicorn-logic ratchet: business traction, regulator acceptance, insurer pricing, standards adoption, and procurement pull.

## Verification Rules

Verifiers must reject a dossier when:

- `dossier_id` does not match the canonical unsigned body.
- no signature verifies over `{dossier_id, phase_scoreboard_authority}`.
- mode, timestamps, references, or evidence rows are malformed.
- `scoreboard_source` does not match the supplied roadmap phase scoreboard.
- the supplied roadmap phase scoreboard does not verify.
- `required_external_authority`, `summary`, or `controls` do not match verifier recomputation.
- an authority row uses an unsupported requirement or authority kind.
- an authority row has a non-canonical `sha256:` evidence hash or mismatched `evidence_id`.
- an authority row is not bound to the source scoreboard context.
- `require_complete` is set and any checklist item is uncovered.
- `require_fresh` is set and any authority row lacks a fresh `issued_at` / `expires_at` window.
- `mode` is `production-dossier` and the source scoreboard is not an `external-evidence` scoreboard with all phase controls passed.
- `mode` is `production-dossier` and any CI, regulator, insurer, standards-body, or customer checklist item is uncovered or stale.

## Chain Entry

Appending a verified dossier emits entry type `trustai.roadmap_phase_scoreboard.production_authority.attested` with:

- dossier id, hash, refs, mode, and environment
- source scoreboard id, ref, mode, milestone count, and exit-readiness status
- authority evidence count
- covered and required checklist counts
- freshness counts
- control status summary

## CLI

```powershell
python -m trustai phase-scoreboard-authority artifacts/phase-scoreboard.json --root . --mode scoreboard-dossier --environment aitrade-prod --dossier-ref dossier:phase-scoreboard-authority/roadmap --authority-ref authority:phase-scoreboard/roadmap --producer-ref oidc:trustai.example/phase-scoreboard-authority-worker --authority-evidence "ci-scoreboard-source-audit,ci-run,ci:github-actions/roadmap-scoreboard-retained-evidence,sha256:0000000000000000000000000000000000000000000000000000000000000000,CI run evidence for retained artifact verification.;issuer=GitHub Actions;subject=roadmap phase scoreboard retained evidence;source_uri=https://github.com/MSBeni/trust_ai/actions;issued_at=2029-07-01T00:00:00Z;expires_at=2029-12-31T00:00:00Z" --out artifacts/phase-scoreboard-authority.json
python -m trustai phase-scoreboard-authority-verify artifacts/phase-scoreboard-authority.json artifacts/phase-scoreboard.json --root .
python -m trustai phase-scoreboard-authority-append artifacts/phase-scoreboard-authority.json artifacts/phase-scoreboard.json --root . --state .trustai/phase-scoreboard-authority/evidence-chain.json --tenant phase-scoreboard-authority --out artifacts/phase-scoreboard-authority-entry.json
```
