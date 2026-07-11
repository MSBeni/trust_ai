# Regulator Disclosure Package v0.1

The regulator disclosure package is a selective-disclosure artifact for
supervisors, regulators, and external examiners. It reveals specific evidence
chain entries and Merkle inclusion proofs without exposing the entire tenant log.

## Schema

`schema`: `trustai.regulator-disclosure/0.1`

Top-level fields:

- `disclosure_id`: canonical hash of the disclosure body.
- `issued_at`: disclosure timestamp.
- `audience`: intended reviewer or supervisory body.
- `purpose`: review purpose, for example EU AI Act Annex III technical
  documentation.
- `selection`: disclosure criteria and counts.
- `source_proof_pack`: summary of the proof pack that motivated the disclosure.
- `chain`: selected chain entries and inclusion proofs against the current chain
  root.
- `signatures`: detached signature over `disclosure_id` and disclosure body.

## Source Proof Pack Summary

The package intentionally does not embed the full proof pack by default. It
includes only:

- proof pack id and spec version.
- issued timestamp.
- contract id and hash.
- agent metadata.
- gate outcome.
- canonical hash of the gate decision.
- proof-pack chain tree at pack issue time.

This keeps the disclosure narrow while still tying the regulator package back to
the promotion artifact under examination.

## Chain Disclosure

The `chain` object contains:

- `tenant_id`.
- current chain `tree`.
- selected signed chain entries.
- inclusion proofs keyed by entry id.

Default disclosed entry types:

- `verification_contract.registered`
- `eval.completed`
- `promotion_gate.decided`
- `runtime.attested`
- `shadow_replay.completed`
- `soak_report.completed`
- `policy.decision`
- `incident.recorded`
- `promotion_gate.demoted`
- `promotion_gate.rolled_back`
- `chain.anchor.published`

The package can also include specific entry ids in addition to the selected
types.

## Verification

An offline verifier checks:

- disclosure schema.
- disclosure id canonical hash.
- disclosure signature.
- each disclosed chain entry signature and timestamp token.
- each disclosed entry payload hash.
- each disclosed entry Merkle inclusion proof against the disclosed tree root.
- packed disclosure tree-header shape and size consistency.
- source proof-pack summary consistency with the disclosed contract, eval, and
  gate entries, including contract hash/id, agent, gate outcome, gate decision
  hash, and pack-time tree size.
- selection count consistency.

The verifier does not need access to undisclosed entries. Inclusion proofs reveal
that a disclosed entry is part of the current tree root while preserving the
rest of the log.

## Regulator View

`trustai regulator-view` verifies a disclosure package and renders a static HTML
artifact with disclosure scope, source proof-pack metadata, verification
messages, the chain root, and every disclosed entry id and payload hash. It is a
local supervised-access stand-in, not a credentialed portal.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai regulator-export artifacts/aitrade-proof-pack.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local --out artifacts/regulator-disclosure.json
python -m trustai regulator-verify artifacts/regulator-disclosure.json
python -m trustai regulator-view artifacts/regulator-disclosure.json --out artifacts/regulator-view.html
```
