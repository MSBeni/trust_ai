# Temporal Holdout Manifest v0.1

A temporal holdout manifest is a signed proof that a shadow replay dataset was
checked against the verification contract's frozen version boundary before being
used as promotion evidence.

## Artifact

The manifest uses schema `trustai.temporal-holdout-manifest/0.1` and records:

- contract ID, contract hash, freeze timestamp, and holdout minimum timestamp;
- replay run ID, dataset ID, candidate version, and replay payload hash;
- first, last, earliest, and latest replay record timestamps;
- a hash-chained record list with sequence, record ID, timestamp, record hash,
  previous node hash, and node hash;
- a `records_root` equal to the final record node hash;
- explicit temporal boundary violations and pass/fail status;
- detached signatures over the canonical manifest body.

The per-record node hash uses schema
`trustai.temporal-holdout-record-chain/0.1` and binds sequence number, total
record count, record ID, timestamp, canonical record hash, and previous node
hash. Reordering, truncating, inserting, or editing replay records changes the
root.

## Verification

`temporal-holdout-verify` recalculates the manifest ID, verifies at least one
signature, checks the internal record hash chain, recomputes boundary flags and
violations from the frozen contract timestamps, and optionally replays the source
contract and replay JSON to catch source tampering.

The manifest proves the supplied replay records postdate the freeze and holdout
minimum. It does not prove the production traffic export is complete without
collector or provider-owned production export evidence.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai temporal-holdout-manifest examples/aitrade/verification-contract.yaml examples/aitrade/shadow-replay.json --out artifacts/temporal-holdout-manifest.json
python -m trustai temporal-holdout-verify artifacts/temporal-holdout-manifest.json --contract examples/aitrade/verification-contract.yaml --replay examples/aitrade/shadow-replay.json
python -m trustai temporal-holdout-append artifacts/temporal-holdout-manifest.json --contract examples/aitrade/verification-contract.yaml --replay examples/aitrade/shadow-replay.json --state .trustai/holdout-demo/evidence-chain.json --tenant holdout-local --out artifacts/temporal-holdout-entry.json
```
