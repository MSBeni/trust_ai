# Temporal Holdout Manifest v0.1

A temporal holdout manifest is a signed proof that a shadow replay dataset was
checked against the verification contract's frozen version boundary before being
used as promotion evidence.

## Artifact

The manifest uses schema `trustai.temporal-holdout-manifest/0.1` and records:

- contract ID, contract hash, freeze timestamp, and holdout minimum timestamp;
- replay run ID, dataset ID, candidate version, replay payload hash, and optional retained replay source artifact byte binding;
- first, last, earliest, and latest replay record timestamps;
- `dataset_fingerprint`, a canonical dataset-level fingerprint over dataset ID, replay run ID, candidate version, record count, records root, root kind, and timestamp bounds, plus any replay-declared fingerprint match status;
- `outcome_summary`, a verifier-recomputed behavioral summary over held-out replay records, including action comparison counts, action-comparison hash root, mismatch record IDs, policy-violation counts, latency percentiles, and position-error bounds;
- a hash-chained record list with sequence, unique record ID, timestamp, record
  hash, previous node hash, and node hash;
- a `records_root` equal to the final record node hash;
- explicit temporal boundary violations and pass/fail status;
- detached signatures over the canonical manifest body.

The per-record node hash uses schema
`trustai.temporal-holdout-record-chain/0.1` and binds sequence number, total
record count, record ID, timestamp, canonical record hash, and previous node
hash. Reordering, truncating, inserting, or editing replay records changes the
root and therefore the dataset fingerprint. Relabeling the dataset ID, replay run,
or candidate version also changes the fingerprint.

## Verification

`temporal-holdout-verify` recalculates the manifest ID, verifies at least one
signature, checks the internal record hash chain, recomputes duplicate record-id and
boundary violations from the frozen contract timestamps, recomputes the dataset fingerprint,
rejects replay-declared fingerprint mismatches, recomputes the behavioral `outcome_summary`
from the supplied replay, and optionally replays the source contract, replay JSON, and
retained replay source bytes to catch source tampering. When
`replay_source_artifact` is present, verification requires the source replay path so the
SHA-256 bytes, canonical content hash, replay hash, record count, record hash root, and
per-record manifest hashes can be recomputed from the retained source file even when the
caller does not separately pass a parsed replay object.

The manifest proves the supplied replay records postdate the freeze and holdout
minimum and binds the candidate behavior observed on those held-out records when the replay
source is supplied. A `traffic-holdout-export` receipt can separately bind production
traffic source refs, extraction windows, replay record hashes, and privacy limits.
A `traffic-completeness` receipt can replay provider stream/audit exports for the supplied window. Neither artifact proves upstream production traffic completeness without
collector or provider-owned production export evidence.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai temporal-holdout-manifest examples/aitrade/verification-contract.yaml examples/aitrade/shadow-replay.json --out artifacts/temporal-holdout-manifest.json
python -m trustai temporal-holdout-verify artifacts/temporal-holdout-manifest.json --contract examples/aitrade/verification-contract.yaml --replay examples/aitrade/shadow-replay.json
python -m trustai temporal-holdout-append artifacts/temporal-holdout-manifest.json --contract examples/aitrade/verification-contract.yaml --replay examples/aitrade/shadow-replay.json --state .trustai/holdout-demo/evidence-chain.json --tenant holdout-local --out artifacts/temporal-holdout-entry.json
```
