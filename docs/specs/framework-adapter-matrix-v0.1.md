# Framework Adapter Matrix v0.1

The framework adapter matrix is a signed compatibility receipt for TrustAI's
framework-neutral adapters. It answers a narrower question than trace ingest:
which framework/runtime versions were mapped, which fixture proved the mapping,
and which event types the adapter produced.

## Artifact

A matrix uses schema `trustai.framework-adapter-matrix/0.1` and contains:

- `matrix_ref` and `issued_at`;
- `adapter_schema_url` and `adapter_package_version`;
- `source_spec` hash for the adapter spec;
- one row per framework/runtime version;
- a summary of frameworks, rows, hook modes, statuses, and fixture event count;
- detached signatures over the canonical matrix body.

Each row records:

- framework name and aliases;
- runtime package, version range, and release channel;
- adapter version, hook mode, and emitted schema URL;
- compatibility status;
- tested timestamp;
- checked-in trace fixture path, SHA-256, event names, event count, and
  normalized event root;
- replayed per-trace adapter event-chain fields, including source trace hash,
  event sequence, event count, previous event node hash, and trace root;
- required event names that must be emitted by replaying the fixture;
- evidence references and row-level control statuses.

## Verification

`framework-adapter-matrix-verify` recalculates the matrix ID, verifies at least
one signature, validates the source spec and fixture hashes, replays each trace
fixture through the adapter code, and checks the resulting event names, event
count, per-trace event chain, and normalized event root. Any fixture edit, row
edit, event omission, event reordering, or matrix summary edit breaks
verification.

Rows marked `verified-reference` prove local fixture compatibility only. Native
hook or production-certified claims require release, deployment, and runtime
provider evidence in addition to this local receipt.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-adapter-matrix examples/aitrade/framework-adapter-matrix.json --root . --out artifacts/framework-adapter-matrix.json
python -m trustai framework-adapter-matrix-verify artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-adapter-matrix-append artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-demo/evidence-chain.json --tenant framework-local --out artifacts/framework-adapter-matrix-entry.json
```
