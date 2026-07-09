# Framework Hook Release v0.1

A framework hook release receipt is a signed artifact for TrustAI's
framework-neutral native hook shims. It narrows the claim from "the adapter can
map exported JSON" to "this hook package and entrypoint are bound to a specific
framework runtime row, checked-in source artifacts, and replayed fixture event
chains."

The receipt does not import or orchestrate agent frameworks. The local reference
hook package is dependency-free: native integrations can call the hook entrypoint
with a framework-native payload, and the hook emits the same normalized adapter
events used by `framework-ingest`.

## Artifact

A release uses schema `trustai.framework-hook-release/0.1` and contains:

- `release_ref` and `released_at`;
- `source_spec` hash for this spec;
- a signed adapter matrix binding with `matrix_id`, `matrix_hash`, matrix ref,
  and issue timestamp;
- one row per framework/runtime/hook package;
- a summary of frameworks, modes, statuses, and rows;
- detached signatures over the canonical release body.

Each row records:

- framework name and aliases;
- runtime package, runtime version, and release channel;
- hook package, hook version, mode, module ref, entrypoint ref, and collector
  hook ref;
- release status;
- adapter matrix compatibility hash and normalized event root;
- replayed trace fixture event count, event names, per-trace roots, and event
  chain verification flag;
- checked-in source artifact hashes and source artifact root;
- release/evidence/audit references and control statuses.

## Verification

`framework-hook-release-verify` recalculates the release ID, verifies at least
one signature, validates the source spec and source artifact hashes, verifies the
adapter matrix when supplied, replays each bound fixture through the adapter
code, and checks event names, event counts, per-trace roots, event chains,
compatibility hashes, and normalized event roots.

Any source edit, matrix edit, fixture edit, row edit, event omission, event
reordering, or summary edit breaks verification.

Rows marked `reference-release` prove only local package metadata and fixture
compatibility. `native-hook-tested` and `production-certified` require native
framework runtime tests, collector service evidence, and provider/runtime audit
logs appropriate to the claimed status.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-adapter-matrix examples/aitrade/framework-adapter-matrix.json --root . --out artifacts/framework-adapter-matrix.json
python -m trustai framework-hook-release examples/aitrade/framework-hook-release.json artifacts/framework-adapter-matrix.json --root . --out artifacts/framework-hook-release.json
python -m trustai framework-hook-release-verify artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-hook-release-append artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-hook-demo/evidence-chain.json --tenant framework-hook-local --out artifacts/framework-hook-release-entry.json
```