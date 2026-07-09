# TrustAI Re-execution Runner Evidence v0.1

The re-execution runner plan records how repeated eval outputs were produced
for a frozen agent version. It complements the re-execution report: the runner
evidence proves that a declared command was executed with fixed run IDs, seeds,
output paths, and a policy body; the report then evaluates those outputs against
the verification contract and re-execution policy.

## Plan Schema

`schema`: `trustai.reexecution-runner-plan/0.1`

Required fields:

- `id`: stable plan identifier.
- `version`: plan version.
- `command`: argv list executed with shell disabled. `{python}` expands to the
  current Python interpreter for portable local examples.
- `timeout_seconds`: per-run timeout.
- `policy`: embedded `trustai.reexecution-policy/0.1` body.
- `runs`: non-empty list of run IDs, seeds, and output paths.

The local runner rejects shell execution and duplicate output paths.

## Evidence Schema

`schema`: `trustai.reexecution-runner-evidence/0.1`

Evidence includes:

- `evidence_id`: canonical hash of the evidence body.
- `generated_at`: evidence creation time.
- `plan`: plan ID, version, hash, and embedded body.
- `runs`: per-run command, seed, exit code, stdout/stderr hashes, output JSON
  hash, embedded eval results, and `run_hash`.
- `outcome`: `passed` only when every command exits with `0` and emits valid
  eval-results JSON.
- `limitations`: local-runner caveats.

`trustai reexecution-runner-run` appends a `reexecution.runner.completed` entry
to the evidence chain. The entry includes the evidence hash, plan hash, run
count, output paths, and result hashes.

## CLI

```bash
python -m trustai reexecution-runner-run examples/aitrade/reexecution-runner-plan.json --contract examples/aitrade/verification-contract.yaml --state .trustai/runner-demo/evidence-chain.json --tenant runner-local --out artifacts/reexecution-runner-evidence.json
python -m trustai reexecution-runner-verify artifacts/reexecution-runner-evidence.json
python -m trustai reexecution-report examples/aitrade/verification-contract.yaml artifacts/runner-runs/eval-results-runner-1.json artifacts/runner-runs/eval-results-runner-2.json artifacts/runner-runs/eval-results-runner-3.json --policy examples/aitrade/reexecution-policy.json --temperature 0
```

## Production Boundary

The v0.1 local runner executes with `shell=False`, records command/output hashes,
and verifies declared sandbox evidence. It does not provide kernel, container,
network, or filesystem isolation. Production deployments still need a hardened
runner service that enforces those controls and emits attested runner-image and
tool-manifest provenance.
