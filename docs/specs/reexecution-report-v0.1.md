# TrustAI Re-execution Report v0.1

The re-execution report records repeated evaluation runs for a frozen agent
version. It is used when deterministic replay is possible or when agent
nondeterminism requires distributional evidence instead of a single-point score.

The report does not claim nondeterminism has been eliminated. It records the
observed run distribution, worst-case threshold checks, pass rates, and
confidence intervals so auditors can see the spread explicitly.

## Schema

`schema`: `trustai.reexecution-report/0.1`

Required top-level fields:

- `report_id`: canonical hash of the report body.
- `generated_at`: creation timestamp.
- `contract`: verification contract id, hash, agent, and embedded body.
- `execution`: method, seed policy, temperature, run count, and required pass
  rate.
- `source_runs`: embedded eval results, per-run hashes, metrics, holdout
  outcomes, and recomputed gate decisions.
- `metric_distributions`: per-contract-metric distribution summaries.
- `policy`: optional embedded `trustai.reexecution-policy/0.1` body and hash.
- `policy_result`: optional risk-class policy evaluation result for model/runtime
  pins, seeds, temperature, sample-size, and sandbox evidence.
- `overall`: pass/fail outcome across repeated runs.
- `limitations`: explicit nondeterminism caveats.

## Metric Distribution Rules

For each metric in the verification contract, the report records:

- observed values;
- mean, min, max, and sample standard deviation;
- 95% normal-approximation interval for the mean;
- pass count and pass rate;
- Wilson 95% interval for the pass rate;
- worst observed value according to the metric operator;
- whether the worst observed value satisfies the threshold;
- whether the metric satisfies the required pass rate.

The overall report passes only when all embedded runs pass the normal gate
decision, all holdout checks pass, every metric distribution passes, and any
embedded re-execution policy result passes.

## Evidence Chain

`trustai reexecution-report` appends a `reexecution.completed` entry to the
evidence chain. Because the entry contains the contract hash, later proof packs
for the same contract include the distributional evidence entry automatically.

## CLI

```bash
python -m trustai reexecution-runner-run examples/aitrade/reexecution-runner-plan.json --contract examples/aitrade/verification-contract.yaml --state .trustai/runner-demo/evidence-chain.json --tenant runner-local --out artifacts/reexecution-runner-evidence.json
python -m trustai reexecution-runner-verify artifacts/reexecution-runner-evidence.json
python -m trustai reexecution-policy-verify examples/aitrade/reexecution-policy.json examples/aitrade/verification-contract.yaml artifacts/runner-runs/eval-results-runner-1.json artifacts/runner-runs/eval-results-runner-2.json artifacts/runner-runs/eval-results-runner-3.json --temperature 0
python -m trustai reexecution-report examples/aitrade/verification-contract.yaml artifacts/runner-runs/eval-results-runner-1.json artifacts/runner-runs/eval-results-runner-2.json artifacts/runner-runs/eval-results-runner-3.json --state .trustai/demo/evidence-chain.json --tenant aitrade-local --out artifacts/reexecution-report.json --markdown artifacts/reexecution-report.md --temperature 0 --policy examples/aitrade/reexecution-policy.json
python -m trustai reexecution-verify artifacts/reexecution-report.json
```

## Production Boundary

This v0.1 artifact verifies repeated eval outputs, distribution summaries,
policy-bound model/runtime pins, seed and temperature evidence, sample-size
minimums, and recorded sandbox runner evidence. Production re-execution still
needs:

- actual sandboxed runner orchestration that produces the recorded evidence;
- independent seed and temperature controls enforced by the runner service;
- trusted build provenance for runner images and tool manifests;
- customer-specific sample-size policies beyond the bundled local example;
- external reviewer guidance for interpreting confidence intervals.
