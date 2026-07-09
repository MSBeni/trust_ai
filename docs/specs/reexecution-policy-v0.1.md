# TrustAI Re-execution Policy v0.1

The re-execution policy binds repeated eval evidence to a risk-class-specific
minimum standard before the report can support promotion. It closes the gap
between "we ran the eval several times" and "we reran it under the frozen model,
runtime, prompt, tool manifest, seed, temperature, sample-size, and sandbox
constraints required for this risk class."

## Schema

`schema`: `trustai.reexecution-policy/0.1`

Required top-level fields:

- `id`: stable policy identifier.
- `version`: policy version.
- `risk_class`: contract agent risk class governed by this policy.
- `minimums`: minimum `run_count`, `records_per_run`, and
  `required_pass_rate`.
- `execution`: allowed methods, runners, seed policy, temperature ceiling, and
  whether seeds are mandatory.
- `pins`: frozen model, prompt hash, tool manifest hash, and runtime expected
  in every run's environment evidence.
- `sandbox`: required runner image, image digest, network mode, and read-only
  filesystem evidence.

## Evaluation Rules

Policy evaluation verifies:

- contract `agent.risk_class` matches the policy;
- run count and per-run holdout record counts meet the risk-class minimums;
- report execution method, seed policy, and required pass rate meet the policy;
- every run records a seed when `require_seed` is true;
- report and per-run temperature do not exceed `max_temperature`;
- contract freeze pins match policy pins;
- every run environment repeats the model, prompt hash, tool manifest hash, and
  runtime pins;
- every run uses an allowed runner;
- every run includes sandbox evidence matching the required image digest,
  network mode, and read-only filesystem setting.

The policy result is embedded in the re-execution report as `policy_result` and
is included in the canonical `report_id`. Any change to a pin, sandbox setting,
sample count, or policy result invalidates offline verification.

## CLI

```bash
python -m trustai reexecution-runner-run examples/aitrade/reexecution-runner-plan.json --contract examples/aitrade/verification-contract.yaml --state .trustai/runner-demo/evidence-chain.json --tenant runner-local --out artifacts/reexecution-runner-evidence.json
python -m trustai reexecution-runner-verify artifacts/reexecution-runner-evidence.json
python -m trustai reexecution-policy-verify examples/aitrade/reexecution-policy.json examples/aitrade/verification-contract.yaml artifacts/runner-runs/eval-results-runner-1.json artifacts/runner-runs/eval-results-runner-2.json artifacts/runner-runs/eval-results-runner-3.json --temperature 0
python -m trustai reexecution-report examples/aitrade/verification-contract.yaml artifacts/runner-runs/eval-results-runner-1.json artifacts/runner-runs/eval-results-runner-2.json artifacts/runner-runs/eval-results-runner-3.json --policy examples/aitrade/reexecution-policy.json --temperature 0
```

## Production Boundary

This v0.1 policy verifies recorded runner evidence. Production deployments still
need an actual sandbox runner service that produces these environment fields,
attests runner image digests from a trusted build pipeline, and enforces network
and filesystem isolation rather than merely checking recorded evidence.
