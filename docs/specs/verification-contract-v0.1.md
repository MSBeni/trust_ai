# Verification Contract DSL v0.1

A Verification Contract is the pre-registered promise that binds an agent
version to fixed success criteria before evaluation starts. Its canonical
SHA-256 hash is committed to the evidence chain when registered.

The MVP accepts JSON, or YAML when `PyYAML` is available. The bundled examples
use JSON syntax in a `.yaml` file, which is valid YAML and keeps the project
self-contained.

## Required Fields

```json
{
  "spec_version": "trustai.verification-contract/0.1",
  "id": "aitrade-btcusdt-canary",
  "version": "0.1.0",
  "agent": {
    "name": "aitrade-risk-agent",
    "version": "sha256:agent-version-hash",
    "risk_class": "trading-prod-write"
  },
  "freeze": {
    "frozen_at": "2026-07-01T00:00:00Z",
    "model": "gpt-5-mini",
    "prompt_hash": "sha256:prompt-hash",
    "tool_manifest_hash": "sha256:tool-manifest-hash"
  },
  "holdout": {
    "min_timestamp": "2026-07-02T00:00:00Z",
    "require_post_freeze": true,
    "soak_duration_hours": 24
  },
  "metrics": [
    {
      "name": "trade_policy_compliance_rate",
      "operator": ">=",
      "threshold": 0.99,
      "source": "eval_results"
    }
  ],
  "required_approvals": [
    {
      "role": "model_risk",
      "description": "Model risk owner approval"
    }
  ]
}
```

## Semantics

- `agent.version` is content-addressed and represents model, prompts, tools, and
  config for the candidate agent version.
- `freeze.frozen_at` is the time boundary after which holdout data must occur.
- `holdout.min_timestamp` is the earliest allowed evaluation record timestamp.
- each metric is evaluated against `eval_results.metrics[metric.name]`;
- supported operators are `>=`, `>`, `<=`, `<`, `==`, and `!=`;
- each required approval role must appear either in `eval_results.approvals[]`
  or in signed `human_approval.granted` evidence entries for the contract;
- chain-backed approval entries are preferred for adversarial verification
  because they are separately signed, timestamped, and Merkle-includable.

The registered contract hash is immutable evidence. If the contract changes by a
single byte after registration, proof-pack verification fails.
