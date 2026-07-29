# Runtime Policy and Lifecycle Evidence v0.1

Runtime proof is not a permanent certificate. A proof pack can be valid
cryptographically while becoming operationally stale. TrustAI models that with
policy packs, proof-decay checks, and signed lifecycle entries for incidents,
demotions, and rollbacks.

## Policy Pack

A policy pack is a JSON document with `spec_version:
trustai.policy-pack/0.1`.

Required fields:

- `id`: stable policy pack identifier.
- `version`: policy pack version.
- `proof_decay`: freshness limits for evidence in a proof pack.
- `rules`: ordered runtime action rules.

Supported proof-decay keys:

- `max_gate_age_hours`: maximum age of the promotion gate decision.
- `max_soak_age_hours`: maximum age of `soak_report.completed` evidence.
- `max_runtime_attestation_age_hours`: maximum age of `runtime.attested`
  evidence.
- `max_shadow_replay_age_hours`: maximum age of `shadow_replay.completed`
  evidence.

Supported rule effects:

- `deny`: fail the policy decision when the rule matches.
- `require_approval`: require an approval object on the action. If
  `approval_role` is set, an approval with that role is required.
- `allow`: record a matching allow rule without overriding failed decay checks
  or denies.

Runtime action approval checks inspect the action payload. Promotion or gate
sign-offs should be appended as `human_approval.granted` entries using
`trustai approve`; see `docs/specs/human-approval-v0.1.md`.

Conditions use the same comparison operator vocabulary as gate metric checks and
resolve dotted fields against the evaluation context:

- `action`: the runtime action payload.
- `proof`: the proof pack.
- `policy`: the policy pack.

Example:

```json
{
  "field": "action.notional_usd",
  "operator": ">",
  "value": 5000
}
```

## Policy Decision Entry

`trustai policy-check` verifies the referenced proof pack, evaluates proof
freshness and action rules, then appends `policy.decision` to the evidence
chain.

The decision payload includes:

- policy pack id, version, hash, and embedded policy pack body.
- action hash.
- contract hash derived from the proof pack or action.
- `evaluated_at`.
- `passed` and `outcome`.
- freshness checks and matched rules.
- the action payload used for evaluation.

When a `policy.decision` entry is included in a proof pack, offline verifiers
recompute the decision from the embedded policy pack, embedded action, and
packed proof body. Missing policy pack bodies, policy pack hash/id/version
mismatches, stale proof freshness, rule-result mismatches, or outcome tampering
fail verification even when the chain entry and proof pack signatures are valid.

Missing proof packs fail closed. Proof packs must carry an active promotion gate
decision with outcome `passed`; failed, missing, or malformed gate decisions fail
before age-based checks. Missing, malformed, or stale gate, soak, runtime
attestation, or shadow replay timestamps also fail closed when the policy pack
defines the corresponding decay limit.

## Policy Backend Exports

`trustai policy-export` writes a portable policy-backend artifact for the same
policy pack. The export includes:

- `targets.opa_rego`: a Rego module with proof freshness, deny rules, and
  approval requirements. Callers provide the active gate outcome under
  `input.proof.gate_outcome` and precomputed proof ages under
  `input.proof.age_hours`.
- `targets.cedar`: a Cedar-shaped JSON policy set for review or production
  translation. Helper functions such as `hasApproval(role)` are intentionally
  explicit deployment hooks.

The local reference implementation does not embed OPA or Cedar runtimes. It
keeps local policy decisions deterministic while making the production backend
contract inspectable.

## Policy Engine Decision Receipts

`trustai policy-engine-receipt` signs a verifiable bridge between the local
policy decision, the proof pack, the runtime action, and the exported OPA/Rego
or Cedar-shaped backend artifact. The receipt schema is
`trustai.policy-engine-receipt/0.1`; see
`docs/specs/policy-engine-receipt-v0.1.md`.

`trustai policy-engine-verify` re-checks the receipt signature, source hashes,
and supplied policy decision replay from the policy pack, action, proof pack,
active gate outcome, and proof-decay timestamps. `trustai policy-engine-append`
appends `policy_engine.evaluated` after the receipt and all supplied source
artifacts verify.

## Lifecycle Entries

Incidents, demotions, and rollbacks are part of the same audit trail as
promotion evidence.

`incident.recorded` contains:

- incident hash.
- optional contract hash.
- affected agent metadata.
- incident body.

`promotion_gate.demoted` contains:

- contract id and hash.
- agent metadata.
- source and target environments.
- reason.
- optional triggering evidence entry id.

`promotion_gate.rolled_back` contains:

- contract id and hash.
- agent metadata.
- target agent version.
- reason.
- optional triggering evidence entry id.

All lifecycle entries are signed, timestamped, and Merkle-includable in the same
evidence chain as the original contract and gate decision.
