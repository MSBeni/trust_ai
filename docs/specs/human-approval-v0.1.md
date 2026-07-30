# Human Approval Evidence v0.1

Human approvals are first-class evidence-chain entries. They let a promotion
gate prove that required sign-offs existed before the gate decision without
trusting mutable eval-result JSON.

## Approval Object

```json
{
  "role": "model_risk",
  "approver": "model-risk@example.com",
  "approved_at": "2026-07-03T13:00:00Z",
  "source": "slack",
  "external_ref": "slack://trustai-approvals/C07MODEL/1720011600.000100",
  "reason": "Validation scope and holdout evidence reviewed."
}
```

Required fields are `role`, `approver`, and `approved_at`. The timestamp must be
RFC3339-compatible. `source`, `external_ref`, and `reason` are optional metadata
for Slack request payloads, ticketing, GRC, or change-management integrations.

## Evidence Entry

`trustai approve` appends a signed `human_approval.granted` chain entry:

```powershell
$env:PYTHONPATH = "src"
python -m trustai approve examples/aitrade/verification-contract.yaml examples/aitrade/approval-model-risk.json --state .trustai/approval-demo/evidence-chain.json --tenant approval-local
```

The entry payload includes:

- `contract_id`
- `contract_hash`
- `agent`
- `approval_hash`
- `approval`

The entry timestamp is the approval's `approved_at` time.

## Gate Semantics

Promotion gates accept approvals from two sources:

- legacy `results.approvals[]` values in eval-result JSON;
- signed `human_approval.granted` entries already present in the evidence chain.

When approval evidence entries are present, the gate decision records the
matching `approval_entry_id` values. Proof packs include those entries because
they carry the contract hash, and the offline verifier recomputes the gate
decision using the packed approval entries. Removing or tampering with those
entries invalidates the proof pack.

## Verified Callback Flow

Slack approval request artifacts can also be converted into signed callback
artifacts before becoming chain evidence:

```powershell
$env:PYTHONPATH = "src"
python -m trustai slack-approval-request artifacts/approval-backed-proof-pack.json --channel C07TRUSTAI --requested-roles model_risk --callback-url https://example.test/trustai/approval-callbacks --promotion-payload artifacts/trustai-ci-payload.json --out artifacts/slack-approval-request.json
python -m trustai approval-callback-build artifacts/slack-approval-request.json model_risk --approver model-risk@example.com --approved-at 2026-07-03T13:00:00Z --reason "Approved via verified callback artifact." --out artifacts/approval-callback-model-risk.json
python -m trustai approval-callback-verify artifacts/slack-approval-request.json artifacts/approval-callback-model-risk.json
python -m trustai approval-callback-append examples/aitrade/verification-contract.yaml artifacts/slack-approval-request.json artifacts/approval-callback-model-risk.json --state .trustai/approval-callback-demo/evidence-chain.json --tenant approval-callback-local --auto-register --out artifacts/approval-callback-model-risk-entry.json
```

Callback verification binds the provider action id and action value to the
original request, confirms the request payload hash, verifies the callback
signature, rejects provider-target replay when the request includes a
GitHub/GitLab promotion binding, and rejects approvals after request expiry
when `expires_at` is set.
The local server can also store pending Slack requests at
`POST /v0/approval-requests/slack` and accept Slack-style interaction payloads
at `POST /v0/approval-callbacks/slack`, validate Slack request signatures and
replay windows when configured, resolve payload-only callbacks from storage,
build the signed callback, verify it, and append the resulting
`human_approval.granted` entry to the configured chain.
## Demo Flow

```powershell
$env:PYTHONPATH = "src"
python -m trustai register examples/aitrade/verification-contract.yaml --state .trustai/approval-demo/evidence-chain.json --tenant approval-local
python -m trustai approve examples/aitrade/verification-contract.yaml examples/aitrade/approval-model-risk.json --state .trustai/approval-demo/evidence-chain.json --tenant approval-local --out artifacts/approval-model-risk-entry.json
python -m trustai approve examples/aitrade/verification-contract.yaml examples/aitrade/approval-trading-ops.json --state .trustai/approval-demo/evidence-chain.json --tenant approval-local --out artifacts/approval-trading-ops-entry.json
python -m trustai gate examples/aitrade/verification-contract.yaml examples/aitrade/eval-results-chain-approvals.json --state .trustai/approval-demo/evidence-chain.json --tenant approval-local --out artifacts/approval-backed-proof-pack.json --pdf artifacts/approval-backed-proof-pack.pdf
python -m trustai verify artifacts/approval-backed-proof-pack.json
```

`examples/aitrade/eval-results-chain-approvals.json` intentionally omits
embedded approval values so the pass depends on signed chain evidence.
