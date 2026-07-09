# Approval Callback v0.1

Approval callbacks convert provider button clicks, such as Slack Block Kit
actions, into signed TrustAI approval artifacts. A verifier can prove that the
callback matches the generated approval request before appending it as
`human_approval.granted` evidence.

## Schema

`schema`: `trustai.approval-callback/0.1`

Required fields:

- `callback_id`: canonical hash of the callback body without `callback_id` and
  `signatures`.
- `provider`: approval provider. The local reference implementation supports
  `slack` request artifacts.
- `approval_request_id`: generated request id from the approval request.
- `request_payload_hash`: canonical hash of the approval request without its
  embedded `payload_hash`.
- `pack_id`, `contract_id`, `contract_hash`: proof-pack and contract binding.
- `channel`: provider channel or destination.
- `role`: required approval role being granted.
- `action_id`, `action_value`: provider action binding for the role.
- `approver`: human or service principal granting the approval.
- `approved_at`: RFC3339 approval timestamp.
- `signatures`: one or more detached local signatures over the callback id and
  callback body.

Optional fields include `reason`, `external_user_id`, and `team_id`.

## Verification Rules

`trustai approval-callback-verify` checks:

- the request is a valid `trustai.slack-approval-request/0.1` artifact;
- the request `payload_hash` still matches the request body;
- the callback id matches the canonical callback body;
- at least one callback signature verifies;
- provider, request id, request hash, pack id, contract id, contract hash, and
  channel match the approval request;
- the callback role is in `requested_roles`;
- `action_id` and `action_value` match the generated button binding for the
  role;
- `approved_at` is valid and not after request expiry when `expires_at` is set.

`trustai approval-callback-append` re-runs verification and appends a signed
`human_approval.granted` entry whose approval source is `{provider}-callback`.
The appended approval metadata includes the callback id, request hash, action
id, action value, and provider user/team identifiers when present.

## Local HTTP Endpoint

The reference server exposes `POST /v0/approval-requests/slack` to store a
generated approval request with its contract binding in durable local JSON
storage. `POST /v0/approval-callbacks/slack` then accepts either JSON bodies
or Slack `application/x-www-form-urlencoded` bodies whose `payload` field
contains the interaction JSON. A callback may include `approval_request` or
`request` plus `contract` or `contract_path`, or it may send only the Slack
interaction after the request has been registered. The server resolves the
pending request by Slack message metadata `approval_request_id` or by the
action value, builds a signed callback artifact, verifies it against the
approval request, appends a `human_approval.granted` chain entry, and returns
the `callback_id`, `approval_entry_id`, role, approver, request source, and
current tree head.

When `trustai serve --slack-signing-secret` is set, or when Slack signature
headers are present, the endpoint validates `X-Slack-Signature` and
`X-Slack-Request-Timestamp` against the raw request body and rejects requests
outside the configured replay window. The signing secret flag supports
`env:SLACK_SIGNING_SECRET` references.

This endpoint is still a local reference callback path. Production hosted
callbacks must move pending request storage to an operational database, manage
OAuth installations, expose hardened public ingress, and add GitHub/GitLab
webhook signature adapters before accepting live multi-provider traffic.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai slack-approval-request artifacts/approval-backed-proof-pack.json --channel C07TRUSTAI --requested-roles model_risk --callback-url https://example.test/trustai/approval-callbacks --out artifacts/slack-approval-request.json
python -m trustai approval-callback-build artifacts/slack-approval-request.json model_risk --approver model-risk@example.com --approved-at 2026-07-03T13:00:00Z --reason "Approved via verified callback artifact." --out artifacts/approval-callback-model-risk.json
python -m trustai approval-callback-verify artifacts/slack-approval-request.json artifacts/approval-callback-model-risk.json
python -m trustai approval-callback-append examples/aitrade/verification-contract.yaml artifacts/slack-approval-request.json artifacts/approval-callback-model-risk.json --state .trustai/approval-callback-demo/evidence-chain.json --tenant approval-callback-local --auto-register --out artifacts/approval-callback-model-risk-entry.json
python -m unittest tests.test_approval_callback
```

The local implementation builds and verifies callback artifacts, stores pending
Slack approval requests for payload-only callbacks, can validate Slack request
signatures and replay windows when configured, and can post provider payloads
through delivery receipts. It does not post to Slack on its own, manage
provider OAuth credentials, or expose a hardened public callback surface; those
remain deployment concerns around the same signed artifact contract.
