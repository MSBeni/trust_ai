# Provider Lifecycle Manifest v0.1

Provider lifecycle manifests bind provider OAuth/app lifecycle, token storage,
revocation, uninstall, and audit-log stream references into signed evidence.
They connect app installation evidence to public callback ingress and callback
storage evidence so auditors can replay the lifecycle control surface without
trusting operator screenshots.

## Manifest

`schema`: `trustai.provider-lifecycle/0.1`

The manifest binds:

- `lifecycle_manifest_id`: canonical hash of the manifest body.
- `lifecycle`: mode, environment, lifecycle reference, and provider.
- `installation`: provider installation manifest id/hash, app reference,
  installation reference, tenant reference, owner, and repository.
- `oauth`: HTTPS callback URL, authorization callback reference, token-exchange
  reference, redacted token-store reference, refresh-policy reference, scopes,
  and permissions.
- `revocation`: HTTPS revocation endpoint, token revocation reference, and app
  uninstall reference.
- `operations`: required operation references for authorization callback, token
  exchange, refresh policy, credential rotation, revocation, uninstall, and
  provider audit-log stream binding.
- `source_artifacts`: canonical summaries for the provider installation,
  optional provider ingress manifest, and optional callback storage manifest.
- `controls`: implemented/planned status for installation binding, OAuth
  callback execution, redacted token storage, credential refresh/rotation,
  revocation workflow, ingress binding, storage binding, provider audit stream
  binding, and live hosted provider lifecycle operation.

Supported modes:

- `local-reference`
- `byoc-reference`
- `recorded-provider-lifecycle`
- `production-design`

## Verification

`trustai provider-lifecycle-verify` checks:

- canonical `lifecycle_manifest_id` and detached signature;
- RFC3339 `generated_at`;
- supported provider and lifecycle mode;
- required installation, OAuth, revocation, operation, source, and control
  fields;
- HTTPS callback and revocation URLs;
- redacted token-store reference and absence of raw token/secret-like fields;
- optional provider installation replay;
- optional provider ingress replay and OAuth callback host alignment;
- optional callback storage manifest replay, including nested callback-store manifest, database, and source-artifact replay when supplied ingress or storage evidence records callback-store bindings.

Verification emits warnings when optional lifecycle source artifacts are not supplied. It fails when supplied ingress or storage evidence records callback-store bindings and callback-store replay inputs are omitted, or when the
mode does not claim recorded live provider lifecycle operation.

## Chain Entry

`provider_lifecycle.attested` entries record the lifecycle manifest id and hash,
non-secret lifecycle metadata, installation record, OAuth callback metadata with
token storage omitted, revocation metadata, operation counts, source artifact
count, and control summary.

## Operation Receipts

Pair lifecycle manifests with `trustai.provider-lifecycle-operation/0.1`
receipts to attest individual authorization, token exchange, refresh policy,
credential rotation, revocation, uninstall, and audit-log stream operations.
Those receipts bind provider endpoints, request hashes, response statuses,
response hashes, redacted credential references, and optional token-store
references back to operation kinds declared in this manifest.

## Limitations

This artifact verifies signed lifecycle bindings and redaction discipline. It
does not by itself prove live hosted OAuth execution, provider credential
issuance, revocation execution, uninstall completion, audit-log streaming, or
incident-linked lifecycle monitoring unless those are supplied as
`recorded-provider-lifecycle` evidence.
