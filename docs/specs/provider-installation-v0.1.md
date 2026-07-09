# Provider Installation Manifest v0.1

Provider installation manifests bind GitHub, GitLab, or Slack app installation
state to TrustAI evidence. They cover the hosted callback setup layer for CI/CD
promotion gates: which provider app was installed, which tenant/repository it
covers, which permissions/scopes/events it uses, and where provider callbacks
are expected to arrive.

This v0.1 artifact supports:

- GitHub App, GitLab application, and Slack app installation records.
- Provider app, installation, tenant, owner, and repository references.
- Provider permissions, OAuth scopes, subscribed events, and audit-log scopes.
- Webhook and callback ingress URLs with HTTPS/TLS evidence flags.
- Redacted webhook-secret and credential references.
- Evidence-chain append as `provider_installation.registered`.

## Schema

`schema`: `trustai.provider-installation/0.1`

Top-level fields:

- `manifest_id`: canonical hash of the manifest body without `manifest_id` and
  `signatures`.
- `provider`: `github`, `gitlab`, or `slack`.
- `mode`: `local-reference`, `recorded-installation`, `oauth-installation`, or
  `app-installation`.
- `installed_at`: RFC3339 timestamp when the installation evidence was recorded.
- `expires_at`: optional RFC3339 expiration for temporary app grants.
- `app`: provider app reference and optional app URL.
- `installation`: provider installation reference, tenant reference, owner, and
  repository/project/channel scope when applicable.
- `capabilities`: provider permissions, OAuth scopes, and subscribed events.
- `webhook`: provider webhook URL, callback URL, TLS flag, and redacted secret
  reference.
- `credential`: redacted provider credential or private-key reference.
- `audit_log`: provider audit-log reference and scopes for later audit-log
  correlation receipts.
- `controls`: local control summary for installation, redaction, ingress, audit
  log access, and callback response path.
- `signatures`: detached TrustAI signatures over manifest id and body.

Provider tokens, webhook secrets, client secrets, and private keys must never be
stored directly. They are represented only by redacted references such as
`env:GITHUB_APP_PRIVATE_KEY`.

## Verification

`trustai provider-installation-verify` checks:

- manifest schema, mode, provider, and RFC3339 timestamps;
- manifest id canonical hash;
- detached TrustAI signature;
- required app, installation, tenant, permission/scope, and event fields;
- webhook and callback URL shape;
- redacted secret and credential references;
- expiration status when `--now` is supplied;
- control presence and secret-like field redaction.

`trustai provider-installation-append` appends a
`provider_installation.registered` evidence-chain entry containing the manifest
id, provider, installation references, capabilities, webhook ingress summary,
audit-log access summary, and control counts.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai provider-installation --provider github --app-ref github-app:trustai-local --installation-ref github-installation:123456 --tenant-ref github-org:volelabs --owner volelabs --repository volelabs/trust_ai --mode app-installation --app-url https://github.com/apps/trustai-local --webhook-url https://trustai.example/v0/provider-webhooks/github --callback-url https://trustai.example/v0/provider-callbacks/github --permission checks:write --permission metadata:read --event check_suite --event check_run --secret-ref env:GITHUB_WEBHOOK_SECRET --credential-ref env:GITHUB_APP_PRIVATE_KEY --audit-log-ref github:org-audit-log:volelabs --audit-log-scope read:audit_log --installed-at 2026-07-08T03:00:00Z --evidence-ref github-app-installation:123456 --out artifacts/github-provider-installation.json
python -m trustai provider-installation-verify artifacts/github-provider-installation.json --now 2026-07-08T04:00:00Z
python -m trustai provider-installation-append artifacts/github-provider-installation.json --state .trustai/provider-installation-demo/evidence-chain.json --tenant provider-installation-local --out artifacts/github-provider-installation-entry.json
```

Production deployments still need hosted OAuth/app installation execution,
revocation handling, provider-owned installation/audit APIs, public ingress, and
managed Postgres/HA request storage. Pair this manifest with
`trustai.provider-lifecycle/0.1` to bind OAuth callback, token-exchange,
revocation, uninstall, and audit-log stream references. This manifest defines
the portable installation evidence those hosted systems must emit.
