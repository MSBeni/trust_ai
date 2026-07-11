# Provider Ingress Manifest v0.1

Provider ingress manifests bind public callback ingress configuration to provider
app installation and callback-store evidence. They cover the BYOC/local reference
path for GitHub, GitLab, and Slack callbacks without claiming TrustAI-operated
hosted OAuth, DNS, WAF, ACME, or HA request storage.

## Manifest

`schema`: `trustai.provider-ingress/0.1`

The manifest binds:

- `ingress_manifest_id`: canonical hash of the manifest body.
- `ingress`: mode, environment, ingress reference, HTTPS base URL, DNS name, and
  healthcheck URL.
- `tls`: HTTPS requirement plus a redacted certificate reference or SHA-256
  certificate fingerprint.
- `network_controls`: WAF, network policy, rate-limit policy, allowed provider
  source references, and replay-window seconds.
- `endpoints`: derived webhook/callback endpoints from provider installation
  manifests, including provider, path, URL, expected signature scheme, and source
  installation hash.
- `source_artifacts`: canonical summaries for provider installation manifests and
  optional provider callback-store manifests.
- `controls`: implemented/planned status for public HTTPS ingress, DNS/TLS
  binding, provider signature verification, replay/rate-limit controls, network
  boundary controls, callback-store binding, and hosted operation readiness.

Supported modes:

- `local-reference`
- `byoc-reference`
- `recorded-public-ingress`
- `production-design`

## Verification

`trustai provider-ingress-verify` checks:

- canonical `ingress_manifest_id` and detached signature;
- RFC3339 `generated_at`;
- absolute HTTPS ingress, healthcheck, webhook, and callback URLs;
- DNS name matching the ingress base URL host;
- TLS certificate reference redaction or `sha256:` fingerprint;
- replay window between 1 and 600 seconds;
- required network-policy and rate-limit references;
- provider endpoint signature schemes and source installation IDs/hashes;
- provider installation replay plus callback-store replay with source artifacts when callback-store evidence is supplied.

Verifier warnings are emitted when non-required source artifacts are not supplied, WAF or DNS
references are missing, or a non-operational mode is used.

## Chain Entry

`provider_ingress.attested` entries record the ingress manifest id and hash, the
public ingress URL metadata, TLS attestation summary, network control references,
endpoint count, provider counts, source artifact count, and control summary.

## Limitations

This artifact does not prove that TrustAI operates a public SaaS ingress. Pair it
with `trustai.provider-callback-storage/0.1` manifests to bind Postgres/HA request
storage controls and `trustai.provider-lifecycle/0.1` manifests to bind OAuth,
revocation, uninstall, and provider audit-log stream evidence. Live production
operation still requires provider-owned OAuth/app flows, public DNS and
certificate automation, WAF/rate-limit enforcement, revocation workflows, live
managed Postgres or equivalent HA request storage, and provider-authenticated
audit-log streaming.

