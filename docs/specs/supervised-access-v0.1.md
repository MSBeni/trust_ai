# Supervised Access Receipt v0.1

TrustAI proof packs, regulator disclosures, auditor views, and insurer telemetry
are meant to be consumed by third parties. The supervised access receipt is a
signed, offline-verifiable record that a specific reviewer was granted access to
a bounded set of evidence artifacts for a defined purpose and expiry window.

This v0.1 receipt does not claim a hosted React auditor portal, credentialed
regulator UI, or production insurer partner portal. It binds the local artifacts
that those portals would expose: proof packs, selective disclosures, static HTML
views, and consented insurer telemetry. Production deployments should replace
local reviewer references with OIDC/SAML-backed sessions and immutable portal
access logs.

## Schema

`schema`: `trustai.supervised-access/0.1`

Required top-level fields:

- `receipt_id`: canonical hash of the receipt body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{receipt_id, receipt}`.
- `session_id`: canonical hash of the audience, reviewer, expiry, and artifact
  references.
- `issued_at`: RFC3339 access grant timestamp.
- `expires_at`: RFC3339 expiry timestamp, required to be after `issued_at`.
- `audience`: audience type and purpose. Supported types are `auditor`,
  `regulator`, `insurer`, and `procurement`.
- `reviewer`: reviewer subject reference, organization, role, and local auth
  context.
- `scope`: read-only selective-disclosure scope.
- `artifacts`: source artifacts bound by canonical hash or raw SHA-256.
- `controls`: implemented-reference, local-reference, and planned-production
  controls.
- `limitations`: explicit non-production claims.

Supported artifact records:

- `proof_pack`: proof pack id, contract id, agent summary, gate outcome, and
  canonical artifact hash.
- `regulator_disclosure`: disclosure id, audience, purpose, disclosed-entry
  count, and canonical artifact hash.
- `static_view`: raw SHA-256 and size of a rendered local HTML view.
- `insurer_telemetry`: consent id, consent status, risk tier, risk score, and
  canonical telemetry hash.

## Verification

`trustai supervised-access-verify` checks:

- receipt schema and canonical `receipt_id`;
- detached receipt signature;
- supported audience type and non-empty purpose;
- reviewer subject, organization, and role;
- valid issued/expiry time window, with expiry surfaced as a warning when
  verifying after `expires_at`;
- required artifact types for the selected audience;
- source artifact hash and recorded summary-field binding when source files are
  supplied;
- optional source proof pack validity when `--pack` is supplied;
- optional regulator disclosure validity when `--disclosure` is supplied;
- regulator-disclosure source proof-pack binding to the supplied proof pack;
- optional static HTML view hash when `--view` is supplied;
- static regulator view replay against the supplied disclosure render;
- optional insurer telemetry schema and active consent when
  `--insurer-telemetry` is supplied;
- insurer telemetry pack id, contract id, agent, gate outcome, and chain-root
  binding to the supplied proof pack;
- `session_id` binding to audience, reviewer, expiry, and artifact references.

`trustai supervised-access-append` first verifies the receipt, then appends
`supervised.access.granted` to an evidence chain. The appended entry records the
receipt id/hash, session id, audience, reviewer, expiry, artifact references,
and limitations.

## Example Commands

```powershell
python -m trustai supervised-access --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html --audience-type regulator --subject-ref oidc:regulator.example/supervisor-123 --organization "Example Supervisor" --role regulator_reviewer --purpose "EU AI Act supervised review" --expires-at 2026-12-31T00:00:00Z --out artifacts/supervised-access-receipt.json
python -m trustai supervised-access-verify artifacts/supervised-access-receipt.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html --now 2026-07-08T00:00:00Z
python -m trustai supervised-access-append artifacts/supervised-access-receipt.json --state .trustai/supervised-access-demo/evidence-chain.json --tenant supervised-access-local --out artifacts/supervised-access-entry.json
python -m trustai chain-verify --state .trustai/supervised-access-demo/evidence-chain.json --tenant supervised-access-local
```

## Production Notes

A production portal implementation should add:

- OIDC/SAML authentication and tenant-scoped authorization;
- reviewer identity proofing and organization trust metadata;
- immutable portal access logs with login, view, download, and expiry events;
- consent checks before insurer/underwriter sessions;
- regulator selective-disclosure policies enforced server-side;
- short-lived URLs or tokens bound to the receipt id;
- revocation and emergency access cutoff evidence.

The receipt is the local verifier shape for those controls. It lets a third
party prove what evidence was made available, to whom, for what purpose, and
under what expiry window, without accepting an unaudited portal screenshot as
evidence.
