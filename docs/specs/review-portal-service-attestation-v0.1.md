# TrustAI Review Portal Service Attestation v0.1

This specification defines the signed
`trustai.review-portal-service-attestation/0.1` artifact.

The attestation binds signed supervised-access review receipts to hosted auditor
or regulator portal service hardening evidence. It narrows the gap between
static local HTML review surfaces and production credentialed review portals by
recording service identity, frontend integrity, auth/session/RBAC controls,
selective-disclosure policy, tenant isolation, network controls, audit roots,
access-log roots, metrics, alerting, and redacted operator credentials.

## Scope

A review portal service attestation MUST include:

- a verified `trustai.supervised-access/0.1` receipt;
- portal service identity fields: service ref, version, HTTPS endpoint, image
  digest, binary hash, frontend bundle ref/hash, API ref, replica bounds, and at
  least two availability zones;
- access binding fields from the supervised-access receipt: receipt id, session
  id, audience type, reviewer subject, organization, role, and artifact count;
- portal-kind consistency for regulator and auditor portals: `service.portal_kind`
  must match the supervised-access audience type;
- security controls for identity provider, auth policy, RBAC, session policy,
  selective-disclosure policy, tenant isolation, rate limiting, network policy,
  egress policy, content security policy, and encryption key ref;
- observability controls for audit log root, access log root, metrics, alerting,
  and retention;
- an operator actor and redacted credential reference.

It MAY include source bindings for a proof pack, regulator disclosure, static
HTML view, frontend bundle artifact, EU AI Act technical-documentation export,
and regulator acceptance receipt. When source artifacts are supplied to
verification, their canonical hashes MUST match the attestation. When a
frontend bundle artifact is supplied, its SHA-256 digest MUST equal `service.frontend_bundle_hash`
and is recorded as `service.frontend_bundle_artifact_hash`. When an EU AI Act
technical-documentation export is supplied, it MUST pass the EU AI Act document
verifier against the supplied proof pack and regulator disclosure even when no
regulator acceptance receipt is supplied.

## Verification

`trustai review-portal-service-verify` checks:

- schema, canonical attestation id, and detached signature;
- supported mode and portal kind;
- HTTPS endpoint and SHA-256 image, binary, and frontend bundle references;
- replica floor, replica max, and multi-zone evidence;
- supervised-access source replay, access-field consistency, and portal-kind/audience consistency;
- optional proof pack, regulator disclosure, EU AI Act document, frontend bundle artifact, and regulator acceptance replay;
- audit/access log roots and retention window;
- redacted credential references and absence of raw secret-like fields.

## Chain Entry

`trustai review-portal-service-append` appends
`review_portal.service_attested` with the attestation id/hash, service summary,
access binding, source summary, controls, and limitations.

## Example

```powershell
$reviewPortalBundleHash = "sha256:$((Get-FileHash artifacts/review-portal.bundle.js -Algorithm SHA256).Hash.ToLower())"
python -m trustai review-portal-service-attestation artifacts/supervised-access-receipt.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html --frontend-bundle artifacts/review-portal.bundle.js --regulator-acceptance artifacts/regulator-acceptance.json --eu-ai-act-document artifacts/eu-ai-act-technical-documentation.json --environment aitrade-prod --portal-kind regulator --service-ref review-portal:trustai/regulator-prod --service-version 0.1.0 --endpoint-url https://portal.example/reviews/aitrade --service-image ghcr.io/trustai/review-portal:0.1.0 --service-image-digest sha256:trustai-review-portal-image --service-binary-hash sha256:trustai-review-portal-binary --frontend-bundle-ref bundle:review-portal/regulator-ui --frontend-bundle-hash $reviewPortalBundleHash --api-ref api:review-portal/v0 --session-store-ref redis:review-portal/sessions --auth-provider-ref oidc:review-portal/idp --auth-policy-ref policy:review-portal/auth-v0.1 --rbac-policy-ref policy:review-portal/rbac-v0.1 --session-policy-ref policy:review-portal/session-v0.1 --selective-disclosure-policy-ref policy:review-portal/selective-disclosure-v0.1 --tenant-isolation-ref tenant-isolation:review-portal/aitrade --rate-limit-policy-ref rate-limit:review-portal/regulator --network-policy-ref netpol:review-portal/deny-by-default --egress-policy-ref egress:review-portal/kms-tsa-only --content-security-policy-ref csp:review-portal/regulator-v0.1 --encryption-key-ref kms:review-portal/session-store --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --audit-log-ref audit-log:review-portal/service --audit-log-root sha256:review-portal-service-audit-root --access-log-ref access-log:review-portal/sessions --access-log-root sha256:review-portal-access-log-root --metrics-ref metrics:review-portal/service --alert-policy-ref alert:review-portal/service --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/review-portal-operator --credential-ref env:REVIEW_PORTAL_TOKEN --evidence-ref evidence:review-portal/service --attested-at 2026-07-08T06:00:00Z --out artifacts/review-portal-service-attestation.json
python -m trustai review-portal-service-verify artifacts/review-portal-service-attestation.json artifacts/supervised-access-receipt.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html --frontend-bundle artifacts/review-portal.bundle.js --regulator-acceptance artifacts/regulator-acceptance.json --eu-ai-act-document artifacts/eu-ai-act-technical-documentation.json
python -m trustai review-portal-service-append artifacts/review-portal-service-attestation.json artifacts/supervised-access-receipt.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --view artifacts/regulator-view.html --frontend-bundle artifacts/review-portal.bundle.js --regulator-acceptance artifacts/regulator-acceptance.json --eu-ai-act-document artifacts/eu-ai-act-technical-documentation.json --state .trustai/review-portal-service-demo/evidence-chain.json --tenant review-portal-service-local --out artifacts/review-portal-service-entry.json
```

## Production Boundary

This v0.1 artifact can prove that a portal service configuration is bound to
signed review evidence and hardening controls. It does not prove that a live
React auditor portal, regulator UI, identity-provider login, or hosted access
log was operated unless the source artifacts and audit roots come from that
hosted service. Production deployments should preserve identity-provider
authentication events, immutable access logs, portal session records, frontend
release manifests or bundle artifacts, and service audit exports for replay.
