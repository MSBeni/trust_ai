# Consumption Exports v0.1

TrustAI proof packs are meant for third parties, not just agent operators. The
local reference implementation produces consumption artifacts from verified proof
packs and evidence chains.

## CI Report

`trustai ci-report` writes a GitHub- or GitLab-shaped JSON report that can back a
promotion check. The command fails when verification fails or the gate outcome is
not `passed`.

`trustai ci-payload` writes an API-ready promotion-check request body for
GitHub Checks or GitLab commit statuses. The payload includes proof-pack context,
verification status, the provider request path, body, and a source-report hash so
CI workers can post the request without reinterpreting the proof pack. Soak
report jobs can also pass `--demote-on-failure` to append a chain-backed
`promotion_gate.demoted` event when post-promotion soak evidence fails.

## Provider Installation Manifests

`trustai provider-installation` writes a signed GitHub, GitLab, or Slack app
installation manifest. The manifest binds provider app and installation
references, tenant/repository scope, permissions, OAuth scopes, subscribed
events, webhook/callback URLs, redacted secret references, provider credential
references, and audit-log scopes.

`trustai provider-installation-verify` checks canonical hashes, signatures,
required provider fields, redaction, URL shape, and optional expiration status.
`trustai provider-installation-append` records the manifest as a
`provider_installation.registered` evidence-chain entry.

## Provider Delivery Receipts

`trustai provider-delivery` wraps API-ready GitHub, GitLab, or Slack payloads
in a signed delivery receipt. The receipt binds provider, payload hash, request
method/path, request body hash, endpoint base, redacted credential reference,
idempotency key, optional or captured provider response hash, and delivery timestamp.

`trustai provider-delivery-verify` verifies a receipt against the original
payload. `trustai provider-delivery-append` records the delivery receipt as a
`provider_delivery.recorded` evidence-chain entry.

`trustai provider-delivery --send` can post the payload over HTTP using an
`env:` credential reference and records redacted request-header plus response
hashes. Production dispatch workers should emit the same receipt after
provider-specific credentialed posting, retry, rate-limit, and response capture. Provider delivery service attestations bind those production dispatch-worker controls to the delivery receipt evidence.

## Provider Delivery Service Attestations

`trustai provider-delivery-service-attestation` writes a signed
`trustai.provider-delivery-service-attestation/0.1` attestation for the
provider dispatch service that would operate credentialed GitHub, GitLab, or
Slack posting in production. The attestation binds a provider delivery receipt
and optional provider operations service attestation to service image/binary
hashes, replica and zone controls, dispatch worker, queue, DLQ, retry policy,
idempotency store, outbound proxy, provider endpoint, redacted provider
credential, mTLS/auth/network/egress/rate-limit/request-signing policies, audit
root, metrics, alerting, operator identity, and redacted operator credential.

`trustai provider-delivery-service-verify` replays supplied source artifacts and
checks redaction, service hardening, dispatch controls, source hashes, audit
retention, and signatures. `trustai provider-delivery-service-append` records
the attestation as a `provider.delivery_service_attested` evidence-chain entry.
## Provider Webhook Receipts

`trustai provider-webhook` verifies inbound GitHub or GitLab webhook
authentication, binds the raw payload SHA-256 and redacted header hash, and
writes a signed `trustai.provider-webhook/0.1` receipt without storing provider
secrets.

`trustai provider-webhook-verify` verifies the receipt against the raw body and
can replay provider authentication when headers and secret are supplied.
`trustai provider-webhook-append` records the receipt as a
`provider_webhook.recorded` evidence-chain entry.

The local HTTP server exposes `POST /v0/provider-webhooks/github` and
`POST /v0/provider-webhooks/gitlab` when configured with provider webhook
secrets. The endpoints verify GitHub `X-Hub-Signature-256` or GitLab
`X-Gitlab-Token`, sign a receipt, append the chain entry, deduplicate provider
retries, and return the updated tree summary.

## Provider Audit Correlation Receipts

`trustai provider-audit-correlation` binds a provider audit-log export to a
TrustAI webhook or delivery receipt. The signed `trustai.provider-audit-correlation/0.1`
receipt stores the audit-log hash, source receipt hash, matched audit event hash,
and non-secret match criteria such as provider, event, delivery id, payload hash,
request body hash, target URL, or request path.

`trustai provider-audit-verify` replays the correlation against the provider
audit export and source receipts. `trustai provider-audit-append` records the
receipt as a `provider_audit.correlated` evidence-chain entry.

## Provider Audit Stream Receipts

`trustai provider-audit-stream` writes a signed
`trustai.provider-audit-stream/0.1` receipt for a provider audit-log retrieval
or stream window. The receipt binds provider endpoint URL, request hash,
response status, response hash, redacted credential reference, window start/end,
optional cursor refs, audit-log hash/count, provider installation audit scopes,
provider lifecycle `audit_log_stream_binding`, and optional audit correlation
receipt hash.

`trustai provider-audit-stream-verify` replays the audit-log hash/count and
source manifest bindings. `trustai provider-audit-stream-append` records the
receipt as a `provider_audit.stream_recorded` evidence-chain entry.

## Provider Credential Custody Receipts

`trustai provider-credential-custody` writes a signed
`trustai.provider-credential-custody/0.1` receipt for provider credential
custody. The receipt binds a redacted provider credential reference to source
provider installation, lifecycle, lifecycle-operation, and audit-worker hashes,
plus vault/KMS endpoint metadata, key policy hash, rotation and revocation
references, approver quorum, custody audit-log root, optional attestation, and
optional provider vault/KMS response hash.

`trustai provider-credential-custody-verify` replays supplied source artifacts
and checks redaction, policy, quorum, attestation, response hash, and custody
audit-log bindings. `trustai provider-credential-custody-append` records the
receipt as a `provider_credential.custody_recorded` evidence-chain entry.

## Provider Operations Service Attestations

`trustai provider-operations-service-attestation` writes a signed
`trustai.provider-operations-service-attestation/0.1` attestation for the
provider operations service that fronts callback, OAuth/app lifecycle, audit,
storage, and credential-custody workflows. The attestation binds provider
installation, ingress, callback storage, lifecycle, lifecycle-operation, audit
worker, credential-custody, and optional callback-store/audit-stream/audit
correlation source hashes to service image/binary hashes, replica and zone
controls, public ingress, OAuth/callback/audit worker refs, Postgres storage,
vault/KMS refs, webhook signature/replay/dedup policy, scheduler lease and
checkpoint refs, external-call policy, audit root, actor, and redacted
credential refs.

`trustai provider-operations-service-verify` replays supplied source artifacts
and checks redaction, service hardening, source hashes, audit retention, and
signatures. `trustai provider-operations-service-append` records the attestation
as a `provider.operations_service_attested` evidence-chain entry.
## Provider Callback Store Manifests

`trustai provider-callback-store` imports signed provider installation, delivery,
webhook, audit-correlation, audit-stream, approval-request, and approval-callback artifacts into
an indexed SQLite operation store. The signed `trustai.provider-callback-store/0.1`
manifest binds database schema and indexes, operation counts, redacted operation
summaries, source artifact hashes, and a retention horizon.

`trustai provider-callback-store-verify` replays the SQLite summary and optional
source artifact hashes. `trustai provider-callback-store-append` records the
store manifest as a `provider_callback_store.attested` evidence-chain entry.

## Provider Ingress Manifests

`trustai provider-ingress` writes a signed `trustai.provider-ingress/0.1`
manifest for public GitHub, GitLab, and Slack callback ingress. The manifest
binds an HTTPS base URL, DNS name, healthcheck URL, TLS certificate reference or
fingerprint, WAF/network/rate-limit controls, replay window, provider endpoints
derived from installation manifests, and callback-store evidence whose recorded source artifacts must be replayed when supplied.

`trustai provider-ingress-verify` checks canonical hashes, signatures, HTTPS URL
shape, DNS/base-host alignment, TLS attestation, network controls, provider
signature schemes, optional installation replay, and required callback-store source-artifact replay when callback-store evidence is supplied. `trustai
provider-ingress-append` records the manifest as a `provider_ingress.attested`
evidence-chain entry.

## Provider Callback Storage Manifests

`trustai provider-callback-storage` writes a signed
`trustai.provider-callback-storage/0.1` manifest for Postgres-compatible callback
request storage. The manifest binds a redacted DSN reference, target schema,
SQLite-to-Postgres migration reference, source callback-store hash, optional
provider ingress hash, HA topology, backup retention, encryption, network, and
monitoring controls.

`trustai provider-callback-storage-verify` checks canonical hashes, signatures,
retention timestamps, redaction, migration-plan replay, HA minimums, backup and
security controls, and required callback-store source-artifact replay when callback-store evidence is supplied. `trustai
provider-callback-storage-append` records the manifest as a
`provider_callback_storage.attested` evidence-chain entry.

## Provider Lifecycle Manifests

`trustai provider-lifecycle` writes a signed
`trustai.provider-lifecycle/0.1` manifest for provider OAuth/app lifecycle and
revocation evidence. The manifest binds the provider installation, HTTPS OAuth
callback URL, authorization and token-exchange references, redacted token-store
reference, refresh and credential-rotation references, revocation and uninstall
references, provider audit-log stream reference, and optional ingress/storage
source artifacts.

`trustai provider-lifecycle-verify` checks canonical hashes, signatures, HTTPS
callback and revocation URLs, redacted token storage, required lifecycle
operations, provider installation replay, optional ingress host alignment, and
optional callback-storage replay. `trustai provider-lifecycle-append` records
the manifest as a `provider_lifecycle.attested` evidence-chain entry.

## Provider Lifecycle Operation Receipts

`trustai provider-lifecycle-operation` writes a signed
`trustai.provider-lifecycle-operation/0.1` receipt for one recorded provider
operation. The receipt binds a lifecycle manifest id/hash, operation kind and
reference, provider endpoint URL, request hash, response status, response hash,
redacted credential reference, optional redacted token-store reference, actor,
and idempotency key.

`trustai provider-lifecycle-operation-verify` checks canonical hashes,
signatures, lifecycle replay, operation kind/reference declaration, HTTPS
endpoint, SHA-256 request/response references, response success consistency,
redaction, and audit-log stream references. `trustai
provider-lifecycle-operation-append` records the receipt as a
`provider_lifecycle.operation_recorded` evidence-chain entry.

The local server also exposes `POST /v0/provider-lifecycle-operations` for
recording the same receipt through HTTP. It accepts inline lifecycle manifests or
`lifecycle_path`, top-level or nested operation fields, and either explicit
request/response hashes or JSON request/response bodies for local SHA-256 hash
derivation. `trustai serve --provider-lifecycle-operation-token env:VAR` enables
bearer-token protection for this operation-recording endpoint.

## Verifier Conformance

`trustai verifier-conformance` writes a tamper-vector report proving the offline
verifier accepts a valid pack and rejects changed signatures, evidence payloads,
Merkle proofs, and packed contract bodies. `trustai verifier-conformance-verify`
checks the report hash, expected outcomes, pass flags, and summary counts.

## Slack Approval Request

`trustai slack-approval-request` writes a Slack Block Kit `chat.postMessage`
payload for required human approval roles. The artifact includes requested
roles, already-approved roles, missing roles, Slack action IDs, and approval
entry templates. When `--promotion-payload` is supplied, the request also
binds the human approval to the exact GitHub/GitLab promotion payload hash,
repository/project commit target, and provider-native proof-pack reference.

`trustai approval-callback-build`, `trustai approval-callback-verify`, and
`trustai approval-callback-append` convert a provider action into a signed
callback artifact, verify it against the original request, and append it as
chain-backed human approval evidence. The local HTTP server also exposes
`POST /v0/approval-requests/slack` to register pending requests and
`POST /v0/approval-callbacks/slack` to convert Slack-style interaction
payloads into verified callback artifacts and chain-backed approvals.

The local reference implementation can record provider app installation manifests, post API-ready payloads with
`provider-delivery --send`, issue provider delivery service hardening attestations for dispatch workers, queues, DLQs, retry policy, idempotency, outbound proxy, provider endpoint, egress/rate-limit/request-signing, audit, metrics, actor, and redacted credential bindings, verify GitHub/GitLab provider webhooks, store pending
Slack approval requests, persist provider callback operations into SQLite, attest public/BYOC provider ingress configuration, bind callback storage migration to Postgres/HA controls, sign provider OAuth/app lifecycle and revocation manifests, record provider audit stream receipts, record provider audit worker operation receipts with scheduler/lease/checkpoint bindings, record provider credential custody receipts with vault/KMS policy bindings, issue provider operations service hardening attestations for public ingress, OAuth/callback/audit workers, managed storage, vault/KMS, signature/replay/dedup, scheduler/lease/checkpoint, external-call, audit, actor, and redacted credential bindings, record provider lifecycle operation receipts through the CLI or the local `/v0/provider-lifecycle-operations` endpoint, and accept Slack-style local approval interactions. The
Slack callback endpoint supports signing-secret and replay-window validation
when configured. Public GitHub, GitLab, and Slack callback handling still
requires continuously operated hosted OAuth/app lifecycle workers, live provider-owned vault/KMS integrations behind credential custody receipts, credentialed external provider calls, live managed Postgres/HA request storage operations, live TrustAI-operated public ingress, production dispatch workers that emit live `http-dispatch` or recorded-response provider delivery receipts plus signed callback artifacts, and production-operated provider audit worker infrastructure beyond the signed local/reference worker receipts, provider operations service attestations, and provider delivery service attestations.

## Compliance Export

`trustai compliance-export` maps one proof pack to five framework surfaces:

- ISO 42001;
- NIST AI RMF;
- EU AI Act Annex III;
- SR 11-7;
- SOC 2.

## Insurer Telemetry

`trustai consent-grant` appends signed customer consent for underwriting data sharing. `trustai insurer-export --require-consent` emits underwriting telemetry only when that consent is active. The local `/v0/insurer-risk` endpoint can also require a bearer token and validates active consent before returning telemetry.

## Actuarial Corpus

`trustai actuarial-export --require-consent` emits anonymized corpus records for
AI liability pricing and longitudinal reliability analysis. It reuses active
insurer consent, pseudonymizes pack/contract/agent identifiers, and aggregates
incident, demotion, rollback, risk tier, and risk-class signals. See
`docs/specs/actuarial-corpus-v0.1.md`.

## Insurer Partner Service Attestations

`trustai insurer-partner-service-attestation` binds active consented insurer
telemetry, signed underwriting quote receipts, optional actuarial product
manifests, and hosted insurer portal/API controls into a single signed service
attestation. The verifier replays the telemetry-to-quote hash binding, optional
actuarial corpus/product bindings, HTTPS service and partner endpoints, partner
authentication, request signing, data-minimization, PII redaction, tenant
isolation, delivery-log roots, audit/access roots, metrics, alerting, and
redacted credential references. Live production insurer authority still requires
credentialed partner API calls, partner-owned authentication events,
policy-system workflow IDs, immutable delivery logs, and operated worker fleets.
## Regulator Disclosure

`trustai regulator-export` emits a selective-disclosure package with chosen
chain entries and Merkle inclusion proofs. `trustai regulator-verify` verifies
the package offline without access to undisclosed log entries.

## EU AI Act Documentation

`trustai eu-ai-act-export` turns a proof pack and optional regulator disclosure
into a signed technical-documentation artifact and Markdown companion for
high-risk AI system review. `trustai eu-ai-act-verify` checks the document hash,
signature, required sections, and optional source artifact links.

## Auditor View

`trustai auditor-view` renders a static, read-only HTML artifact for internal
model risk or audit review. `trustai regulator-view` renders a selective-disclosure
HTML artifact for regulator review.

## Review Portal Service Attestations

`trustai review-portal-service-attestation` writes a signed
`trustai.review-portal-service-attestation/0.1` attestation for the hosted
review portal that would serve auditor, regulator, or third-party review
sessions in production. The attestation binds a supervised-access receipt and
optional proof pack, regulator disclosure, static HTML view, EU AI Act document,
and regulator acceptance receipt to portal service image/binary hashes,
frontend bundle integrity, HTTPS endpoint, API ref, session store, identity
provider, auth/session/RBAC policies, selective-disclosure policy, tenant
isolation, rate limits, network/egress/CSP/encryption controls, audit roots,
access-log roots, metrics, alerting, operator identity, and redacted operator
credential.

`trustai review-portal-service-verify` replays supplied source artifacts and
checks service hardening, source hashes, access-field consistency, redaction,
retention, and signatures. `trustai review-portal-service-append` records the
attestation as a `review_portal.service_attested` evidence-chain entry. Live
React or hosted regulator UI operation still requires production identity-provider
sessions, hosted portal workers, immutable access logs, and account lifecycle
evidence from the operated service.

## Auditor Certification Kit

`trustai auditor-certification-export` writes a local training and verification
kit for auditors reviewing proof packs, selective disclosures, and standards
submission packages. `trustai auditor-certification-verify` checks the kit hash,
required modules, required exercises, and optional source artifact hashes.

The kit is not an external accreditation credential. It documents repeatable
local curriculum and practical exercises; independent program governance remains
outside the reference implementation.

## Vendor Trust Network

`trustai trust-network-export` writes a buyer procurement manifest that binds
vendor proof-pack submissions to a clause requiring offline-verifiable TrustAI
proof packs. `trustai trust-network-verify` checks the manifest hash, source
proof-pack hashes, proof-pack validity, framework requirements, gate outcome,
risk-class constraints, and accepted/rejected status.

The manifest is a local artifact for cross-org verification. Hosted registries,
procurement-platform integration, vendor identity, and marketplace distribution
remain production concerns outside this reference implementation.

## Marketplace Catalog

`trustai marketplace-export` writes a local catalog of certified verification
contract templates and runtime policy packs per vertical and regulation.
`trustai marketplace-verify` checks catalog hashes, source artifact hashes,
contract/policy schemas, asset ids, vertical metadata, regulation metadata, and
aggregate counts.

The catalog is a reference artifact for template distribution. Hosted listings,
publisher onboarding, revocation, billing, and independent certification remain
outside this implementation.
## Trust Network Service Attestations

`trustai trust-network-service-attestation` writes a signed hosted-service
hardening attestation over trust-network registry receipts, optional registry
status receipts, marketplace catalogs, and marketplace distribution receipts.
`trustai trust-network-service-verify` replays the registry, identity-provider,
procurement, proof-pack, catalog, and distribution sources when supplied, then
checks hosted-service controls for HTTPS endpoints, identity federation,
buyer/vendor/subscriber authorization, procurement sync, entitlement stores,
revocation/cache invalidation, tenant isolation, request signing, network
policy, audit roots, publication logs, retention, and redacted credentials.

`trustai trust-network-service-append` emits a
`trust_network.service_attested` chain entry containing the attestation hash,
service summary, registry summary, marketplace summary, source summary, controls,
and limitations. This gives buyers and auditors a replay-verifiable bridge
between local cross-org receipt formats and the hosted registry/marketplace
service evidence those formats require in production.

The attestation is not live hosted authority by itself. Production deployments
still need operated identity-provider sessions, account lifecycle events,
immutable registry propagation logs, marketplace entitlement logs, subscriber
authentication, revocation propagation, billing or third-party author governance
where applicable, and worker fleets that emit signed receipts from live hosted
operations.




