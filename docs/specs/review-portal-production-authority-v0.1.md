# Review Portal Production Authority Dossier v0.1

Status: draft reference format.

This specification defines the `trustai.review-portal-production-authority-dossier/0.1` artifact. The dossier binds a signed review portal service hardening attestation to external authority evidence for a hosted auditor or regulator portal.

The format is intended to separate local or static portal evidence from a live production hosted UI claim. A valid dossier can be partial. A production claim is valid only when every required production authority category is covered by fresh evidence.

## Artifact

A dossier is a JSON object with:

- `schema`: `trustai.review-portal-production-authority-dossier/0.1`.
- `dossier_id`: canonical hash of the dossier body excluding `dossier_id` and `signatures`.
- `mode`: one of `local-dossier`, `provider-dossier`, or `production-dossier`.
- `environment`: deployment environment label.
- `generated_at`: RFC3339 timestamp.
- `dossier_ref`, `authority_ref`, `producer_ref`: stable references for the dossier, external authority scope, and producer.
- `service_attestation_binding`: canonical binding to the review portal service attestation.
- `required_production_authority`: the v0.1 requirement checklist.
- `authority_evidence`: supplied external authority evidence items.
- `summary`: derived coverage and freshness summary.
- `controls`: derived control statuses.
- `limitations`: human-readable non-claim statements.
- `signatures`: one or more signatures over `{dossier_id, review_portal_authority}`.

## Authority Evidence Bundle

A review portal authority evidence bundle is a source-independent JSON artifact with schema `trustai.review-portal-authority-evidence-bundle/0.1`. It records normalized external authority evidence rows before they are rebound into a concrete service-attestation dossier.

A bundle contains `bundle_id`, `mode`, `environment`, `generated_at`, `bundle_ref`, `issuer_ref`, `subject_ref`, `authority_ref`, `required_production_authority`, `authority_evidence`, `summary`, `controls`, `limitations`, and `signatures`. Modes are `authority-export`, `offline-review`, and `production-export`. `production-export` requires complete production checklist coverage, live non-placeholder `source_uri` values for every evidence item, and fresh `issued_at`/`expires_at` windows.

A verifier can consume a valid bundle through `--authority-evidence-bundle`. The dossier builder rebinds each bundled row to the supplied review portal service attestation by deriving a fresh `service_context` and `evidence_id`; bundle-local service context is not trusted for dossier claims.

Appending a valid bundle writes entry type `review_portal.production_authority_evidence_bundled`. The entry payload retains the bundle hash, issuer/subject/authority refs, coverage summary, control summary, and normalized authority evidence rows so the control plane can index freshness and live source URI coverage offline.

## Service Attestation Binding

The service binding records the source review portal service attestation id, hash, schema, mode, environment, timestamp, source count/hash, service reference, portal kind, endpoint URL, service image and binary hashes, frontend bundle reference/hash/artifact hash, API reference, replica limits, availability zones, supervised-access receipt/session/reviewer fields, auth/session/RBAC/selective-disclosure/tenant/network/encryption references, audit and access log roots, metrics, alert policy, retention, actor reference, redacted credential reference, and evidence references.

Verification recomputes the binding from the supplied service attestation. Even when the service attestation or optional raw source artifacts are omitted, the verifier must require every service binding field emitted by the v0.1 builder; omitted sources may produce replay warnings, but they must not permit partial binding summaries. If optional raw source artifacts are supplied, the verifier also replays the underlying review portal service attestation checks.

## Production Authority Requirements

The v0.1 checklist contains:

- `hosted-portal-worker-fleet`.
- `production-identity-provider-sessions`.
- `regulator-auditor-account-lifecycle`.
- `immutable-access-logs`.
- `hosted-frontend-bundle-release`.
- `selective-disclosure-enforcement`.
- `tenant-isolation-rbac`.
- `kms-session-data-encryption`.
- `portal-observability-alerting`.
- `supervised-access-session-replay`.

Each evidence item contains `requirement_id`, `authority_kind`, `evidence_ref`, `evidence_hash`, `description`, optional `issuer`, `subject`, `source_uri`, `issued_at`, `expires_at`, derived `service_context`, and derived `evidence_id`. Evidence hashes must use `sha256:` references. Authority kinds must be accepted by the requirement. The derived `service_context` binds each external authority row to the exact service attestation id/hash, environment, service ref, portal kind, endpoint, frontend bundle hash, supervised-access receipt/session, audience type, reviewer subject, and reviewer organization recorded in `service_attestation_binding`.

## Verification

A conforming verifier must:

- Verify the schema, canonical `dossier_id`, and at least one signature.
- Require every service attestation binding field emitted by the v0.1 builder, even when source artifacts are omitted.
- Recompute the service attestation binding from the supplied review portal service attestation when supplied.
- Verify the source service attestation, including optional proof pack, supervised access, disclosure, view, frontend bundle, regulator acceptance, and EU AI Act documentation when supplied.
- Verify every authority evidence id, evidence hash reference, and derived service-context binding.
- Recompute the summary from evidence.
- Warn for missing production authority requirements.
- Fail when `--require-complete` is set and any requirement is missing.
- Fail when `--require-fresh` is set and any evidence item lacks an unexpired `issued_at`/`expires_at` window.
- Fail when `mode` is `production-dossier` and any production authority requirement is missing.
- Reject secret-like fields unless they are redacted objects or reference/hash/root fields.

## Chain Entry

Appending a valid dossier writes entry type `review_portal.production_authority_recorded`. The entry payload includes dossier identity, mode, environment, source service attestation binding, coverage summary, control summary, and compact authority evidence references.

## CLI

Reference commands:

```powershell
python -m trustai review-portal-authority-evidence-bundle --environment aitrade-prod --bundle-ref bundle:review-portal-authority/regulator-prod --issuer-ref issuer:trustai-cloud/review-portal --subject-ref service:review-portal/regulator-prod --authority-ref authority:review-portal/regulator-prod --authority-evidence "hosted-portal-worker-fleet,hosted-service,service:review-portal/regulator-prod,sha256:531d0507835b71ab71b64d88c0c1795c3cbba9aa558f893a83df3b3e8e7a00cc,Hosted regulator review portal service export;issuer=TrustAI Cloud;subject=aitrade-prod regulator review portal;source_uri=https://ops.example/trustai/review-portal/regulator-prod;issued_at=2026-07-08T06:10:00Z;expires_at=2026-07-15T06:10:00Z" --generated-at 2026-07-08T06:14:00Z --out artifacts/review-portal-authority-evidence-bundle.json
python -m trustai review-portal-authority-evidence-bundle-verify artifacts/review-portal-authority-evidence-bundle.json
python -m trustai review-portal-authority-evidence-bundle-append artifacts/review-portal-authority-evidence-bundle.json --state .trustai/review-portal-authority-demo/evidence-chain.json --tenant review-portal-authority-local --out artifacts/review-portal-authority-evidence-bundle-entry.json
python -m trustai review-portal-authority artifacts/review-portal-service-attestation.json --environment aitrade-prod --dossier-ref dossier:review-portal-authority/regulator-prod --authority-ref authority:review-portal/regulator-prod --producer-ref oidc:trustai.example/review-portal-authority-worker --authority-evidence-bundle artifacts/review-portal-authority-evidence-bundle.json --generated-at 2026-07-08T06:15:00Z --out artifacts/review-portal-authority.json
python -m trustai review-portal-authority-verify artifacts/review-portal-authority.json artifacts/review-portal-service-attestation.json
python -m trustai review-portal-authority-append artifacts/review-portal-authority.json artifacts/review-portal-service-attestation.json --state .trustai/review-portal-authority-demo/evidence-chain.json --tenant review-portal-authority-local --out artifacts/review-portal-authority-entry.json
```

## Limits

This artifact proves signed service-context binding for each authority evidence row, coverage accounting, freshness windows, and strict claim gates. It does not itself prove a live hosted portal exists. Production operation still requires fresh external evidence from the actual identity provider, hosted portal workers, immutable access logs, account lifecycle systems, KMS/session data stores, and hosted frontend/API infrastructure.
