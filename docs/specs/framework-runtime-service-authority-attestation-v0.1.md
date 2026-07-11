# Framework Runtime Service Authority Attestation v0.1

A framework runtime service authority attestation binds a verified authority
provider export receipt to a signed authority statement. It is the acceptance
layer above `framework-runtime-service-authority-provider`: the provider export
receipt proves the scheduler/queue/request/storage/audit records for the
authority worker run, while this attestation records who reviewed or accepted
that evidence for a named production authority subject.

## Artifact

A receipt uses schema
`trustai.framework-runtime-service-authority-attestation/0.1` and contains:

- mode, environment, issuer, issued/expires timestamps, subject ref, attester
  ref, statement ref, and a redacted credential ref;
- authority provider binding with provider receipt ID/hash, provider mode,
  provider, export timestamp, authority worker operation ID/hash, dossier
  ID/hash, authority request/evidence roots, provider export hash, record roots,
  audit root, and provider exchange evidence;
- authority dossier binding with dossier ID/hash, authority ref, producer ref,
  provider receipt ID, and the production authority coverage summary;
- attestation evidence records for authority reviews, provider-export custody,
  audit logs, operator approvals, or external-authority records, each with
  evidence hash, optional issuer/subject/source URI, freshness window, and
  canonical evidence ID;
- controls, limitations, and detached signatures.

## Verification

`framework-runtime-service-authority-attestation-verify` recalculates the
attestation ID, verifies at least one detached signature, validates
issued/expires timestamps, checks credential redaction, rejects raw secret-like
fields, recalculates attestation evidence IDs, and enforces freshness when
`--require-fresh` is used. It also requires every `authority_provider_binding`
and `authority_dossier_binding` key emitted by the v0.1 builder. Provider
receipt metadata, worker/dossier hashes, authority request roots, provider
export roots, nested provider exchange fields, dossier metadata, and dossier
summary counts/lists must be present and source artifacts must be supplied for replay.

Offline verification is fail-closed: the authority provider receipt/export,
authority worker receipt, authority dossier, service provider receipt/export,
service worker receipt, service attestation, storage receipt/export, runtime
worker receipt, runtime audit receipt, audit export, hook operation, source
trace, hook release, and adapter matrix are required. Verification first replays
`framework-runtime-service-authority-provider-verify`, then replays
`framework-runtime-service-authority-verify` against the source dossier. It
rejects mismatches in provider receipt hashes, dossier hashes, authority
evidence roots, missing requirement roots, provider export roots, or dossier
coverage summaries. A detached signature over partial replay inputs is not
enough to verify the attestation.

`production-attestation` mode requires a `production-export` authority provider
receipt, successful provider exchange evidence, complete production-authority
coverage, and fresh attestation evidence windows. `local-attestation` and
`provider-attestation` modes remain local/reference evidence and do not claim
continuously operated production infrastructure.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-authority-attestation artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode provider-attestation --environment aitrade-prod --issuer "TrustAI production authority" --subject-ref authority:framework-runtime-service/aitrade-prod --attester-ref oidc:trustai.example/framework-runtime-authority-attester --statement-ref authority-attestation:framework-runtime-service/lg-trace-001 --credential-ref env:FRAMEWORK_RUNTIME_SERVICE_AUTHORITY_ATTESTATION_TOKEN --attestation-evidence "authority-review,authority-review:framework-runtime-service/lg-trace-001,sha256:framework-runtime-service-authority-review,Production authority reviewer accepted the provider export evidence set.;issuer=TrustAI authority desk;subject=aitrade-prod framework runtime service authority;issued_at=2026-07-09T01:08:00Z;expires_at=2026-12-31T00:00:00Z" --issued-at 2026-07-09T01:10:00Z --expires-at 2027-07-09T01:10:00Z --require-fresh --out artifacts/framework-runtime-service-authority-attestation.json
python -m trustai framework-runtime-service-authority-attestation-verify artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --require-fresh --now 2026-07-09T01:10:00Z
python -m trustai framework-runtime-service-authority-attestation-append artifacts/framework-runtime-service-authority-attestation.json --authority-provider-receipt artifacts/framework-runtime-service-authority-provider.json --authority-provider-export artifacts/framework-runtime-service-authority-provider-export.json --authority-worker artifacts/framework-runtime-service-authority-worker.json --authority-dossier artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --require-fresh --now 2026-07-09T01:10:00Z --state .trustai/framework-runtime-service-authority-attestation-demo/evidence-chain.json --tenant framework-runtime-service-authority-attestation-local --out artifacts/framework-runtime-service-authority-attestation-entry.json
```
