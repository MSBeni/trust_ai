# Framework Runtime Service Authority Dossier v0.1

A framework runtime service authority dossier binds a verified
`framework-runtime-service-provider` receipt to the explicit live-production
authority checklist that remains outside the local reference implementation.
It is intentionally conservative: provider/source receipts prove the recorded
operation, while authority evidence records which external production signals
exist, which are fresh, and which are still missing.

## Artifact

A dossier uses schema `trustai.framework-runtime-service-authority-dossier/0.1`
and contains:

- mode, environment, dossier ref, authority ref, producer ref, and generation
  timestamp;
- provider receipt binding with provider receipt ID/hash, provider mode,
  service worker operation, service/storage IDs, provider export hash, record
  roots, provider exchange metadata, and provider audit root;
- required production authority checklist for collector fleets, framework
  hooks, runtime service fleets, scheduler/queue/lease APIs, KMS/HSM evidence,
  stream/storage/database exports, MCP proxy workers, and immutable audit logs;
- authority evidence refs with authority kind, evidence hash, issuer/subject,
  optional source URI, and issued/expires freshness windows;
- summary, controls, limitations, and detached signatures.

`local-dossier` and `provider-dossier` modes do not claim live production
operation. `production-dossier` requires every production authority requirement
to be covered before verification succeeds.

## Verification

`framework-runtime-service-authority-verify` recalculates the dossier ID,
verifies at least one detached signature, validates the provider receipt binding,
checks the fixed v0.1 authority checklist, verifies each authority evidence ID,
checks accepted authority kinds per requirement, validates `sha256:` evidence
hash refs, and rejects raw secret-like fields.

When supplied with the provider receipt and source artifacts, verification first
replays `framework-runtime-service-provider-verify`, which in turn replays the
service worker, service attestation, storage export, runtime audit, hook
operation, hook release, and adapter matrix chain. `--require-complete` makes
missing authority categories fail verification. `--require-fresh` makes missing
or expired freshness windows fail verification.

`framework-runtime-service-authority-append` requires the provider receipt and
all provider source artifacts. The chain entry records the dossier ID/hash,
provider binding, authority summary, control summary, and hash-bound authority
evidence summaries.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-service-authority artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode provider-dossier --environment aitrade-prod --dossier-ref dossier:framework-runtime-service-authority/lg-trace-001 --authority-ref authority:framework-runtime-service/aitrade-prod --producer-ref oidc:trustai.example/framework-runtime-authority-worker --authority-evidence "collector-fleet,hosted-service,service:collector-fleet/aitrade-prod,sha256:collector-fleet-authority,Hosted collector fleet deployment export;issuer=TrustAI Cloud;subject=aitrade-prod collector fleet;source_uri=https://ops.example/trustai/collector-fleet/aitrade-prod;issued_at=2026-07-09T00:50:00Z;expires_at=2026-12-31T00:00:00Z" --generated-at 2026-07-09T01:00:00Z --out artifacts/framework-runtime-service-authority.json
python -m trustai framework-runtime-service-authority-verify artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --require-fresh --now 2026-07-09T01:00:00Z
python -m trustai framework-runtime-service-authority-append artifacts/framework-runtime-service-authority.json --provider-receipt artifacts/framework-runtime-service-provider.json --provider-export artifacts/framework-runtime-service-provider-export.json --service-worker artifacts/framework-runtime-service-worker.json --service-attestation artifacts/framework-runtime-service.json --storage-receipt artifacts/framework-runtime-storage.json --storage-export examples/aitrade/framework-runtime-storage-export.json --worker artifacts/framework-runtime-worker.json --runtime-audit artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-service-authority-demo/evidence-chain.json --tenant framework-runtime-service-authority-local --out artifacts/framework-runtime-service-authority-entry.json
```
