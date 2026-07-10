# Deployment Manifest v0.1

TrustAI is designed for BYOC and self-hosted deployment because regulated
customers may not send agent traces, proof packs, or incident evidence to a
startup SaaS. The deployment manifest is a signed, offline-verifiable record of
the local Docker/Helm reference scaffold, including the self-hosted API
Deployment and Service, and the production controls it does and does not claim.

This v0.1 manifest does not claim a production operator, managed SaaS control
plane, cloud Object Lock, Kafka/ClickHouse/Postgres services, or live KMS/TSA
providers. It binds the current reference deployment files by hash and records
which controls are implemented locally versus planned for production.

## Schema

`schema`: `trustai.deployment-manifest/0.1`

Required top-level fields:

- `manifest_id`: canonical hash of the manifest body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{manifest_id, manifest}`.
- `generated_at`: RFC3339 creation timestamp.
- `deployment`: deployment name, mode, environment, chart metadata, image
  reference, default tenant id, API settings, and artifact type.
- `source_files`: hashed Docker, Helm, deployment documentation, and README
  source files.
- `components`: local runtime, Helm chart, storage, signing secret, API
  Deployment, API Service, WORM, and trust-authority component records.
- `controls`: implemented-reference and planned-production control records.
- `limitations`: explicit non-production claims.

Default source files:

- `deploy/docker/Dockerfile`
- `deploy/helm/trustai/Chart.yaml`
- `deploy/helm/trustai/values.yaml`
- `deploy/helm/trustai/templates/configmap.yaml`
- `deploy/helm/trustai/templates/deployment.yaml`
- `deploy/helm/trustai/templates/service.yaml`
- `deploy/helm/trustai/templates/demo-job.yaml`
- `deploy/helm/trustai/templates/pvc.yaml`
- `docs/deployment/byoc.md`
- `docs/specs/production-trust-v0.1.md`
- `README.md`

## Verification

`trustai deployment-verify` checks:

- manifest schema and canonical `manifest_id`.
- detached manifest signature.
- every source file exists in the supplied root.
- source file `sha256` and size match the current worktree.
- required deployment sources are present.
- required components exist: Docker runtime, Helm chart, persistent evidence
  storage, signing-key secret, local ingestion API, and API Service.
- control records are present and planned-production controls are surfaced as
  warnings rather than silently passing as implemented controls.

`trustai deployment-append` first verifies the manifest, then appends
`deployment.manifest.published` to an evidence chain. The appended entry records
the manifest id/hash, deployment metadata, source-file count, component count,
control summary, and limitations.

## Example Commands

```powershell
python -m trustai deployment-manifest --root . --environment aitrade-byoc --out artifacts/deployment-manifest.json --markdown artifacts/deployment-manifest.md
python -m trustai deployment-verify artifacts/deployment-manifest.json --root .
python -m trustai helm-chart-validation artifacts/deployment-manifest.json --root . --out artifacts/helm-chart-validation.json
python -m trustai helm-chart-validation-verify artifacts/helm-chart-validation.json artifacts/deployment-manifest.json --root .
python -m trustai deployment-append artifacts/deployment-manifest.json --root . --state .trustai/deployment-demo/evidence-chain.json --tenant deployment-local --out artifacts/deployment-entry.json
python -m trustai chain-verify --state .trustai/deployment-demo/evidence-chain.json --tenant deployment-local
```

## Production Notes

A production BYOC or air-gapped operator should add:

- image signing and SBOM/provenance attestations;
- network policies and explicit egress controls;
- managed KMS/HSM signing and independent RFC 3161 timestamping;
- cloud Object Lock compliance mode and legal-hold release workflows;
- Kafka/Redpanda, ClickHouse, and Postgres services where required;
- backup/restore, upgrade, rollback, and operator reconciliation evidence;
- separate control-plane and data-plane tenancy controls.

The manifest is meant to make those claims verifiable as they are added, not to
hide them behind deployment prose. The companion Helm chart validation receipt
replays chart-source checks for the API Deployment, Service, probes, PVC mount,
ConfigMap, optional demo Job, and Secret-backed signing key without requiring a
local Helm binary. The v0.1 chart runs both the API server and the optional
aitrade demo job with the same Secret-backed signing key.
