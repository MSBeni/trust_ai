# BYOC / Self-Hosted Reference Deployment

The roadmap calls for BYOC and self-hosted deployment because regulated buyers
will not send sensitive agent traces to a startup SaaS by default. This
repository includes a reference deployment:

- `deploy/docker/Dockerfile` builds the local CLI and API runtime.
- `deploy/helm/trustai` runs the TrustAI API as a Kubernetes Deployment and
  ClusterIP Service, NetworkPolicy, plus the bundled aitrade proof-pack flow as an optional
  Job with persistent evidence storage.

## Build

```powershell
docker build -f deploy/docker/Dockerfile -t trustai:0.1.0 .
```

## Install

Create a signing key secret:

```powershell
kubectl create secret generic trustai-signing-key --from-literal=signing-key=replace-me
```

Render or install the chart:

```powershell
helm template trustai deploy/helm/trustai
helm install trustai deploy/helm/trustai
kubectl port-forward svc/trustai-api 8080:8080
```

The API exposes `/health`, local ingest, proof-pack verification, approval
callback, provider webhook, and consent-gated insurer risk endpoints. The API
Deployment and optional demo Job both read `TRUSTAI_SIGNING_KEY` from the
Kubernetes Secret and pass it through `--key env:TRUSTAI_SIGNING_KEY`.

## Deployment Evidence

The reference scaffold can be bound into signed deployment, Helm chart
validation, network policy, Kubernetes release-state, and image integrity receipts for third-party review:

```powershell
python -m trustai deployment-manifest --root . --environment aitrade-byoc --out artifacts/deployment-manifest.json --markdown artifacts/deployment-manifest.md
python -m trustai deployment-verify artifacts/deployment-manifest.json --root .
python -m trustai helm-chart-validation artifacts/deployment-manifest.json --root . --out artifacts/helm-chart-validation.json
python -m trustai helm-chart-validation-verify artifacts/helm-chart-validation.json artifacts/deployment-manifest.json --root .
python -m trustai kubernetes-release-state artifacts/deployment-manifest.json artifacts/helm-chart-validation.json --root . --environment aitrade-byoc --provider "Example Kubernetes API" --cluster-ref k8s:cluster/aitrade-prod --namespace trustai --release-name trustai --release-revision 7 --release-status deployed --export-ref k8s-export:aitrade-prod/trustai/2026-07-04 --export-hash sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --service-account-ref k8s:sa/trustai/trustai-api --deployment-ref k8s:deployment/trustai/trustai-api --service-ref k8s:service/trustai/trustai-api --network-policy-ref k8s:networkpolicy/trustai/trustai-api --secret-ref k8s:secret/trustai/trustai-signing-key --desired-replicas 2 --ready-replicas 2 --pod-selector-hash sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --ingress-policy-hash sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --egress-policy-hash sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd --audit-log-ref audit-log:kubernetes/aitrade-prod/trustai --audit-log-root sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --exported-at 2026-07-04T03:08:00Z --issued-at 2026-07-04T03:08:00Z --expires-at 2026-07-05T03:08:00Z --generated-at 2026-07-04T03:10:00Z --out artifacts/kubernetes-release-state.json
python -m trustai kubernetes-release-state-verify artifacts/kubernetes-release-state.json artifacts/deployment-manifest.json artifacts/helm-chart-validation.json --root .
'{"sbom":"trustai","version":"0.1.0"}' | Set-Content -NoNewline artifacts/trustai-image.sbom.json
'{"builder":"trustai-local","source":"git"}' | Set-Content -NoNewline artifacts/trustai-image.provenance.json
'sigstore-placeholder-signature' | Set-Content -NoNewline artifacts/trustai-image.sig
python -m trustai deployment-image-integrity artifacts/deployment-manifest.json --root . --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --sbom artifacts/trustai-image.sbom.json --provenance artifacts/trustai-image.provenance.json --signature artifacts/trustai-image.sig --out artifacts/deployment-image-integrity.json
python -m trustai deployment-image-integrity-verify artifacts/deployment-image-integrity.json artifacts/deployment-manifest.json --root .
python -m trustai deployment-image-integrity-append artifacts/deployment-image-integrity.json artifacts/deployment-manifest.json --root . --state .trustai/image-integrity-demo/evidence-chain.json --tenant image-integrity-local --out artifacts/deployment-image-integrity-entry.json
python -m trustai chain-verify --state .trustai/image-integrity-demo/evidence-chain.json --tenant image-integrity-local
python -m trustai helm-chart-validation-append artifacts/helm-chart-validation.json artifacts/deployment-manifest.json --root . --state .trustai/helm-validation-demo/evidence-chain.json --tenant helm-validation-local --out artifacts/helm-chart-validation-entry.json
python -m trustai chain-verify --state .trustai/helm-validation-demo/evidence-chain.json --tenant helm-validation-local
python -m trustai kubernetes-release-state-append artifacts/kubernetes-release-state.json artifacts/deployment-manifest.json artifacts/helm-chart-validation.json --root . --state .trustai/kubernetes-release-demo/evidence-chain.json --tenant kubernetes-release-local --out artifacts/kubernetes-release-state-entry.json
python -m trustai chain-verify --state .trustai/kubernetes-release-demo/evidence-chain.json --tenant kubernetes-release-local
```

`trustai deployment-append` can append the verified manifest as
`deployment.manifest.published` evidence, `trustai helm-chart-validation-append`
can append `deployment.helm_chart.validated` evidence for API, Service, PVC, Secret, and NetworkPolicy chart checks, and
`trustai deployment-image-integrity-append` can append
`deployment.image.integrity_attested` evidence for image digest, SBOM,
provenance, and signature bindings. See
`docs/specs/deployment-manifest-v0.1.md`,
`docs/specs/helm-chart-validation-v0.1.md`, and
`docs/specs/deployment-image-integrity-v0.1.md` for the schemas.

## Production Authority Dossier

The deployment manifest and BYOC operator attestation can be bound into a
signed production authority dossier. The dossier records the fixed BYOC
production checklist, external authority evidence hashes, NetworkPolicy admission/audit evidence, freshness windows,
and conservative `production-dossier` guardrails.

```powershell
python -m trustai byoc-authority artifacts/deployment-manifest.json artifacts/byoc-operator-attestation.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --environment aitrade-byoc --dossier-ref dossier:byoc-authority/aitrade-byoc --authority-ref authority:byoc/aitrade-byoc --producer-ref oidc:trustai.example/byoc-authority-worker --authority-evidence "live-cloud-account-binding,provider-api,aws:account/123456789012/trustai-byoc,sha256:byoc-live-cloud-account,Provider account export;issued_at=2026-07-04T03:05:00Z;expires_at=2026-12-31T00:00:00Z" --authority-evidence "network-policy-admission-audit-export,provider-api,k8s:networkpolicy/trustai/trustai-api,sha256:byoc-network-policy-admission-export,Provider Kubernetes NetworkPolicy admission export;issued_at=2026-07-04T03:07:00Z;expires_at=2026-12-31T00:00:00Z" --out artifacts/byoc-authority.json
python -m trustai byoc-authority-verify artifacts/byoc-authority.json --deployment-manifest artifacts/deployment-manifest.json --byoc-operator artifacts/byoc-operator-attestation.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --require-fresh --now 2026-07-04T03:10:00Z
python -m trustai byoc-authority-append artifacts/byoc-authority.json artifacts/deployment-manifest.json artifacts/byoc-operator-attestation.json --worm-receipt artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --state .trustai/byoc-authority-demo/evidence-chain.json --tenant byoc-authority-local
```

See `docs/specs/byoc-production-authority-v0.1.md` for the schema.

This is a reference deployment for the proof-pack engine and local API. A
production BYOC installation still needs managed KMS/HSM signing, RFC 3161
timestamping, registry/admission-controller exports, provider network-policy admission/audit exports, network collectors,
object-lock storage, and operational hardening.
