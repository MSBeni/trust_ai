# BYOC / Self-Hosted Reference Deployment

The roadmap calls for BYOC and self-hosted deployment because regulated buyers
will not send sensitive agent traces to a startup SaaS by default. This
repository includes a minimal reference deployment:

- `deploy/docker/Dockerfile` builds the local CLI runtime.
- `deploy/helm/trustai` runs the bundled aitrade proof-pack flow as a Kubernetes
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
```

## Deployment Manifest

The reference scaffold can be bound into a signed deployment manifest for
third-party review:

```powershell
python -m trustai deployment-manifest --root . --environment aitrade-byoc --out artifacts/deployment-manifest.json --markdown artifacts/deployment-manifest.md
python -m trustai deployment-verify artifacts/deployment-manifest.json --root .
```

`trustai deployment-append` can then append the verified manifest as
`deployment.manifest.published` evidence. See
`docs/specs/deployment-manifest-v0.1.md` for the schema.

This is a reference deployment for the proof-pack engine. A production BYOC
installation still needs managed KMS/HSM signing, RFC 3161 timestamping,
network collectors, object-lock storage, and operational hardening.
