# Deployment Image Integrity Receipt v0.1

The deployment image integrity receipt binds a BYOC/self-hosted deployment
manifest to the container image reference that the Helm chart will run, plus the
image digest, SBOM, build provenance, and signature artifacts supplied by the
builder or release pipeline.

It closes the first production-hardening item in the deployment manifest: image
signing and SBOM/provenance evidence. The receipt is intentionally offline and
source-replayable. It does not build or pull the image; it proves that the
reviewed deployment manifest, Dockerfile, Helm image values, and supplied
supply-chain artifacts have not changed since the receipt was signed.

## Schema

`schema`: `trustai.deployment-image-integrity/0.1`

Required top-level fields:

- `receipt_id`: canonical hash of the receipt body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{receipt_id, receipt}`.
- `generated_at`: RFC3339 creation timestamp.
- `image`: chart-bound image reference, sha256 image digest, manifest/chart
  image refs, tag, pull policy, and pinned `image@digest` reference.
- `deployment_manifest`: verified deployment manifest id/hash and replay
  summary.
- `source_files`: Dockerfile, Helm values/deployment template, package metadata,
  API server, and CLI source hashes.
- `artifacts`: exactly one SBOM, provenance, and signature artifact hash record.
- `checks`: deterministic pass/fail controls.
- `summary`: passed, failed, and total check counts.
- `passed`: true only when all checks pass.
- `limitations`: explicit claims this receipt does not make.

Default source files:

- `deploy/docker/Dockerfile`
- `deploy/helm/trustai/values.yaml`
- `deploy/helm/trustai/templates/deployment.yaml`
- `pyproject.toml`
- `src/trustai/server.py`
- `src/trustai/cli.py`

## Verification

`trustai deployment-image-integrity-verify` checks:

- schema and canonical `receipt_id`.
- detached receipt signature.
- every source file exists in the supplied root.
- source file `sha256` and size match the current worktree.
- SBOM, provenance, and signature artifact files exist and match their recorded
  hashes and sizes.
- the receipt replays from the supplied deployment manifest and artifact paths.
- the deployment manifest verifies.
- the declared image reference matches the deployment manifest and Helm values.
- the image digest is a `sha256:<64 hex>` reference.
- the image tag is explicit and not `latest`.
- the Dockerfile copies the TrustAI source and uses the package entrypoint.
- the Helm API Deployment consumes the chart image repository, tag, and pull
  policy values.

`trustai deployment-image-integrity-append` first verifies the receipt, then
appends `deployment.image.integrity_attested` to an evidence chain. The appended
entry records the receipt id/hash, image reference and digest, deployment
manifest binding, artifact count, source count, check summary, and pass status.

## Example Commands

```powershell
python -m trustai deployment-manifest --root . --environment aitrade-byoc --out artifacts/deployment-manifest.json --markdown artifacts/deployment-manifest.md
'{"sbom":"trustai","version":"0.1.0"}' | Set-Content -NoNewline artifacts/trustai-image.sbom.json
'{"builder":"trustai-local","source":"git"}' | Set-Content -NoNewline artifacts/trustai-image.provenance.json
'sigstore-placeholder-signature' | Set-Content -NoNewline artifacts/trustai-image.sig
python -m trustai deployment-image-integrity artifacts/deployment-manifest.json --root . --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --sbom artifacts/trustai-image.sbom.json --provenance artifacts/trustai-image.provenance.json --signature artifacts/trustai-image.sig --out artifacts/deployment-image-integrity.json
python -m trustai deployment-image-integrity-verify artifacts/deployment-image-integrity.json artifacts/deployment-manifest.json --root .
python -m trustai deployment-image-integrity-append artifacts/deployment-image-integrity.json artifacts/deployment-manifest.json --root . --state .trustai/image-integrity-demo/evidence-chain.json --tenant image-integrity-local --out artifacts/deployment-image-integrity-entry.json
python -m trustai chain-verify --state .trustai/image-integrity-demo/evidence-chain.json --tenant image-integrity-local
```

## Production Notes

A production release pipeline should replace local placeholder artifacts with
registry/exported evidence: signed image digest, SPDX or CycloneDX SBOM,
SLSA-style provenance, Sigstore or KMS-backed signature material, admission
controller policy results, registry immutability settings, vulnerability scan
summaries, and Kubernetes image-pull audit logs.