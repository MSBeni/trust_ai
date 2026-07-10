# Helm Chart Validation Receipt v0.1

The roadmap requires a BYOC/self-hosted Helm deployment path, but offline review
environments may not have the Helm binary or a Kubernetes cluster. A Helm chart
validation receipt is a signed, replayable record of deterministic chart-source
checks that prove the reference chart still exposes the expected TrustAI API,
optional demo Job, persistent state, NetworkPolicy ingress/egress controls, and Secret-backed signing key wiring.

This receipt is not a substitute for `helm template`, Kubernetes admission, or
provider-owned release-state exports. It is local evidence that the chart source
itself still satisfies the controls the deployment manifest claims.

## Schema

`schema`: `trustai.helm-chart-validation/0.1`

Required top-level fields:

- `receipt_id`: canonical hash of the receipt body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{receipt_id, receipt}`.
- `generated_at`: RFC3339 creation timestamp.
- `chart`: chart metadata from `deploy/helm/trustai/Chart.yaml`.
- `values`: selected image, tenant, signing secret, and API values from
  `deploy/helm/trustai/values.yaml`.
- `deployment_manifest`: hash binding to a verified deployment manifest.
- `source_files`: hash and size records for the Helm chart sources.
- `checks`: deterministic control checks with `id`, `passed`, `description`,
  and `evidence` fields.
- `summary`: count of passed, failed, and total checks.
- `passed`: true only when every check passed.
- `limitations`: explicit non-production claims.

Default source files:

- `deploy/helm/trustai/Chart.yaml`
- `deploy/helm/trustai/values.yaml`
- `deploy/helm/trustai/templates/configmap.yaml`
- `deploy/helm/trustai/templates/deployment.yaml`
- `deploy/helm/trustai/templates/service.yaml`
- `deploy/helm/trustai/templates/networkpolicy.yaml`
- `deploy/helm/trustai/templates/demo-job.yaml`
- `deploy/helm/trustai/templates/pvc.yaml`

## Required Checks

The v0.1 verifier replays the chart sources and deployment manifest, then
requires these checks to pass:

- chart metadata declares the TrustAI application chart.
- API values include replica, port, state path, control DB, approval store, and
  provider webhook store settings.
- readiness and liveness probe values exist.
- API `Deployment` source exists with expected name, labels, selectors, and
  `trustai serve` arguments.
- API `Deployment` consumes `TRUSTAI_SIGNING_KEY` from a Secret and passes it as
  `--key env:TRUSTAI_SIGNING_KEY`.
- readiness and liveness probes call `/health`.
- API `Deployment` mounts the PVC for state.
- API `Service` exposes the API Deployment through the expected selector and
  named port.
- API `NetworkPolicy` selects the API pods and declares ingress and egress policy types.
- API `NetworkPolicy` restricts ingress by namespace and constrains egress to DNS and configured CIDRs.
- optional demo Job uses the same Secret-backed signing key.
- PVC and tenant ConfigMap templates exist.
- the receipt is bound to a verified deployment manifest.

## Verification

`trustai helm-chart-validation-verify` checks:

- schema and canonical `receipt_id`.
- detached signature.
- every chart source file exists and matches its recorded hash and size.
- every required chart source is present.
- replayed chart metadata, values, source hashes, check results, summary,
  limitations, and deployment-manifest binding match the receipt.
- every check passed and the top-level `passed` field is true.

`trustai helm-chart-validation-append` verifies first, then appends
`deployment.helm_chart.validated` to an evidence chain. The appended entry
records the receipt id/hash, chart metadata, deployment-manifest binding,
source-file count, check summary, and pass/fail state.

## Example Commands

```powershell
python -m trustai deployment-manifest --root . --environment aitrade-byoc --out artifacts/deployment-manifest.json --markdown artifacts/deployment-manifest.md
python -m trustai helm-chart-validation artifacts/deployment-manifest.json --root . --out artifacts/helm-chart-validation.json
python -m trustai helm-chart-validation-verify artifacts/helm-chart-validation.json artifacts/deployment-manifest.json --root .
python -m trustai helm-chart-validation-append artifacts/helm-chart-validation.json artifacts/deployment-manifest.json --root . --state .trustai/helm-validation-demo/evidence-chain.json --tenant helm-validation-local --out artifacts/helm-chart-validation-entry.json
python -m trustai chain-verify --state .trustai/helm-validation-demo/evidence-chain.json --tenant helm-validation-local
```
