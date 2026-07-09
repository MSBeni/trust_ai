# EU Data-Plane Attestation v0.1

The EU data-plane attestation binds TrustAI deployment and BYOC operator
evidence to an EU-hosted residency and digital-sovereignty proof. It is the
local proof shape for the roadmap's Phase 3 EU-hosted data plane, Frankfurt
deployment story, data residency, key residency, subprocessor disclosure, and
transfer-governance requirements.

This v0.1 artifact does not prove that a live Frankfurt cloud service is
continuously operating. It records the signed source artifacts and control
evidence that a production deployment must preserve so an offline verifier can
detect stale, tampered, or non-EU source evidence.

## Schema

`schema`: `trustai.eu-data-plane-attestation/0.1`

Required top-level fields:

- `attestation_id`: canonical hash of the attestation body.
- `signatures`: detached `trustai.signature/0.1` signatures over
  `{attestation_id, eu_data_plane}`.
- `mode`: one of `local-reference`, `eu-data-plane-attested`, or
  `production-design`.
- `environment` and `attested_at`.
- `source`: deployment manifest id/hash, BYOC operator attestation id/hash,
  BYOC tenant/data-plane refs, and optional EU AI Act document id/hash.
- `deployment`: deployment manifest metadata.
- `regions`: primary region/location, availability zones, replica regions,
  backup regions, analytics/log regions, and BYOC Object Lock region.
- `residency`: tenant, data-plane, customer account, data categories,
  subprocessors, residency policy, data-classification policy, DPA, transfer
  impact assessment, optional SCC, deletion, export, and cross-border egress
  posture.
- `sovereignty`: customer-managed key flag, keyring, encryption key, key
  region, key-access policy, and optional HSM reference.
- `network`: ingress/private endpoint posture, BYOC egress policy, network
  policy, support-access policy, JIT support flag, and break-glass policy.
- `audit`: audit, access, and transfer log references/root hashes plus
  retention timestamp.
- `operation`: actor reference, redacted credential reference, and supporting
  evidence refs.
- `source_artifacts`, `controls`, and `limitations`.

## Verification

`trustai eu-data-plane-verify` checks:

- schema, canonical `attestation_id`, and detached signature.
- deployment manifest signature and source-file hashes against the supplied
  worktree root.
- BYOC operator attestation signature, tenant/data-plane/keyring binding, and
  Object Lock region binding.
- optional EU AI Act technical-documentation signature and hash binding.
- primary, replica, backup, analytics, log, Object Lock, and KMS key regions
  are in the EU cloud-region allowlist.
- the BYOC Object Lock region matches the attested object-lock region.
- customer-managed keys are enabled and key residency remains in the EU.
- data categories and subprocessor references are present.
- DPA and transfer-impact references are present, and SCC evidence is required
  when cross-border egress is allowed.
- private endpoint and network/access policies are recorded.
- audit, access, and transfer log roots are `sha256` references and retention
  extends past `attested_at`.
- source records and `source_artifacts` match supplied deployment, BYOC, and
  optional EU AI Act sources.
- operation credentials are redacted references and secret-like fields do not
  contain raw material.

`trustai eu-data-plane-append` first verifies the attestation and supplied
sources, then appends `deployment.eu_data_plane_attested` to the evidence
chain. The chain entry records the attestation hash, source bindings, region,
residency, sovereignty, network, audit, operation, and control summary.

## Example Commands

```powershell
python -m trustai eu-data-plane-attestation artifacts/deployment-manifest.json artifacts/eu-byoc-operator-attestation.json --root . --environment aitrade-eu-prod --tenant-id aitrade-eu --data-plane-ref k8s:cluster/aitrade-eu-central-1 --control-plane-ref trustai:control-plane/eu --primary-region eu-central-1 --primary-location "Frankfurt, Germany" --availability-zone eu-central-1a --availability-zone eu-central-1b --availability-zone eu-central-1c --replica-region eu-west-1 --backup-region eu-central-1 --backup-region eu-west-3 --analytics-region eu-central-1 --log-region eu-central-1 --data-category agent_trace_hashes --data-category proof_pack_metadata --data-category policy_decision_metadata --subprocessor-ref subprocessor:aws-eu --subprocessor-ref subprocessor:example-rfc3161-tsa-eu --residency-policy-ref policy:trustai/eu-residency-v0.1 --data-classification-policy-ref policy:trustai/eu-data-classification-v0.1 --dpa-ref dpa:trustai/aitrade-eu-2026 --transfer-impact-assessment-ref tia:trustai/aitrade-eu-2026 --deletion-policy-ref policy:trustai/eu-deletion-v0.1 --data-export-policy-ref policy:trustai/eu-export-v0.1 --encryption-key-ref kms:eu-central-1:trustai/aitrade-eu/evidence --kms-key-region eu-central-1 --key-access-policy-ref policy:kms/aitrade-eu-key-access-v0.1 --hsm-ref hsm:eu-central-1/trustai-eu --network-policy-ref netpol:trustai/eu-deny-by-default --support-access-policy-ref policy:trustai/eu-jit-support-v0.1 --breakglass-policy-ref policy:trustai/eu-breakglass-v0.1 --audit-log-ref audit-log:eu-data-plane/service --audit-log-root sha256:eu-data-plane-audit-root --access-log-ref access-log:eu-data-plane/sessions --access-log-root sha256:eu-data-plane-access-root --transfer-log-ref transfer-log:eu-data-plane/egress --transfer-log-root sha256:eu-data-plane-transfer-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/eu-data-plane-operator --credential-ref env:EU_DATA_PLANE_TOKEN --evidence-ref evidence:eu-data-plane/service --attested-at 2026-07-04T04:00:00Z --out artifacts/eu-data-plane-attestation.json
python -m trustai eu-data-plane-verify artifacts/eu-data-plane-attestation.json artifacts/deployment-manifest.json artifacts/eu-byoc-operator-attestation.json --root .
python -m trustai eu-data-plane-append artifacts/eu-data-plane-attestation.json artifacts/deployment-manifest.json artifacts/eu-byoc-operator-attestation.json --root . --state .trustai/eu-data-plane-demo/evidence-chain.json --tenant eu-data-plane-local --out artifacts/eu-data-plane-entry.json
python -m trustai chain-verify --state .trustai/eu-data-plane-demo/evidence-chain.json --tenant eu-data-plane-local
```

## Production Notes

A live deployment should replace local references with provider-native exports:

- cloud region and availability-zone placement exports for every data store,
  trace store, log store, backup copy, and analytics system.
- customer-managed KMS/HSM key policies, grants, key residency, rotation, and
  denial-of-export evidence.
- DPA, subprocessor, transfer-impact, SCC, support access, JIT approval, and
  break-glass records.
- network policy, private endpoint, egress gateway, and transfer log roots.
- independently retained audit, access, and transfer log roots with retention
  at least as long as the governed proof-pack retention period.

The attestation is intentionally explicit about what is local reference evidence
versus production evidence so regulators and auditors can reject incomplete
sovereignty claims.
