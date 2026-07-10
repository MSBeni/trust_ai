# TrustAI BYOC Production Authority Dossier v0.1

Status: draft

## Purpose

The BYOC production authority dossier binds a signed TrustAI deployment
manifest and a signed BYOC operator attestation to the external authority
evidence needed before TrustAI can claim production BYOC or self-hosted
readiness for regulated buyers.

The dossier is designed for offline review. It stores hashes, references,
freshness windows, control summaries, and source bindings. It must not store
raw customer cloud, Kubernetes, KMS, object-store, or operator credentials.

## Schema

`trustai.byoc-production-authority-dossier/0.1`

## Source Bindings

The dossier binds:

- deployment manifest ID, hash, schema, mode, environment, artifact type, and
  source file count
- BYOC operator attestation ID, hash, schema, mode, environment, operator
  image digest, namespace, source artifacts, and control summary
- Object Lock/WORM receipt, retention, legal hold, bucket, region, and
  versioning fields from the operator attestation
- tenant/customer account, data-plane, control-plane, and keyring references
- backup/restore and RPO/RTO evidence references
- private ingress, egress policy, NetworkPolicy admission/audit evidence requirements, and optional air-gap bundle references
- immutable operator audit-log root and retention window

## Modes

- `local-dossier`: records local/reference source bindings only.
- `operator-dossier`: records a signed BYOC operator attestation and partial
  production authority evidence without claiming complete production authority.
- `production-dossier`: claims production BYOC/self-hosted authority only when
  all production authority requirements are covered with fresh evidence and
  complete source bindings.

## Production Authority Requirements

The fixed checklist is:

- `live-cloud-account-binding`
- `object-lock-compliance-mode`
- `legal-hold-retention-export`
- `air-gapped-installation-evidence`
- `helm-release-and-namespace-state`
- `network-policy-admission-audit-export`
- `operator-controller-reconciliation`
- `customer-controlled-kms-key-custody`
- `backup-restore-dr-evidence`
- `network-egress-private-ingress-controls`
- `immutable-provider-audit-logs`
- `tenant-data-plane-isolation`

Each evidence item records:

- requirement ID
- authority kind
- evidence reference
- evidence hash, prefixed with `sha256:`
- description
- optional issuer, subject, source URI, issued_at, and expires_at
- canonical evidence ID

## Verification Rules

Verifiers must:

- recompute `dossier_id` from the canonical body
- verify at least one dossier signature
- replay the deployment manifest when supplied
- replay the BYOC operator attestation when supplied
- compare source bindings to supplied deployment/operator artifacts
- recompute the authority evidence summary
- recompute controls from the dossier body, including the dedicated NetworkPolicy admission/audit evidence control
- reject malformed authority evidence and unsupported authority kinds
- reject raw secret-like values that are not references or hashes
- reject `production-dossier` mode unless all production authority requirements
  are covered and all evidence items are fresh

Strict verification may additionally require complete checklist coverage and
fresh evidence windows.

## Evidence Chain Entry

`deployment.byoc_production_authority_recorded`

The chain payload records the dossier ID/hash, mode, environment, producer and
authority references, source binding summary, authority evidence summary,
control summary, and authority evidence metadata.
