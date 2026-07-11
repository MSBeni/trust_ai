# TrustAI BYOC Production Authority Dossier v0.1

Status: draft

## Purpose

The BYOC production authority dossier binds a signed TrustAI deployment
manifest and a signed BYOC operator attestation to the external authority
evidence needed before TrustAI can claim production BYOC or self-hosted
readiness for regulated buyers.

The dossier is designed for offline review. It stores hashes, references,
freshness windows, control summaries, source bindings, and optional retained
authority artifacts that can be hash-replayed from local source files. It must
not store raw customer cloud, Kubernetes, KMS, object-store, or operator
credentials.

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
- optional retained authority artifacts, each repository-relative and hash-bound
  to a matching authority evidence item

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
- derived `source_context` computed from `source_binding`
- canonical evidence ID

## Authority Artifacts

`authority_artifacts` is optional. Each item records a retained source artifact
that can be replayed by an offline auditor:

- requirement ID
- evidence reference and evidence ID copied from the matched evidence item
- repository-relative path
- SHA-256 byte hash, prefixed with `sha256:`
- byte size
- canonical artifact ID

The retained artifact hash must equal the matched authority evidence hash. A
path must be repository-relative and must not contain `..` traversal segments.
When multiple evidence items cover the same requirement, the artifact input must
include `evidence_ref` to disambiguate the match.

`artifact_summary` records artifact count, requirement count, covered
requirement IDs, and an artifact hash root over retained artifact hashes.

## Verification Rules

Verifiers must:

- recompute `dossier_id` from the canonical body
- verify at least one dossier signature
- replay the deployment manifest when supplied
- replay the BYOC operator attestation when supplied
- compare source bindings to supplied deployment/operator artifacts
- reject incomplete source bindings even when raw source artifacts are omitted,
  including missing nested deployment, operator, source artifact, Object Lock,
  WORM receipt, legal hold, tenancy, network, backup, and audit-log fields
- recompute the authority evidence summary
- recompute the authority artifact summary
- replay retained authority artifact files when present and compare their hashes
  to matching authority evidence hashes
- reject absolute or parent-traversing retained artifact paths
- optionally compare caller-supplied `--authority-artifact` inputs to the
  dossier's retained artifact metadata
- recompute controls from the dossier body, including the dedicated NetworkPolicy admission/audit evidence and artifact replay controls
- reject malformed authority evidence, unsupported authority kinds, mismatched
  evidence IDs, missing `source_context`, and `source_context` values that do
  not match `source_binding`
- reject raw secret-like values that are not references or hashes
- reject `production-dossier` mode unless all production authority requirements
  are covered, all evidence items are fresh, and deployment, BYOC operator,
  Object Lock, legal hold, customer account, keyring, backup, network, and
  audit-log bindings are complete

Strict verification may additionally require complete checklist coverage and
fresh evidence windows.

## Evidence Chain Entry

`deployment.byoc_production_authority_recorded`

The chain payload records the dossier ID/hash, mode, environment, producer and
authority references, source binding summary, authority evidence summary,
authority artifact summary, control summary, authority evidence metadata
including `source_context`, and retained authority artifact metadata.