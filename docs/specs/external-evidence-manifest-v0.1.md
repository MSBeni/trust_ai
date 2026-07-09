# TrustAI External Evidence Manifest v0.1

Status: Draft

The external evidence manifest binds live authority artifacts to the roadmap
requirements that a local reference implementation cannot prove by itself. It is
the bridge between `roadmap-audit` output and production completion evidence:
GitHub Actions run exports, KMS/HSM attestations, RFC 3161 TSA receipts, cloud
Object Lock reports, provider API responses, hosted service audit roots,
identity-provider events, regulator acknowledgements, insurer responses,
standards-body dockets, and customer acceptance artifacts can all be supplied as
hashed files and verified offline.

## Schema

`trustai.external-evidence-manifest/0.1`

## Required Fields

- `schema`: fixed schema identifier.
- `manifest_id`: canonical hash of the manifest body without `manifest_id`.
- `generated_at`: RFC3339 timestamp.
- `manifest_ref`: caller-supplied reference for the dossier.
- `source_roadmap_audit`: `audit_id`, audit content hash, and completion
  position for the roadmap audit this manifest satisfies.
- `required_external_requirements`: every `reference-attested` requirement from
  the roadmap audit.
- `evidence`: supplied external evidence artifacts.
- `summary`: coverage totals and missing requirement IDs.
- `limitations`: explicit non-claims about live fetching and issuer quality.

## Evidence Item

Each evidence item contains:

- `evidence_id`: canonical hash of the evidence item body.
- `requirement_id`: a `reference-attested` roadmap requirement ID.
- `authority_kind`: one of `ci-run`, `kms-hsm`, `tsa`,
  `cloud-object-lock`, `provider-api`, `hosted-service`,
  `identity-provider`, `regulator`, `insurer`, `standards-body`, `customer`,
  or `other`.
- `path`: repository-relative path to the supplied evidence artifact.
- `sha256`: SHA-256 hash of the supplied artifact.
- `description`: short human-readable reason the artifact satisfies the
  requirement.
- Optional `issuer`, `subject`, `source_uri`, `issued_at`, and `expires_at`
  fields.

## Verification Rules

A verifier MUST:

1. Recompute `manifest_id` from the canonical manifest body.
2. Verify the supplied roadmap audit first.
3. Recompute the roadmap audit content hash and source audit metadata.
4. Confirm the required requirement list exactly matches `reference-attested`
   roadmap audit requirements.
5. Reject evidence for unknown or non-external requirement IDs.
6. Reject absolute paths or paths containing `..`.
7. Re-hash every evidence artifact and compare it to the recorded SHA-256.
8. Recompute coverage summary and missing requirement IDs.
9. When complete production evidence is required, reject manifests that do not
   cover every reference-attested requirement.

The manifest verifies that supplied external evidence has not changed and is
mapped to the right roadmap gap. It does not independently validate the legal or
technical authority of the issuer beyond the artifact provided.
