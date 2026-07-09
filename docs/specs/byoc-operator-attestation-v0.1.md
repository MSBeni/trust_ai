# BYOC Operator Attestation v0.1

The BYOC operator attestation binds TrustAI's self-hosted deployment manifest to
immutable storage, legal-hold, backup/restore, tenant, keyring, network, and
operator evidence. It is the local proof shape for the roadmap's production
operator, cloud Object Lock, legal hold, and air-gapped hardening requirements.

This v0.1 artifact does not prove that a live cloud operator or cloud Object
Lock service is continuously enforcing controls. It records the evidence that a
production deployment must preserve and lets offline verifiers detect stale,
tampered, or mismatched deployment and WORM sources.

## Schema

`schema`: `trustai.byoc-operator-attestation/0.1`

Required top-level fields:

- `attestation_id`: canonical hash of the attestation body.
- `signatures`: detached `trustai.signature/0.1` signatures over
  `{attestation_id, byoc_operator}`.
- `mode`: one of `local-reference`, `byoc-operator-attested`,
  `airgap-operator-design`, or `production-design`.
- `environment` and `attested_at`.
- `source`: deployment manifest id/hash, WORM receipt id/hash/content hash, and
  optional legal-hold id/hash.
- `deployment`: deployment manifest metadata and source-file count.
- `operator`: operator ref, version, image, image digest, namespace, service
  account, reconciler, upgrade policy, and rollback policy.
- `tenancy`: tenant id, customer account, data-plane, optional control-plane,
  and keyring references.
- `object_lock`: provider, bucket, region, Object Lock mode, versioning,
  retention mode, default retention, WORM receipt binding, and optional legal
  hold binding.
- `backup`: backup policy, schedule, restore test, RPO, and RTO.
- `network`: ingress mode, egress policy, private endpoint flag, optional
  allowed egress refs, and optional air-gap bundle hash.
- `operation`: actor reference, redacted credential reference, and supporting
  evidence refs.
- `audit_log`: audit-log reference, root hash, and retention timestamp.
- `source_artifacts`, `controls`, and `limitations`.

## Verification

`trustai byoc-operator-verify` checks:

- schema, canonical `attestation_id`, and detached signature.
- deployment manifest signature, source-file hashes, required components, and
  required deployment controls against the supplied worktree root.
- WORM receipt id, stored object existence, stored object hash, stored object
  size, retention timestamp, and optional legal hold via the supplied WORM
  store root.
- Object Lock and versioning are explicitly enabled.
- legal-hold evidence is supplied when `legal_hold_required` is true.
- WORM retention is active or protected by an active legal hold.
- operator image digest, audit root, and optional air-gap bundle hash are
  `sha256` references.
- backup restore test timestamps and non-negative RPO/RTO.
- operation credentials are redacted references and secret-like fields do not
  contain raw material.
- source records and `source_artifacts` match the supplied deployment manifest,
  WORM receipt, and legal hold.

`trustai byoc-operator-append` first verifies the attestation and source
artifacts, then appends `deployment.byoc_operator_attested` to the evidence
chain. The chain entry records the attestation hash, source bindings, operator,
tenancy, Object Lock, backup, network, audit-log, operation, and control summary.

## Example Commands

```powershell
python -m trustai byoc-operator-attestation artifacts/deployment-manifest.json artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --environment aitrade-byoc --operator-ref operator:trustai/byoc --operator-version 0.1.0 --operator-image ghcr.io/trustai/operator:0.1.0 --operator-image-digest sha256:trustai-byoc-operator-digest --namespace trustai --service-account-ref k8s:sa/trustai/operator --reconciler-ref controller:trustai/byoc-operator --upgrade-policy-ref policy:trustai/byoc-upgrade-v0.1 --rollback-policy-ref policy:trustai/byoc-rollback-v0.1 --tenant-id aitrade-local --customer-account-ref aws:123456789012 --data-plane-ref k8s:cluster/aitrade-prod --control-plane-ref trustai:control-plane/local --keyring-ref keyring:.trustai/keyring.local.json --object-lock-provider "Example S3 Object Lock" --object-lock-bucket arn:aws:s3:::trustai-aitrade-evidence --object-lock-region us-east-1 --backup-policy-ref backup:trustai/daily --backup-schedule "rate(1 day)" --restore-test-ref restore-test:trustai/2026-07-04 --restore-test-at 2026-07-04T02:00:00Z --rpo-minutes 60 --rto-minutes 240 --ingress-mode private-load-balancer --egress-policy-ref egress-policy:trustai/deny-by-default --allowed-egress-ref egress:kms --allowed-egress-ref egress:tsa --airgap-bundle-ref bundle:trustai/airgap/2026-07-04 --airgap-bundle-hash sha256:trustai-airgap-bundle --audit-log-ref audit-log:byoc/operator --audit-log-root sha256:byoc-operator-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/byoc-operator --credential-ref env:BYOC_OPERATOR_TOKEN --evidence-ref evidence:byoc/operator --attested-at 2026-07-04T03:00:00Z --out artifacts/byoc-operator-attestation.json
python -m trustai byoc-operator-verify artifacts/byoc-operator-attestation.json artifacts/deployment-manifest.json artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm
python -m trustai byoc-operator-append artifacts/byoc-operator-attestation.json artifacts/deployment-manifest.json artifacts/aitrade-proof-pack.worm-receipt.json --legal-hold artifacts/aitrade-proof-pack.legal-hold.json --root . --store .trustai/worm --state .trustai/byoc-operator-demo/evidence-chain.json --tenant byoc-operator-local --out artifacts/byoc-operator-entry.json
python -m trustai chain-verify --state .trustai/byoc-operator-demo/evidence-chain.json --tenant byoc-operator-local
```

## Production Notes

A live deployment should replace local references with provider-native exports:

- S3 Object Lock compliance-mode configuration, versioning state, bucket policy,
  retention, legal-hold, and privileged deletion denial evidence.
- operator reconciliation events, image provenance, SBOM, admission-controller
  policy, upgrade, and rollback events.
- backup job, immutable backup copy, and restore drill logs.
- customer account, private endpoint, network policy, and air-gap image bundle
  attestations.
- independently retained audit-log roots and retention controls.

The attestation is intentionally explicit about these claims so third parties
can reject incomplete production evidence rather than accepting deployment prose.
