# Provider Operations Service Attestation v0.1

Provider operations service attestations bind the provider callback, OAuth/app
lifecycle, audit-worker, callback-storage, and credential-custody receipts to a
single service-hardening claim. The schema is
`trustai.provider-operations-service-attestation/0.1`.

## Contents

- `mode`: one of `provider-operations-attested`, `local-reference`, or
  `production-design`.
- `environment` and `attested_at`: deployment context and signing time.
- `source`: count, hash, schemas, and required source artifact types.
- `service`: service reference, version, provider, image, image digest, binary
  hash, replica bounds, and availability zones.
- `operations`: public ingress, OAuth worker, callback worker, audit worker,
  callback storage, vault, KMS key, scheduler, lease, checkpoint, and external
  call policy references.
- `security`: mTLS, auth, webhook signature, replay window, deduplication,
  rate-limit, network, and egress policy references.
- `audit_log`: provider operations audit-log reference, root hash, and retention
  horizon.
- `operation_actor`: redacted operator credential reference and supporting
  evidence references.
- `source_artifacts`: canonical ids, schemas, and hashes for the bound provider
  receipts and manifests.
- `controls`: derived control statuses for service identity, callback ingress,
  storage/vault/KMS, signature/replay/deduplication, audit scheduling, and audit
  retention.
- `attestation_id` and `signatures`: canonical attestation hash and detached
  signatures.

## Verification

`trustai provider-operations-service-verify` checks:

1. Schema, canonical `attestation_id`, and at least one valid signature.
2. RFC 3339 timestamps and retention after `attested_at`.
3. Service image digest, binary hash, replica floor, replica ceiling, and
   multi-zone evidence.
4. Required operations, security, audit-log, and redacted actor credential
   references.
5. Source-artifact hashes and source summary match supplied artifacts.
6. Deep verification of provider installation, ingress, callback storage,
   lifecycle, lifecycle operation, audit lifecycle operation, audit worker,
   credential custody, and optional callback-store, audit-stream, and
   audit-correlation evidence.
7. Secret-like fields are redacted references rather than raw provider tokens or
   webhook secrets.

## CLI

```powershell
python -m trustai provider-operations-service-attestation --provider-installation artifacts/github-provider-installation.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-lifecycle-operation.json --audit-lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --credential-custody artifacts/provider-credential-custody.json --callback-store artifacts/provider-callback-store.json --callback-store-db .trustai/provider-callbacks.sqlite --audit-stream artifacts/provider-audit-stream.json --audit-correlation artifacts/github-provider-audit-correlation.json --environment aitrade-prod --service-ref provider-ops:trustai/github-prod --service-version 0.1.0 --service-image ghcr.io/trustai/provider-ops:0.1.0 --service-image-digest sha256:trustai-provider-ops-image --service-binary-hash sha256:trustai-provider-ops-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --public-ingress-ref ingress:trustai-example --oauth-worker-ref worker:provider-oauth/github --callback-worker-ref worker:provider-callbacks/github --audit-worker-ref worker:provider-audit/github --storage-ref postgres:provider-callbacks --vault-ref vault:trustai/provider-audit --kms-key-ref kms:trustai/provider-audit-token --mtls-policy-ref policy:provider-ops/mtls-required-v0.1 --auth-policy-ref policy:provider-ops/oidc-authz-v0.1 --webhook-signature-policy-ref policy:provider-ops/webhook-signature-v0.1 --replay-window-ref replay-window:provider-ops/5m --dedup-store-ref sqlite:provider-callbacks/dedup --rate-limit-policy-ref rate-limit:provider-ops/github --network-policy-ref netpol:provider-ops/deny-by-default --egress-policy-ref egress:provider-ops/provider-apis-only --scheduler-ref schedule:provider-audit/github/10m --lease-ref lease:provider-audit/github --checkpoint-ref checkpoint:provider-audit/github --external-call-policy-ref policy:provider-ops/external-calls-v0.1 --audit-log-ref audit-log:provider-ops/service --audit-log-root sha256:provider-ops-service-audit-root --retention-until 2033-07-08T00:00:00Z --actor-ref oidc:trustai.example/provider-ops-operator --credential-ref env:PROVIDER_OPS_TOKEN --evidence-ref evidence:provider-ops/service --attested-at 2026-07-08T05:00:00Z --out artifacts/provider-operations-service-attestation.json
python -m trustai provider-operations-service-verify artifacts/provider-operations-service-attestation.json --provider-installation artifacts/github-provider-installation.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-lifecycle-operation.json --audit-lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --credential-custody artifacts/provider-credential-custody.json --callback-store artifacts/provider-callback-store.json --callback-store-db .trustai/provider-callbacks.sqlite --audit-stream artifacts/provider-audit-stream.json --audit-correlation artifacts/github-provider-audit-correlation.json
python -m trustai provider-operations-service-append artifacts/provider-operations-service-attestation.json --provider-installation artifacts/github-provider-installation.json --provider-ingress artifacts/provider-ingress.json --callback-storage artifacts/provider-callback-storage.json --lifecycle artifacts/provider-lifecycle.json --lifecycle-operation artifacts/provider-lifecycle-operation.json --audit-lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --audit-worker artifacts/provider-audit-worker.json --credential-custody artifacts/provider-credential-custody.json --callback-store artifacts/provider-callback-store.json --callback-store-db .trustai/provider-callbacks.sqlite --audit-stream artifacts/provider-audit-stream.json --audit-correlation artifacts/github-provider-audit-correlation.json --state .trustai/provider-operations-service-demo/evidence-chain.json --tenant provider-operations-service-local --out artifacts/provider-operations-service-entry.json
```

## Limits

This attestation strengthens the local/reference provider callback story by
binding the signed source receipts to service fleet, storage, vault/KMS,
network, scheduling, audit, actor, and redacted credential controls. It does not
claim that this workspace has a live TrustAI-operated provider service fleet,
live provider-owned vault/KMS calls, or live external GitHub/GitLab/Slack API
posting unless those live receipts are supplied as source artifacts.
