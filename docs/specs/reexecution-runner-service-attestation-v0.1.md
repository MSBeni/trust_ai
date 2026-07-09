# TrustAI Re-execution Runner Service Attestation v0.1

Re-execution isolation attestations bind a runner to sandbox controls. A
runner service attestation binds that source isolation evidence to the hosted
service envelope that schedules, queues, executes, records, and audits repeated
eval runs.

This artifact is for third-party review of service-level operating controls. It
records runner image and binary integrity, replica and availability-zone
configuration, scheduler cadence, queue and dead-letter queue, lease and
checkpoint stores, concurrency and retry policy, admission and tenant isolation,
network and egress policy, artifact and result custody, idempotency, secrets and
KMS references, metrics, alerting, audit-log root, retention deadline, actor
reference, and redacted service credential reference.

## Schema

`schema`: `trustai.reexecution-runner-service-attestation/0.1`

Required top-level fields:

- `attestation_id`: canonical hash of the attestation body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{attestation_id, reexecution_runner_service}`.
- `mode`: `local-reference`, `isolated-runner-service`, or `production-design`.
- `environment`: deployment/environment label.
- `attested_at`: RFC3339 timestamp for the service evidence record.
- `source`: source isolation attestation id/hash/mode, runner evidence id/hash,
  optional policy and report ids/hashes, run count, source runner image digest,
  source network mode, source read-only rootfs flag, and source audit-log
  reference/root.
- `service`: service reference, version, runner image, runner image digest,
  runner binary hash, replica range, and availability zones.
- `scheduler`: scheduler reference, cadence, queue, dead-letter queue, lease
  store, checkpoint store, max concurrency, and retry policy reference.
- `execution_controls`: isolation profile, admission policy, tenant isolation,
  network policy, egress policy, artifact store, result store, idempotency
  store, secret store, KMS key, and replayed source isolation controls.
- `observability`: metrics and alert policy references.
- `operation`: actor reference, redacted service credential reference, and
  optional supporting evidence references.
- `audit_log`: audit-log reference, audit-log root hash, and retention deadline.
- `source_artifacts`: hashes of the source isolation attestation, runner
  evidence, policy, and optional re-execution report supplied to verification.
- `controls`: implementation/planned-production status for image integrity,
  fleet redundancy, scheduler/queue/lease controls, isolation/admission/egress,
  artifact/result custody, and observability/audit controls.

Runner service credentials, raw secrets, raw audit logs, provider API tokens,
and raw KMS material are never copied into the attestation.

## Verification

`trustai reexecution-runner-service-verify` checks:

- attestation schema and canonical `attestation_id`.
- detached signature over the attestation body.
- RFC3339 `attested_at` and audit-log retention ordering.
- supported mode.
- full verification of supplied re-execution isolation attestation.
- full verification of supplied runner evidence, policy, and optional report
  through the source isolation replay.
- source record and `source_artifacts` match the supplied source artifacts.
- service runner image digest matches the source isolation runner image digest
  when the source records one.
- service runner image digest, runner binary hash, source artifact hashes, and
  audit-log root are SHA-256 references.
- replica floor is at least two, replica ceiling is not below the floor, and at
  least two availability zones are present.
- scheduler, queue, dead-letter queue, lease, checkpoint, concurrency, and retry
  policy references exist.
- isolation profile, admission policy, tenant isolation, network policy, egress
  policy, artifact store, result store, idempotency store, secret store, and KMS
  key references exist.
- source network mode is disabled and source read-only rootfs is true.
- operation credentials are represented only by redacted references.
- absence of raw secret-like fields outside approved redacted references.

`trustai reexecution-runner-service-append` first verifies the service
attestation and source artifacts, then appends
`reexecution.runner_service_attested` to an evidence chain. The appended entry
contains the attestation id/hash, source bindings, service, scheduler,
execution controls, observability, operation metadata, audit metadata,
source-artifact hashes, and control summary.

## Example Commands

```powershell
python -m trustai reexecution-runner-service-attestation artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --environment aitrade-prod --service-ref runner-service:trustai/reexecution-prod --service-version 0.1.0 --runner-image ghcr.io/trustai/reexecution-runner:0.1.0 --runner-binary-hash sha256:trustai-reexecution-runner-binary --replicas-min 3 --replicas-max 9 --availability-zone us-east-1a --availability-zone us-east-1b --availability-zone us-east-1c --scheduler-ref scheduler:reexecution/runner --schedule-cadence-seconds 60 --queue-ref queue:reexecution/runs --dead-letter-queue-ref queue:reexecution/runs-dlq --lease-store-ref postgres:reexecution/leases --checkpoint-store-ref postgres:reexecution/checkpoints --max-concurrency 12 --retry-policy-ref policy:reexecution/retry-v0.1 --isolation-profile-ref isolation-profile:reexecution/container-v0.1 --admission-policy-ref admission:reexecution/signed-plans-only --tenant-isolation-ref tenant-isolation:reexecution/aitrade --network-policy-ref netpol:reexecution/deny-by-default --egress-policy-ref egress-policy:deny-all --artifact-store-ref s3:trustai-reexecution-artifacts --result-store-ref s3:trustai-reexecution-results --idempotency-store-ref postgres:reexecution/idempotency --secret-store-ref vault:reexecution/secrets --kms-key-ref kms:example/reexecution-runner --metrics-ref metrics:reexecution/runner-service --alert-policy-ref alert:reexecution/runner-service --audit-log-ref audit-log:reexecution/runner-service --audit-log-root sha256:reexecution-runner-service-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/reexecution-runner-operator --credential-ref env:REEXECUTION_RUNNER_SERVICE_TOKEN --evidence-ref evidence:reexecution/runner-service --attested-at 2026-07-04T04:07:00Z --out artifacts/reexecution-runner-service-attestation.json
python -m trustai reexecution-runner-service-verify artifacts/reexecution-runner-service-attestation.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json
python -m trustai reexecution-runner-service-append artifacts/reexecution-runner-service-attestation.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --state .trustai/reexecution-runner-service-demo/evidence-chain.json --tenant reexecution-runner-service-local --out artifacts/reexecution-runner-service-entry.json
python -m trustai chain-verify --state .trustai/reexecution-runner-service-demo/evidence-chain.json --tenant reexecution-runner-service-local
```

## Production Notes

This v0.1 attestation records the service evidence a production re-execution
runner should preserve. It does not claim live kernel/container enforcement by
itself. A production deployment should replace local references with
orchestrator admission logs, signed runner image provenance, queue and lease
exports, runtime audit logs, immutable artifact/result store records, provider
KMS/secret-manager audit exports, scheduler metrics, alert events, and WORM
audit retention evidence.
