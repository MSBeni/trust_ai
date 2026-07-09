# TrustAI Re-execution Runner Worker Receipt v0.1

Runner service attestations bind re-execution evidence to a hosted service
envelope. A runner worker receipt records one scheduled worker operation inside
that envelope: the lease, checkpoint, queue message, job hash, artifact/result
custody, runtime audit roots, request/response hashes, metrics, audit-log root,
and redacted worker credential reference.

This artifact narrows the gap between service design and continuously operated
runner fleets. It is designed for third-party review of how a specific
re-execution run or reconciliation task was scheduled, executed, and recorded.

## Schema

`schema`: `trustai.reexecution-runner-worker/0.1`

Required top-level fields:

- `worker_operation_id`: canonical hash of the receipt body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{worker_operation_id, reexecution_runner_worker}`.
- `mode`: `local-reference`, `scheduled-worker`, `hosted-worker`,
  `isolated-runner-worker`, or `production-design`.
- `environment`: deployment/environment label.
- `recorded_at`: RFC3339 completion timestamp for the worker operation.
- `service`: source runner service attestation id/hash plus service, queue,
  lease, checkpoint, custody, KMS, and audit summary.
- `source`: source-artifact count, aggregate source hash, schemas, required
  source types, and source artifact records.
- `worker`: worker reference, run reference, operation kind, actor, start/end
  timestamps, attempt counters, success flag, and optional error reference.
- `scheduler`: schedule, cadence, lease, checkpoint, checkpoint hash, cursor
  references, and next-run timestamp.
- `execution`: queue, queue message, dead-letter queue, job hash, artifact
  manifest hash, result bundle hash, isolation/runtime audit roots, and
  request/response evidence.
- `observability`: metrics reference, audit-log reference/root, retention
  deadline, and supporting evidence references.
- `credential`: redacted worker credential reference.
- `source_artifacts`: hashes of the runner service attestation, source
  isolation attestation, runner evidence, policy, and optional re-execution
  report supplied to verification.
- `controls`: implementation/planned status for source replay, hosted mode,
  scheduler/lease/checkpoint, queue/job custody, runtime audit roots, and
  worker outcome.

Raw worker credentials, provider tokens, raw audit logs, raw queue payloads, and
raw result bundles are never copied into the receipt.

## Verification

`trustai reexecution-runner-worker-verify` checks:

- receipt schema and canonical `worker_operation_id`.
- detached signature over the receipt body.
- supported mode and RFC3339 timestamps.
- supplied re-execution runner service attestation, including replay of source
  isolation, runner evidence, policy, and report artifacts.
- `service.attestation_hash` and `source_artifacts` match supplied artifacts.
- worker operation kind, attempt counters, and success/error consistency.
- scheduler cadence, lease, checkpoint, and checkpoint hash.
- queue, job hash, artifact manifest hash, result bundle hash, isolation audit
  root, optional runtime audit root, and request/response hashes.
- metrics, audit root, retention ordering, and evidence refs.
- worker credential is represented only by a redacted reference.
- absence of raw secret-like fields outside approved redacted references.

`trustai reexecution-runner-worker-append` first verifies the receipt and source
artifacts, then appends `reexecution.runner_worker_recorded` to an evidence
chain. The chain entry records the worker operation id/hash, service/source
bindings, worker metadata, scheduler metadata, execution metadata,
observability metadata, redacted credential reference, and control summary.

## Example Commands

```powershell
python -m trustai reexecution-runner-worker --service-attestation artifacts/reexecution-runner-service-attestation.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --mode hosted-worker --environment aitrade-prod --worker-ref worker:reexecution/runner --run-ref worker-run:reexecution/aitrade/2026-07-04T04:08:00Z --operation-kind reexecution_run --actor-ref oidc:trustai.example/reexecution-runner-worker --schedule-ref schedule:reexecution/runner/1m --cadence-seconds 60 --lease-ref lease:reexecution/runner/2026-07-04T04:08:00Z --checkpoint-ref checkpoint:reexecution/runner/aitrade --checkpoint-hash sha256:reexecution-runner-worker-checkpoint --previous-cursor-ref cursor:reexecution/runner/before --next-cursor-ref cursor:reexecution/runner/after --queue-ref queue:reexecution/runs --queue-message-ref queue-message:reexecution/aitrade/2026-07-04T04:08:00Z --dead-letter-queue-ref queue:reexecution/runs-dlq --job-ref job:reexecution/aitrade/2026-07-04T04:08:00Z --job-hash sha256:reexecution-runner-worker-job --artifact-manifest-ref s3:trustai-reexecution-artifacts/aitrade/2026-07-04/manifest.json --artifact-manifest-hash sha256:reexecution-runner-worker-artifacts --result-bundle-ref s3:trustai-reexecution-results/aitrade/2026-07-04/results.json --result-bundle-hash sha256:reexecution-runner-worker-results --isolation-audit-ref audit-log:reexecution/isolation/runner-worker --isolation-audit-root sha256:reexecution-runner-worker-isolation-audit-root --runtime-audit-ref audit-log:reexecution/runtime/runner-worker --runtime-audit-root sha256:reexecution-runner-worker-runtime-audit-root --request-hash sha256:reexecution-runner-worker-request --response-status 200 --response-hash sha256:reexecution-runner-worker-response --metrics-ref metrics:reexecution/runner-worker --audit-log-ref audit-log:reexecution/runner-worker --audit-log-root sha256:reexecution-runner-worker-audit-root --credential-ref env:REEXECUTION_RUNNER_WORKER_TOKEN --retention-until 2033-07-04T00:00:00Z --evidence-ref evidence:reexecution/runner-worker --started-at 2026-07-04T04:08:00Z --completed-at 2026-07-04T04:09:00Z --next-run-at 2026-07-04T04:09:00Z --out artifacts/reexecution-runner-worker.json
python -m trustai reexecution-runner-worker-verify artifacts/reexecution-runner-worker.json --service-attestation artifacts/reexecution-runner-service-attestation.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json
python -m trustai reexecution-runner-worker-append artifacts/reexecution-runner-worker.json --service-attestation artifacts/reexecution-runner-service-attestation.json artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --state .trustai/reexecution-runner-worker-demo/evidence-chain.json --tenant reexecution-runner-worker-local --out artifacts/reexecution-runner-worker-entry.json
python -m trustai chain-verify --state .trustai/reexecution-runner-worker-demo/evidence-chain.json --tenant reexecution-runner-worker-local
```

## Production Notes

This v0.1 receipt records worker operation evidence and source-artifact replay.
It does not by itself prove a live, continuously operated runner fleet.
Production deployments should replace local references with orchestrator job
exports, queue and lease-store records, checkpoint-store exports, runtime-native
container audit logs, immutable artifact/result store manifests, metrics/alert
events, and WORM audit retention evidence.
