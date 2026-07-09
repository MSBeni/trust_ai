# Provider Audit Worker Receipts v0.1

Provider audit worker receipts record a scheduled or hosted worker run that
retrieves provider audit-log windows, advances cursor checkpoints, and optionally
correlates those audit rows to TrustAI provider webhook or delivery evidence.

## Receipt

The JSON receipt uses schema `trustai.provider-audit-worker/0.1` and includes:

- `worker_operation_id`: canonical hash of the signed receipt body.
- `mode`: one of `local-reference`, `scheduled-worker`, `hosted-worker`,
  `provider-authenticated-streamer`, or `production-design`.
- `worker`: worker reference, run reference, operation kind, actor, timing,
  attempt counters, success state, and optional error reference.
- `scheduler`: schedule reference, cadence, lease reference, checkpoint
  reference/hash, cursor handoff, and next-run timestamp.
- `sources.stream_receipts`: hashes and replay metadata for signed provider
  audit stream receipts.
- `sources.correlations`: optional provider audit correlation receipt bindings.
- `sources.lifecycle_operation`: optional provider lifecycle operation receipt
  that authorized or refreshed the audit stream.
- `sources.lifecycle`: optional provider lifecycle manifest binding.
- `credential`: a redacted provider credential reference.
- `controls`: implemented/planned status for source stream binding, correlation
  work, scheduler leases, checkpoint continuity, lifecycle bindings, redacted
  credentials, and hosted operation mode.
- `signatures`: detached signatures over `worker_operation_id` and the canonical
  receipt body.

## Verification

A verifier MUST:

1. Recompute `worker_operation_id` from the canonical body.
2. Verify at least one detached signature.
3. Validate worker timestamps, operation kind, attempt counters, scheduler
   cadence, checkpoint hash shape, and redacted credential references.
4. Confirm stream source records match supplied provider audit stream receipts
   when replay artifacts are supplied.
5. Confirm correlation source records match supplied provider audit correlation
   receipts when supplied.
6. Confirm each correlation audit-log hash matches at least one bound audit
   stream receipt audit-log hash.
7. Confirm lifecycle operation and lifecycle manifest bindings match supplied
   replay artifacts when supplied.
8. Reject secret-like fields unless they are explicitly redacted references.

Verification MAY warn, rather than fail, when replay artifacts are not supplied
and the signed receipt body is otherwise internally valid.

## Chain Entry

Appending a valid receipt emits entry type `provider_audit.worker_recorded` with
the receipt id/hash, worker metadata, scheduler checkpoint metadata, redacted
credential reference, source bindings, and control summary.

## CLI

```bash
python -m trustai provider-audit-worker --stream-receipt artifacts/provider-audit-stream.json --correlation artifacts/github-provider-audit-correlation.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --lifecycle artifacts/provider-lifecycle.json --worker-ref worker:provider-audit/github --run-ref worker-run:provider-audit/github/2026-07-08T02:00:00Z --operation-kind stream_and_correlate --actor-ref oidc:trustai.example/provider-audit-worker --schedule-ref schedule:provider-audit/github/10m --cadence-seconds 600 --lease-ref lease:provider-audit/github/2026-07-08T02:00:00Z --checkpoint-ref checkpoint:provider-audit/github --checkpoint-hash sha256:provider-audit-checkpoint --credential-ref env:GITHUB_AUDIT_LOG_TOKEN --previous-cursor-ref github:audit-cursor:start --next-cursor-ref github:audit-cursor:next --next-run-at 2026-07-08T02:20:00Z --mode provider-authenticated-streamer --started-at 2026-07-08T02:10:00Z --completed-at 2026-07-08T02:12:00Z --out artifacts/provider-audit-worker.json
python -m trustai provider-audit-worker-verify artifacts/provider-audit-worker.json --stream-receipt artifacts/provider-audit-stream.json --correlation artifacts/github-provider-audit-correlation.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --lifecycle artifacts/provider-lifecycle.json
python -m trustai provider-audit-worker-append artifacts/provider-audit-worker.json --stream-receipt artifacts/provider-audit-stream.json --correlation artifacts/github-provider-audit-correlation.json --lifecycle-operation artifacts/provider-audit-lifecycle-operation.json --lifecycle artifacts/provider-lifecycle.json --state .trustai/provider-audit-worker-demo/evidence-chain.json --tenant provider-audit-worker-local --out artifacts/provider-audit-worker-entry.json
```

## Limitations

This receipt strengthens audit streaming evidence by binding scheduler, lease,
checkpoint, cursor, source stream, and correlation worker state. It still does
not by itself prove a fully operated SaaS fleet, production credential custody,
or external provider uptime unless paired with deployment, storage, monitoring,
provider credential custody receipts, and live provider dispatch evidence.
