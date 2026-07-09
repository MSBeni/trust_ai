# Framework Hook Operation v0.1

A framework hook operation receipt records one hook capture from a framework
runtime. It binds a source trace to a signed hook release, the adapter matrix,
the emitted adapter event chain, runtime instance metadata, collector delivery
references, and audit-log evidence.

This is the runtime companion to `framework-hook-release`: a release says which
hook entrypoint and source artifacts were shipped; an operation receipt says the
entrypoint captured a specific runtime trace and produced replayable normalized
events. `framework-runtime-audit` can then bind that operation to a
provider/runtime-owned audit export for the same hook capture.

## Artifact

An operation uses schema `trustai.framework-hook-operation/0.1` and contains:

- mode, environment, capture timestamp, operation ref, actor, and redacted
  credential ref;
- runtime framework/package/version plus runtime instance and process refs;
- hook package/version/mode/module/entrypoint/collector hook ref plus the bound
  hook release row hash;
- release and adapter matrix IDs/hashes;
- source trace hash, emitted event count/names/root, per-trace roots, contract
  hashes, and agent metadata;
- collector service, collector worker, stream message, and audit-log refs;
- control statuses and detached signatures over the canonical operation body.

## Verification

`framework-hook-operation-verify` recalculates the operation ID, verifies at
least one signature, verifies the hook release and adapter matrix when supplied,
replays the source trace through the hook adapter path, and checks source trace
hash, event count, event names, event root, per-trace roots, trace ID, hook
release row hash, hook entrypoint metadata, release hash, and matrix hash.

`framework-hook-operation-append` requires the source trace, hook release, and
adapter matrix. Chain append therefore records only hashes and summary metadata,
while offline verifiers can replay the raw trace payload when it is disclosed.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-hook-operation examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --framework langgraph --trace-id lg-trace-001 --root . --mode collector-observed --environment aitrade-prod --operation-ref framework-hook-operation:aitrade/langgraph/lg-trace-001 --runtime-instance-ref runtime:aitrade/langgraph/prod-worker-1 --runtime-process-ref pid:4242 --collector-service-ref collector:trustai/otel-prod --collector-worker-ref worker-run:collector/framework-hook/lg-trace-001 --stream-message-ref stream-message:collector/framework-hook/lg-trace-001 --audit-log-ref audit-log:framework-hooks/aitrade --audit-log-root sha256:framework-hook-operation-audit-root --actor-ref oidc:trustai.example/framework-hook-runtime --credential-ref env:FRAMEWORK_HOOK_TOKEN --captured-at 2026-07-09T00:40:00Z --out artifacts/framework-hook-operation.json
python -m trustai framework-hook-operation-verify artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-hook-operation-append artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-hook-operation-demo/evidence-chain.json --tenant framework-hook-operation-local --out artifacts/framework-hook-operation-entry.json
```