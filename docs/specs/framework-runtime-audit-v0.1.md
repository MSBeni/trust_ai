# Framework Runtime Audit v0.1

A framework runtime audit receipt binds a framework hook operation to an audit
export from the runtime or provider that hosted the hook. The hook operation
proves that TrustAI normalized a source trace into adapter events; the runtime
audit receipt proves that a provider/runtime audit export contains a matching
capture event for the same framework, trace, operation ref, runtime instance,
and collector hook.

This closes the evidence gap between local hook replay and provider-owned
runtime records. Chain entries contain hashes and summary metadata; offline
verification replays the hook operation and the supplied audit export.

## Artifact

A receipt uses schema `trustai.framework-runtime-audit/0.1` and contains:

- mode, environment, export timestamp, provider, and redacted credential ref;
- framework hook operation ID/hash/ref, runtime package/version/instance,
  hook release hash, adapter matrix binding, source trace hash, event root, and
  per-trace roots;
- runtime/provider audit export ref, audit log ref/root, window and cursor refs,
  export hash, event count, and event root;
- the matched audit event ID/kind/timestamp/hash, framework, trace ID,
  operation ref, runtime instance, and collector hook ref;
- provider endpoint URL, request hash, response status, response hash, actor,
  controls, limitations, and detached signatures.

## Verification

`framework-runtime-audit-verify` recalculates the receipt ID, verifies at least
one signature, replays the framework hook operation when operation/trace/release
and matrix sources are supplied, and checks that the recorded operation binding
matches the supplied operation.

When the audit export is supplied, verification recalculates the audit export
hash, event count, event root, window, cursor refs, and matched event hash. The
audit event must match the operation by framework, trace ID, operation ref or
operation ID, runtime instance ref, and collector hook ref. Optional event
fields such as hook release hash, source trace hash, event root, runtime process
ref, and operation audit-log ref must match the operation binding when present.

`framework-runtime-audit-append` requires the receipt, audit export, hook
operation, source trace, hook release, and adapter matrix. The appended evidence
chain entry records only hash-bound summary metadata.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai framework-runtime-audit examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --mode provider-export --environment aitrade-prod --provider langgraph-runtime --endpoint-url https://runtime.example/aitrade/audit/framework-hooks --credential-ref env:LANGGRAPH_RUNTIME_AUDIT_TOKEN --request-hash sha256:framework-runtime-audit-request --response-status 200 --response-hash sha256:framework-runtime-audit-response --actor-ref oidc:trustai.example/framework-runtime-audit-worker --exported-at 2026-07-09T00:42:00Z --out artifacts/framework-runtime-audit.json
python -m trustai framework-runtime-audit-verify artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root .
python -m trustai framework-runtime-audit-append artifacts/framework-runtime-audit.json --audit-export examples/aitrade/framework-runtime-audit.json --operation artifacts/framework-hook-operation.json --trace examples/aitrade/framework-traces.json --release artifacts/framework-hook-release.json --matrix artifacts/framework-adapter-matrix.json --root . --state .trustai/framework-runtime-audit-demo/evidence-chain.json --tenant framework-runtime-audit-local --out artifacts/framework-runtime-audit-entry.json
```
