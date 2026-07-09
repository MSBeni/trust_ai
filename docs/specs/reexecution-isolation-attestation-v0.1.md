# TrustAI Re-execution Isolation Attestation v0.1

Re-execution runner evidence proves that repeated eval commands produced
specific outputs. A re-execution isolation attestation adds the production
runner envelope: it binds that runner evidence to recorded container/kernel
isolation controls, deterministic execution controls, and runner audit-log
evidence.

This artifact exists for third-party review of the sandbox boundary. It records
runner image digest, namespace mode, cgroup reference, seccomp/AppArmor profile
hashes, network mode, filesystem policy, seed policy, temperature, audit-log
root, retention deadline, actor reference, and redacted credential reference.

## Schema

`schema`: `trustai.reexecution-isolation-attestation/0.1`

Required top-level fields:

- `attestation_id`: canonical hash of the attestation body.
- `signatures`: one or more detached `trustai.signature/0.1` signatures over
  `{attestation_id, reexecution_isolation}`.
- `mode`: `local-reference`, `container-attested`, or `production-design`.
- `environment`: deployment/environment label.
- `attested_at`: RFC3339 timestamp for the isolation evidence record.
- `source`: re-execution runner evidence id/hash, plan hash, policy hash,
  optional report id/hash, run ids, seeds, run hashes, and result hashes.
- `isolation`: runner reference, provider, orchestrator, container runtime,
  kernel, namespace mode, cgroup reference, seccomp hash, optional AppArmor
  hash, runner image and digest, network mode, filesystem policy, read-only
  rootfs flag, writable/denied mounts, and egress policy.
- `execution_controls`: seed policy, required-seed flag, per-run seeds,
  temperature, policy maximum temperature, and entropy source reference.
- `operation`: actor reference, redacted runner credential reference, and
  optional evidence references.
- `audit_log`: runner audit-log reference, audit-log root hash, and retention
  deadline.
- `source_artifacts`: hashes of the runner evidence, re-execution policy, and
  optional re-execution report supplied to verification.
- `controls`: implementation/planned-production status for image digest,
  kernel/container isolation, disabled network, read-only rootfs,
  seed/temperature enforcement, audit retention, and credential redaction.

Runner credentials, raw provider secrets, raw audit logs, and raw sandbox
control-plane tokens are never copied into the attestation.

## Verification

`trustai reexecution-isolation-verify` checks:

- attestation schema and canonical `attestation_id`.
- detached signature over the attestation body.
- RFC3339 `attested_at` and audit-log retention ordering.
- supported mode.
- full verification of supplied re-execution runner evidence.
- full verification of supplied re-execution policy.
- optional full verification of supplied re-execution report.
- runner evidence policy hash matches the supplied policy.
- report source-run hashes and contract/policy bindings match runner evidence.
- runner image, image digest, network mode, and read-only rootfs match policy
  sandbox requirements.
- namespace mode is not host/none.
- runner image digest, seccomp hash, optional AppArmor hash, and audit-log root
  are SHA-256 references.
- network mode is disabled.
- read-only rootfs is true.
- seeds match runner evidence and required-seed policy.
- temperature does not exceed the policy maximum.
- source artifact hashes match supplied artifacts.
- runner credential is represented only by a redacted reference.
- absence of raw secret-like fields outside approved redacted references.

`trustai reexecution-isolation-append` first verifies the attestation and source
artifacts, then appends `reexecution.isolation_attested` to an evidence chain.
The appended entry contains the attestation id/hash, source runner/report
bindings, isolation controls, execution controls, operation metadata, audit-log
metadata, source-artifact hashes, and control summary.

## Example Commands

```powershell
python -m trustai reexecution-isolation-attestation artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --isolation-ref isolation:aitrade/reexecution/2026-07-04 --runner-ref runner:trustai-reexecution/local --runner-provider "TrustAI Local Runner" --orchestrator kubernetes --container-runtime containerd --kernel linux-6.8 --namespace-mode private --cgroup-ref cgroup:trustai/reexecution/aitrade --seccomp-profile-hash sha256:trustai-reexecution-seccomp --apparmor-profile-hash sha256:trustai-reexecution-apparmor --network-mode disabled --filesystem-policy-ref fs-policy:trustai/reexecution/read-only-root --read-only-rootfs --writable-mount /tmp/trustai-runner --denied-mount /var/run/docker.sock --egress-policy-ref egress-policy:deny-all --seed-policy recorded-or-fixed-seed --temperature 0 --entropy-source-ref entropy:fixed-seed-runner --audit-log-ref audit-log:reexecution/isolation --audit-log-root sha256:reexecution-isolation-audit-root --retention-until 2033-07-04T00:00:00Z --actor-ref oidc:trustai.example/reexecution-runner --credential-ref env:REEXECUTION_RUNNER_TOKEN --evidence-ref evidence:reexecution/isolation --attested-at 2026-07-04T04:06:00Z --out artifacts/reexecution-isolation-attestation.json
python -m trustai reexecution-isolation-verify artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json
python -m trustai reexecution-isolation-append artifacts/reexecution-isolation-attestation.json artifacts/reexecution-runner-evidence.json --policy examples/aitrade/reexecution-policy.json --report artifacts/reexecution-report.json --state .trustai/reexecution-isolation-demo/evidence-chain.json --tenant reexecution-isolation-local --out artifacts/reexecution-isolation-entry.json
python -m trustai chain-verify --state .trustai/reexecution-isolation-demo/evidence-chain.json --tenant reexecution-isolation-local
```

## Production Notes

The local reference verifies recorded isolation evidence and policy bindings. A
production runner service should enforce the same controls with kernel/container
mechanisms, preserve runtime-native audit events in WORM storage, attest runner
image provenance from a trusted build pipeline, deny network egress by default,
and prevent host filesystem or container-socket mounts. This v0.1 attestation
defines the offline evidence contract for that sandbox boundary.
