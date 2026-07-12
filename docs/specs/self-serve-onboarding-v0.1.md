# TrustAI Self-Serve Onboarding Receipt v0.1

Status: draft

## Purpose

The self-serve onboarding receipt proves that the local SDK/gateway quickstart
surface is present, hash-bound, structurally replayed against registered CLI
commands, and ready for offline review. It targets the
roadmap's SDK/gateway tier: Python SDK, TypeScript SDK, OTel GenAI ingest, MCP
gateway transcript capture, runnable MCP stdio proxy capture, bundled aitrade proof-pack generation, example verification contracts, and offline verifier commands.

The receipt is not a hosted signup or billing artifact. It intentionally limits
its claim to local self-serve onboarding and records the production evidence
still needed for a PLG onboarding service.

## Schema

`trustai.self-serve-onboarding/0.1`

## Bound Sources

The receipt binds these source artifacts by path, `sha256:` hash, and size:

- `docs/specs/python-sdk-v0.1.md`
- `docs/specs/typescript-sdk-v0.1.md`
- `docs/specs/otel-ingest-v0.1.md`
- `docs/specs/mcp-gateway-v0.1.md`
- `src/trustai/cli.py`
- `src/trustai/sdk.py`
- `src/trustai/ingest.py`
- `src/trustai/mcp_gateway.py`
- `src/trustai/proofpack.py`
- `sdk/typescript/src/index.mjs`
- `examples/aitrade/verification-contract.yaml`
- `examples/aitrade/agent-inventory.json`
- `examples/aitrade/delegation.json`
- `examples/aitrade/runtime-action.json`
- `examples/aitrade/shadow-replay.json`
- `examples/aitrade/soak-window.json`
- `examples/aitrade/reexecution-policy.json`
- `examples/aitrade/reexecution-runner-plan.json`
- `examples/aitrade/mcp-transcript.json`
- `examples/aitrade/mcp-stdio-client-messages.json`
- `examples/aitrade/mcp-stdio-upstream.py`
- `examples/aitrade/otel-events.json`

## Receipt Fields

- `receipt_id`: canonical hash of the receipt body excluding `receipt_id` and
  `signatures`.
- `onboarding_ref`, `tenant_ref`, `agent_ref`, `requester_ref`: stable
  references for the onboarding session and actor.
- `environment`: local or deployment environment label.
- `sdk_scope`: `python`, `typescript`, or `python-typescript`.
- `gateway_mode`: `otel-only`, `mcp-gateway`, or `sdk-gateway`.
- `source_artifacts`: bound source file references.
- `quickstart_steps`: deterministic commands derived from SDK scope and gateway
  mode.
- `quickstart_replay`: local structural replay for each command, including CLI
  subcommand registration, source file bindings, generated targets, and command
  validity. The default sequence generates the bundled aitrade proof pack before
  verifying it offline, using `demo --no-clean` so the initialized local chain
  and pre-registered contract remain part of the same onboarding run. Gateway
  modes include both transcript capture and the runnable `mcp-proxy-stdio`
  proxy capture command.
- `controls`: derived status checks for SDK, OTel, MCP, contract example,
  demo proof-pack generation, quickstart command replay, and production-claim
  limits.
- `signatures`: one or more signatures over `{receipt_id,
  self_serve_onboarding}`.

## Verification Rules

Verifiers must:

- recompute `receipt_id` from the canonical body
- verify at least one receipt signature
- validate generated timestamps and required references
- recompute every source artifact hash from the supplied repository root
- reject missing, duplicated, unexpected, or tampered source artifacts
- recompute quickstart steps from `sdk_scope` and `gateway_mode`
- replay each quickstart command against bound source files and registered
  `python -m trustai` CLI subcommands in `src/trustai/cli.py`
- recompute controls from the receipt body
- warn when `gateway_mode` omits the MCP gateway path

## Evidence Chain Entry

Appending a valid receipt writes entry type:

`onboarding.self_serve.completed`

The payload records receipt identity, tenant, agent, requester, SDK scope,
gateway mode, source-artifact count, quickstart-step count, quickstart-replay
count, and control summary.

## CLI

```powershell
python -m trustai self-serve-onboarding --root . --onboarding-ref onboarding:self-serve/aitrade --tenant-ref tenant:aitrade-local --agent-ref agent:aitrade-risk --requester-ref mailto:engineer@example.com --out artifacts/self-serve-onboarding.json
python -m trustai self-serve-onboarding-verify artifacts/self-serve-onboarding.json --root .
python -m trustai self-serve-onboarding-append artifacts/self-serve-onboarding.json --root . --state .trustai/self-serve-onboarding/evidence-chain.json --tenant self-serve-onboarding-local --out artifacts/self-serve-onboarding-entry.json
```

## Limits

This receipt does not prove hosted account creation, identity federation,
payment setup, usage metering, support operations, or production onboarding
SLOs. Those remain external provider/customer evidence for a hosted PLG service.
