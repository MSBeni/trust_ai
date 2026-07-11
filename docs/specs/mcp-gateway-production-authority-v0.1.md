# MCP Gateway Production Authority Dossier v0.1

Status: draft
Schema: `trustai.mcp-gateway-production-authority-dossier/0.1`
Entry type: `mcp.gateway_authority_recorded`

## Purpose

An MCP gateway production authority dossier binds a verified MCP transcript hash chain to explicit external production-authority evidence. It is the bridge between local/reference MCP tool-call capture and a production claim for continuously operated MCP proxy workers, tool-server registry controls, session authentication, request/response replay, immutable audit logs, scheduler/queue operation, policy enforcement, tenant/network controls, credential custody, and observability.

The dossier records what external authority evidence exists, which categories are missing, and whether supplied evidence is fresh at verification time. `local-dossier` and `proxy-dossier` modes are allowed for local/reference evidence and partial proxy exports, but they do not claim live production authority. A production claim requires `mode` set to `production-dossier` and complete fresh evidence for every required category.

## Modes

- `local-dossier`: local or reference authority evidence only.
- `proxy-dossier`: proxy evidence is present, but production authority is not fully claimed.
- `production-dossier`: every required production authority category must have fresh acceptable evidence.

## Required Production Authority Categories

The verifier checks this required checklist exactly. Each category can be covered by one or more authority evidence records.

| Requirement ID | Expected authority kinds | Purpose |
| --- | --- | --- |
| `production-mcp-proxy-worker-fleet` | `hosted-service`, `provider-api` | Continuously operated MCP proxy worker fleet. |
| `mcp-tool-server-registry` | `hosted-service`, `provider-api`, `customer` | Production MCP tool-server registry, allowlist, and version inventory. |
| `mcp-session-authentication` | `identity-provider`, `provider-api`, `hosted-service` | MCP session authentication, identity propagation, and actor binding. |
| `tool-call-request-response-replay` | `hosted-service`, `cloud-object-lock`, `customer` | Retained MCP tool-call request and response replay artifacts. |
| `immutable-mcp-audit-logs` | `hosted-service`, `cloud-object-lock`, `customer` | Immutable MCP proxy, tool server, and policy audit logs. |
| `scheduler-queue-lease-checkpoint` | `hosted-service`, `provider-api` | Production scheduler, queue, lease, checkpoint, cursor, and dead-letter exports. |
| `policy-and-contract-enforcement` | `hosted-service`, `provider-api`, `customer` | Runtime policy and verification-contract enforcement at the MCP proxy boundary. |
| `network-egress-and-tenant-controls` | `hosted-service`, `provider-api` | Tenant isolation, network egress, rate limit, and request signing controls. |
| `credential-custody-and-kms` | `kms-hsm`, `hosted-service`, `provider-api` | MCP proxy credential custody and KMS/HSM enforcement evidence. |
| `observability-and-alerting` | `hosted-service`, `provider-api`, `cloud-object-lock` | Production MCP proxy metrics, alerting, and observability exports. |

## Dossier Fields

A dossier contains:

- `schema`: `trustai.mcp-gateway-production-authority-dossier/0.1`.
- `mode`, `environment`, `generated_at`, `dossier_ref`, `authority_ref`, and `producer_ref`.
- `transcript_binding`: transcript schema, normalized transcript hash, source transcript hash, call count, session ids, tool names, contract hashes, agent bindings, timestamps, transcript roots, and per-call request/response/node hashes.
- `required_production_authority`: the exact requirement list above.
- `authority_evidence`: authority evidence records supplied by the producer.
- `summary`: covered, missing, fresh, stale, and missing-freshness counts.
- `controls`: passed, deferred, and failed claim controls.
- `limitations`: non-production and missing-live-authority disclaimers.
- `dossier_id`: canonical hash of the dossier body without signatures.
- `signatures`: one or more signatures over the dossier id and body.

## Authority Evidence Records

Each `authority_evidence` record must contain:

- `requirement_id`: one of the required production authority category ids.
- `authority_kind`: an allowed external authority kind for that category.
- `evidence_ref`: stable external reference such as a hosted service export id, proxy fleet audit URI, object-lock root, KMS/HSM custody record, tool registry record, or customer-owned ledger pointer.
- `evidence_hash`: hash or immutable root for the external evidence.
- `description`: human-readable evidence description.

Optional metadata fields are `issuer`, `subject`, `source_uri`, `issued_at`, and `expires_at`. Freshness checks use `issued_at` and `expires_at`. Evidence without both timestamps is accepted for non-strict verification but counted as missing freshness.

CLI evidence strings use:

```text
requirement_id,authority_kind,evidence_ref,evidence_hash,description[;issuer=value;subject=value;source_uri=value;issued_at=value;expires_at=value]
```

## Verification Rules

A verifier must:

1. Verify the schema, canonical `dossier_id`, and at least one valid signature.
2. Verify `mode`, `environment`, `dossier_ref`, `authority_ref`, `producer_ref`, and RFC3339 timestamps.
3. Require a complete non-empty `transcript_binding` with schema, transcript hashes, call count, sessions, tools, contract hashes, agent bindings, timestamps, transcript roots, and per-call request/response/node hashes. When the raw transcript is supplied, rebuild the MCP transcript hash chain and compare it to `transcript_binding`.
4. Require the `required_production_authority` checklist to match this specification exactly.
5. Reject evidence with unknown requirement ids or disallowed authority kinds.
6. Reject malformed evidence references, hashes, and timestamp windows.
7. Count missing, stale, and fresh evidence. With `--require-complete`, every requirement id must be covered. With `--require-fresh`, every covered evidence item must include a valid current freshness window.
8. Reject `production-dossier` mode unless all requirements are covered with fresh evidence.
9. Reject raw secrets in the dossier. Secret-bearing fields must be redacted references such as `env:`, `vault:`, `kms:`, or content hashes.

## CLI Examples

Create a proxy dossier with partial production authority evidence:

```powershell
python -m trustai mcp-gateway-authority examples/aitrade/mcp-transcript.json --mode proxy-dossier --environment aitrade-prod --dossier-ref dossier:mcp-gateway-authority/aitrade-prod --authority-ref authority:mcp-gateway/proxy-prod --producer-ref oidc:trustai.example/mcp-gateway-authority-worker --authority-evidence "production-mcp-proxy-worker-fleet,hosted-service,mcp-proxy:fleet/aitrade-prod,sha256:mcp-proxy-worker-fleet,Hosted MCP proxy worker fleet export for governed tool-call capture;issuer=TrustAI Hosted Ops;subject=aitrade-prod MCP proxy fleet;source_uri=https://mcp.example/audit/fleet/aitrade-prod;issued_at=2026-07-12T03:10:00Z;expires_at=2026-07-19T03:10:00Z" --generated-at 2026-07-12T03:12:00Z --now 2026-07-15T00:00:00Z --out artifacts/mcp-gateway-authority.json
```

Verify and append the dossier:

```powershell
python -m trustai mcp-gateway-authority-verify artifacts/mcp-gateway-authority.json examples/aitrade/mcp-transcript.json --now 2026-07-15T00:00:00Z
python -m trustai mcp-gateway-authority-append artifacts/mcp-gateway-authority.json examples/aitrade/mcp-transcript.json --now 2026-07-15T00:00:00Z --state .trustai/mcp-gateway-authority-demo/evidence-chain.json --tenant mcp-gateway-authority-local --out artifacts/mcp-gateway-authority-entry.json
```

## Production Claim Limits

This specification makes production MCP proxy authority auditable, but it does not manufacture live provider evidence. A `local-dossier` or `proxy-dossier` may prove the local transcript graph and document missing authority. A real production claim requires current external evidence from operated MCP proxy fleets, provider-owned scheduler/queue/lease exports, immutable audit storage, tool registry controls, identity/session exports, KMS/HSM custody records, network controls, and observability systems.