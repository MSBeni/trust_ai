# MCP Gateway Review Bundle v0.1

The MCP gateway review bundle packages a signed MCP proxy capture for offline
review by an auditor, insurer, model-risk team, or deployment approver. It is
the portable handoff artifact for the Phase 1 zero-code MCP gateway wedge.

## Schema

`trustai.mcp-gateway-review-bundle/0.1`

Supported modes:

- `offline-review`: local or retained capture review without production claims.
- `proxy-capture-review`: focused review of a proxy capture and retained source
  event export.
- `production-review`: review bundle that also embeds MCP gateway production
  authority evidence; complete production authority is still verified by the
  authority dossier/checklist.

## Required Fields

- `bundle_ref`: reviewer-facing stable bundle reference.
- `reviewer_ref`: identity or process reference for the bundle producer/reviewer.
- `capture_receipt`: embedded `trustai.mcp-proxy-capture/0.1` receipt.
- `capture_binding`: capture id, capture hash, agent, contract hash, proxy refs,
  event root, transcript root, redaction summary, event hashes, and tool-call
  hashes.
- `source_artifacts`: optional retained byte artifacts used during verification,
  including capture JSON, raw proxy events, stdio export, client messages,
  upstream stdout, or authority bundle bytes.
- `controls`: replay status for capture verification, raw proxy event replay,
  redaction summary recomputation, stdio artifact replay, authority evidence,
  and production-review authority.

Optional embedded sources:

- `stdio_export`: `trustai.mcp-proxy-stdio-session/0.1` export.
- `authority_evidence_bundle`:
  `trustai.mcp-gateway-authority-evidence-bundle/0.1`.

## Verification

A verifier must reject the bundle when:

- `bundle_id` does not match the canonical bundle body;
- the bundle signature does not verify;
- the embedded proxy capture fails signature, event-chain, transcript-root,
  JSON-RPC response matching, or redaction-summary verification;
- retained raw proxy event bytes are supplied but do not replay to the embedded
  capture artifact;
- the embedded stdio export, client messages, or stdout artifact fail replay;
- an embedded authority evidence bundle fails signature or evidence validation;
- any binding (`capture_binding`, `stdio_export_binding`, or
  `authority_evidence_bundle_binding`) does not match its embedded source; or
- `production-review` mode omits an authority evidence bundle.

This bundle is not a substitute for live production MCP gateway authority. It is
the portable review envelope that carries the capture and its replay evidence to
a third party.

## CLI

```powershell
python -m trustai mcp-proxy-capture examples/aitrade/mcp-proxy-events.json --agent-name aitrade-risk-agent --agent-version sha256:0d5bbd8d2357b7d36e0f3f7c5e9a0a3e1f5b7a0d2c4e6f8a9b1c3d5e7f901234 --risk-class trading-prod-write --contract-hash 22a3727b124ce6664031037939cf391ce724158d681db3a55e9a0f0c51bcc7a2 --proxy-ref mcp-proxy:trustai/local --upstream-ref mcp-server:aitrade/tools --captured-at 2026-07-03T12:00:12Z --out artifacts/mcp-proxy-capture.json
python -m trustai mcp-gateway-review-bundle artifacts/mcp-proxy-capture.json --events examples/aitrade/mcp-proxy-events.json --mode proxy-capture-review --bundle-ref bundle:mcp-gateway/aitrade/proxy-review --reviewer-ref oidc:auditor.example/mcp-reviewer --generated-at 2026-07-12T03:20:00Z --out artifacts/mcp-gateway-review-bundle.json
python -m trustai mcp-gateway-review-bundle-verify artifacts/mcp-gateway-review-bundle.json --events examples/aitrade/mcp-proxy-events.json
python -m trustai mcp-gateway-review-bundle-append artifacts/mcp-gateway-review-bundle.json --events examples/aitrade/mcp-proxy-events.json --state .trustai/mcp-gateway-review/evidence-chain.json --tenant mcp-gateway-review --out artifacts/mcp-gateway-review-bundle-entry.json
```
