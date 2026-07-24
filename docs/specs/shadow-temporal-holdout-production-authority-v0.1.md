# Shadow Temporal Holdout Production Authority v0.1

Shadow temporal holdout authority dossiers bind replay/holdout source receipts to
the production authority evidence needed for Phase 1 shadow replay claims.

## Artifacts

- Dossier schema: `trustai.shadow-temporal-holdout-production-authority-dossier/0.1`
- Evidence bundle schema: `trustai.shadow-temporal-holdout-authority-evidence-bundle/0.1`
- Chain entry types:
  - `shadow.temporal_holdout_authority_recorded`
  - `shadow.temporal_holdout_authority_evidence_bundled`

## Source Binding

A dossier replays and hashes the registered verification contract, shadow replay
source, temporal holdout manifest, traffic holdout export, and traffic
completeness receipt. When a provider export is supplied, traffic completeness
verification also replays the provider-owned stream/audit records.

The source binding records:

- contract hash, freeze timestamp, and holdout minimum timestamp;
- replay run, dataset, candidate version, source hash, and record count;
- temporal holdout manifest ID, record root, timestamp range, pass flag, and
  violation count;
- traffic export ID, extraction window, cursor refs, source ref, record root,
  pass flag, and violation count;
- traffic completeness ID, production mode, authority ref, matched/missing
  record counts, provider export artifact binding, pass flag, and violation
  count.

## Production Authority Checklist

Production dossiers require evidence for the fixed checklist embedded in
`src/trustai/shadow_authority.py`:

- pre-registered temporal boundary;
- production traffic export window;
- collector/stream completeness;
- candidate version freeze;
- replay runner identity;
- KMS/HSM signing custody;
- immutable traffic audit logs;
- deterministic replay runner provenance;
- holdout leakage review;
- freshness and monitoring window.

Authority evidence rows carry `requirement_id`, `authority_kind`,
`evidence_ref`, `evidence_hash`, optional issuer/subject/source URI metadata,
freshness timestamps, and a source context derived from the bound holdout
receipts. `evidence_hash` MUST be a canonical lowercase `sha256:` reference
with a 64-character hexadecimal digest; builders normalize uppercase digest
hex, and verifiers reject malformed or symbolic hashes.

## Modes

- `local-dossier`: local review of source binding and partial authority
  evidence.
- `provider-dossier`: provider-backed evidence is present but full production
  authority is not claimed.
- `production-dossier`: every checklist item must be covered by fresh authority
  evidence, all source receipts must pass, and traffic completeness must be in
  `production-export` mode.

Evidence bundles use `authority-export`, `offline-review`, and
`production-export` modes. A production evidence bundle must have complete
checklist coverage, fresh evidence windows, and live non-placeholder source
URIs.

## CLI

```bash
python -m trustai shadow-authority-evidence-bundle \
  --mode production-export \
  --environment aitrade-prod \
  --bundle-ref bundle:shadow/aitrade-prod/20260703 \
  --issuer-ref authority:trustai/shadow-exporter \
  --subject-ref agent:aitrade-risk-shadow@2026.07.03 \
  --authority-ref authority:shadow-holdout/provider-completeness-prod \
  --authority-evidence requirement,provider-api,ref,sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,description \
  --require-complete --require-fresh --now 2026-07-19T00:00:00Z

python -m trustai shadow-authority \
  examples/aitrade/verification-contract.yaml \
  examples/aitrade/shadow-replay.json \
  artifacts/temporal-holdout-manifest.json \
  artifacts/traffic-holdout-export.json \
  artifacts/traffic-completeness.json \
  --provider-export examples/aitrade/traffic-completeness-provider-export.json \
  --mode production-dossier \
  --dossier-ref dossier:shadow/aitrade-prod/20260703 \
  --authority-ref authority:shadow-holdout/provider-completeness-prod \
  --producer-ref service:trustai-shadow-authority \
  --authority-evidence-bundle artifacts/shadow-authority-evidence-bundle.json \
  --require-complete --require-fresh --now 2026-07-19T00:05:00Z
```
