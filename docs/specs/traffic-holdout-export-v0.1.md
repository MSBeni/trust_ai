# Traffic Holdout Export Receipt v0.1

A traffic holdout export receipt is a signed proof that the production traffic
records used for shadow replay were exported from a named source, bounded by an
extraction window, and checked against the verification contract freeze and
holdout timestamps before replay promotion evidence is trusted.

## Artifact

The receipt uses schema `trustai.traffic-holdout-export/0.1` and records:

- export ref, source ref, exporter ref, optional query ref, and optional source
  cursors;
- extraction window start and end timestamps;
- contract ID, contract hash, freeze timestamp, and holdout minimum timestamp;
- replay run ID, dataset ID, candidate version, and canonical replay hash;
- optional `replay_source_artifact` with retained replay source path, byte SHA-256, byte size, canonical source content hash, replay hash, record count, and record-hash root;
- first, last, earliest, and latest exported record timestamps;
- a hash-chained record list with sequence, unique record ID, timestamp,
  canonical replay-record hash, previous export record hash, and export record
  hash;
- explicit boundary/window/order violations and pass/fail status;
- privacy metadata confirming raw production traffic payloads are not embedded;
- detached signatures over the canonical receipt body.

Each record uses schema `trustai.traffic-holdout-export-record/0.1`. Reordering,
truncating, inserting, or editing replay records changes the final `records_root`.

## Verification

`traffic-holdout-export-verify` recalculates the receipt ID, verifies at least
one signature, replays the export record hash chain, recomputes duplicate
record-id, freeze/holdout, and extraction-window checks, enforces the
no-raw-payload privacy flag, and can
optionally replay the source verification contract and shadow replay JSON.

When a replay source is supplied, the verifier recomputes the replay hash and
every exported record hash from the replay file. When `replay_source_artifact` is
present, it also replays the retained source file bytes and rejects byte SHA-256,
byte size, canonical source content hash, replay hash, record count, or
record-hash-root mismatches. This catches source replay tampering and
reserialization after the export receipt was signed.

This receipt narrows the roadmap's production-traffic completeness gap, but it
can be paired with a `traffic-completeness` receipt that replays provider stream and audit evidence. By itself, it still does not claim upstream completeness without provider-owned collector,
stream, storage, or immutable audit-log exports.

## Chain Entry

Verified receipts append `traffic_holdout.export_attested` entries with:

- export id and receipt hash;
- export/source/exporter refs and cursors;
- extraction window;
- contract and replay refs, including the retained replay source artifact when present;
- record count, records root, earliest/latest timestamps;
- violation count and pass/fail status;
- privacy metadata.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai traffic-holdout-export examples/aitrade/verification-contract.yaml examples/aitrade/shadow-replay.json --export-ref traffic-export:aitrade/prod-traffic-holdout-20260702 --source-ref collector:aitrade-prod/redpanda/trustai.otel.events --exporter-ref oidc:trustai.example/traffic-exporter --window-start 2026-07-02T00:00:00Z --window-end 2026-07-03T23:59:59Z --produced-at 2026-07-03T12:20:00Z --out artifacts/traffic-holdout-export.json
python -m trustai traffic-holdout-export-verify artifacts/traffic-holdout-export.json --contract examples/aitrade/verification-contract.yaml --replay examples/aitrade/shadow-replay.json
python -m trustai traffic-holdout-export-append artifacts/traffic-holdout-export.json --contract examples/aitrade/verification-contract.yaml --replay examples/aitrade/shadow-replay.json --state .trustai/traffic-holdout-demo/evidence-chain.json --tenant traffic-holdout-local --out artifacts/traffic-holdout-export-entry.json
```