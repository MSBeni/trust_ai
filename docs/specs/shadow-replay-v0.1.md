# Shadow Replay and Soak Reports v0.1

Shadow replay evaluates a frozen candidate agent against production-like traffic
whose timestamps postdate the freeze boundary. The local reference evaluator
computes:

- shadow action match rate;
- trade policy compliance rate;
- maximum position error;
- p95 decision latency;
- holdout timestamp and duplicate replay record-id violations.

The output can be appended as `shadow_replay.completed` evidence and converted
into normal eval results for promotion gates. Shadow replay entries also embed a
signed temporal holdout manifest whose per-record hash chain binds record order,
record hashes, unique replay record IDs, freeze boundary, holdout minimum, and
the final replay root.

`traffic-holdout-export`, `traffic-holdout-export-verify`, and
`traffic-holdout-export-append` produce a signed production traffic export
receipt before replay. The receipt binds source/exporter refs, extraction window,
record hashes, replay hash, privacy limits, duplicate record-id checks, and
boundary/window violations
without embedding raw production traffic payloads.

`traffic-completeness`, `traffic-completeness-verify`, and
`traffic-completeness-append` bind that export receipt to collector/provider
stream records, cursor bounds, provider export hashes, and audit records before
the replay window is treated as complete.

`temporal-holdout-manifest`, `temporal-holdout-verify`, and
`temporal-holdout-append` expose the replay holdout manifest as a standalone
artifact for third-party review before a full proof pack is assembled.

Soak reports summarize post-promotion windows and append
`soak_report.completed` evidence. Blocking high/critical incidents or drift
alarms fail the report. `trustai soak-report --demote-on-failure` records the
failed soak report and appends a `promotion_gate.demoted` entry whose trigger
binds the failed report entry id, failed metric checks, blocking incidents, and
blocking drift alarms.

Proof-pack verification replays soak reports from the embedded source soak
window. The verifier rejects packs when the source soak hash, window timestamps,
metric checks, incidents, drift alarms, outcome, entry timestamp, or contract
hash do not reproduce the signed `soak_report.completed` payload.
