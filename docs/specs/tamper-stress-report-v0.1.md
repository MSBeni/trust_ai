# Tamper Stress Report v0.1

This specification defines a signed artifact for large-log tamper-evidence
stress tests. It supports the roadmap requirement that the evidence-chain core
detects single-entry tampering at roadmap scale, including the 1,000,000-entry
Phase 0 target.

## Artifact

The JSON artifact uses schema `trustai.tamper-stress-report/0.1`.

Required top-level fields:

- `schema`: the schema identifier.
- `report_id`: canonical content hash of the report body.
- `generated_at`: deterministic timestamp used for generated test entries.
- `tenant_id`: tenant namespace for generated entries.
- `chain`: generated chain metadata.
- `samples`: sampled entries with Merkle inclusion proofs.
- `tamper_checks`: representative single-byte tamper vectors and detected
  verification errors.
- `summary`: aggregate generation, tamper-detection status, and explicit roadmap-target status.
- `limitations`: scope notes for local signer/TSA substitutions and deep
  verification.
- `signatures`: detached signature over `report_id` and the report body.

## Chain Metadata

`chain` records:

- `entry_count`: number of generated entries.
- `entry_type`: `tamper_stress.event`.
- `tree_root`: Merkle root over generated entry ids.
- `sample_indexes`: indexes included in the report.
- `tamper_index`: entry used for tamper vectors.
- `entries_verified_during_generation`: entries that passed entry verification
  while the report was generated.
- `generation_errors`: any generation-time verification errors.

Report generation must produce TrustAI-compatible entry ids, payload hashes,
previous-entry pointers, HMAC signatures, timestamp tokens, and Merkle leaves.

## Summary

`summary` records:

- `sample_count`: number of sampled entries embedded in the report.
- `tamper_checks_total` and `tamper_checks_detected`.
- `all_generated_entries_verified`: every generated entry verified during report generation.
- `all_tamper_checks_detected`: every representative mutation was rejected.
- `roadmap_phase0_target_entries`: the Phase 0 target, currently `1000000`.
- `roadmap_phase0_target_met`: true only when the generated chain has at least
  `roadmap_phase0_target_entries` entries and both generation and tamper checks passed.

## Samples

Each sample includes:

- `index`.
- `entry_id`.
- full `entry`.
- `inclusion_proof` with `tree_size`, `tree_root`, and audit path.

Verifiers must validate each sampled entry and its inclusion proof against
`chain.tree_root`.

## Tamper Checks

The reference implementation records these representative single-byte changes:

- `payload-single-byte`: mutate `payload.digest`.
- `signature-single-byte`: mutate the entry signature.
- `timestamp-token-single-byte`: mutate the timestamp-token message hash.
- `entry-id-single-byte`: mutate the Merkle leaf id.

Each tamper check must include the mutated entry, detected errors, target index,
and `detected=true`. For entry-id tampering, the original inclusion proof must
fail against the mutated entry id.

## Verification Modes

Default verification checks:

1. Schema, `report_id`, and signature.
2. Sample entry signatures, payload hashes, timestamp tokens, and inclusion
   proofs.
3. Mutated entries fail verification.
4. Summary counts match the tamper checks.
5. Roadmap Phase 0 target fields match the generated entry count and detection status.

With `--require-roadmap-target`, verification fails unless
`summary.roadmap_phase0_target_met=true`.

Deep verification additionally regenerates every entry, recomputes the full
Merkle root, and compares it with `chain.tree_root`. Deep verification is the
strongest local evidence for the roadmap-scale entry count.

## CLI

Reference commands:

```powershell
python -m trustai tamper-stress-report --entries 1000000 --sample-index 0 --sample-index 500000 --sample-index 999999 --tamper-index 500000 --out artifacts/tamper-stress-report.json
python -m trustai tamper-stress-verify artifacts/tamper-stress-report.json --deep --require-roadmap-target
```

For fast local smoke tests, callers may use a smaller `--entries` value while
retaining the same schema and verification behavior.
