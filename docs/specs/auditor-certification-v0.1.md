# TrustAI Auditor Certification Kit v0.1

The auditor certification kit is a local, verifiable training package for
auditors who need to review TrustAI proof packs, selective disclosures, and
standards-track spec manifests.

It does not claim an external auditor has been accredited. External
certification still requires independent program governance, proctoring, and
credential issuance. This artifact packages the curriculum, exercises, rubric,
and source hashes that an auditor training program can verify offline.

## Schema

`schema`: `trustai.auditor-certification-kit/0.1`

Required top-level fields:

- `kit_id`: canonical hash of the kit body.
- `generated_at`: creation timestamp.
- `program_version`: local training program version.
- `source_artifacts`: proof pack hash and optional regulator-disclosure and
  standards-submission hashes.
- `training_modules`: required learning modules for proof-pack verification,
  evidence-chain forensics, selective disclosure, and policy/lifecycle review.
- `practical_exercises`: command-oriented exercises for verifier use,
  tamper-evidence, disclosure review, and standards-package verification.
- `rubric`: minimum passing score, required modules, required exercises, and
  certification scope.
- `limitations`: explicit boundaries between this local artifact and external
  auditor accreditation.

## Verification

`trustai auditor-certification-verify` checks:

- schema version;
- `kit_id` canonical hash;
- required training modules;
- required practical exercises;
- proof-pack source hash and offline proof-pack verification when supplied;
- regulator-disclosure source hash and disclosure verification when supplied;
- standards-submission source hash and manifest verification when supplied.

Deep verification should be run with the source artifacts:

```bash
python -m trustai auditor-certification-verify artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json
```

If a source artifact is omitted, the verifier returns a warning instead of
claiming deep verification for that source.

## CLI

```bash
python -m trustai auditor-certification-export artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json --out artifacts/auditor-certification-kit.json --markdown artifacts/auditor-certification-kit.md
python -m trustai auditor-certification-verify artifacts/auditor-certification-kit.json --pack artifacts/aitrade-proof-pack.json --disclosure artifacts/regulator-disclosure.json --standards-package artifacts/standards-submission.json
```

## Production Boundary

This v0.1 artifact is useful for repeatable local auditor enablement and
third-party review readiness. A production auditor ecosystem still needs:

- independent accreditation governance;
- exam delivery and identity proofing;
- revocation and renewal policy;
- public credential registry;
- standards-body or industry-program sponsorship.
