# Standards Submission Package v0.1

The standards submission package is a local, verifiable artifact for preparing
TrustAI proof-pack specs for an external standards track.

It does not claim that a standards body has accepted the format. It packages the
public specification documents, conformance targets, and submission checklist so
reviewers can verify exactly which spec text was submitted.

## Schema

`schema`: `trustai.standards-submission/0.1`

Top-level fields:

- `package_id`: canonical hash of the package body.
- `generated_at`: package timestamp.
- `status`: draft/submitted/accepted workflow status.
- `target_body`: intended standards venue.
- `project`: package metadata from `pyproject.toml`.
- `scope`: specification objective, license, and neutrality statement.
- `required_specs`: core spec paths that must be present.
- `specs`: path, title, spec id, content hash, and line count for every
  `docs/specs/*.md` file.
- `conformance_targets`: reference implementation targets and commands.
- `submission_checklist`: review checklist for standards-track readiness.

## Verification

`trustai standards-verify` checks:

- package schema.
- package id canonical hash.
- required spec records are present.
- every referenced spec exists in the worktree.
- each spec title, content hash, and line count still matches current file
  contents.
- conformance target references exist when provided.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai standards-export --out artifacts/standards-submission.json --markdown artifacts/standards-submission.md
python -m trustai standards-verify artifacts/standards-submission.json
```

Production standards work still requires governance outside this repository:
named standards-body engagement, change control, independent implementers,
versioned compatibility policy, and public conformance test suites.
