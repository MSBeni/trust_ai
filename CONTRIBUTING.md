# Contributing

TrustAI is a public reference preview. Contributions to the verifier, evidence
formats, tests, documentation, and reproducible local workflows are welcome.
Do not present retained example evidence as production authority or include
customer data, credentials, private keys, or live access tokens in an issue,
test, or pull request.

## Before a Pull Request

1. Open an issue to discuss substantial changes to the proof format, trust
   boundary, or verifier behavior. Small fixes can go directly to a pull request.
2. Use Python 3.11 or newer. From the repository root, install the package with
   `python -m pip install -e .` and run `python -m unittest discover -s tests`.
3. Run `python -m trustai demo` and
   `python -m trustai verify artifacts/aitrade-proof-pack.json` for changes to
   the proof flow. Run `go test ./...` from `verifier/go/trustai-verify` when
   changing the Go verifier.
4. Add tests for changed behavior and describe the trust claim, threat model,
   compatibility impact, and any example-only assumptions in the pull request.
5. Check `git diff --check` and inspect the diff for secrets or private data.
   Generated `.trustai/`, `artifacts/`, caches, and local build outputs should
   not be committed.

The evidence chain and signed retained examples bind source-file hashes.
Changes to audited files may require regenerating the linked example audit,
manifest, intake, and readiness artifacts; do not hand-edit their identifiers.

By submitting a contribution, you agree that it is licensed under the
repository's Apache-2.0 license and that you have the right to contribute it.
For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.
