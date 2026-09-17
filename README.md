# TrustAI

TrustAI creates verifiable records of how an AI agent was tested and whether it
met a predefined release gate. It combines a verification contract, captured
events, evaluation results, and a gate decision into a portable proof pack. The
pack can be checked offline without access to the original TrustAI instance.

This repository contains the Python toolkit, a dependency-free Go verifier,
and a complete sample workflow for an agent called aitrade. Use the sample to
see the format and verification flow, then capture and verify evidence from
your own agent.

## What It Does

- Registers a verification contract before evaluation.
- Records agent events, runtime actions, replay results, and approvals in a
  tamper-evident evidence chain.
- Evaluates a promotion gate and exports a JSON proof pack and readable PDF.
- Verifies the pack offline, including signatures, hashes, chain ordering, and
  the gate decision.

The broader set of supported receipts, integrations, and ongoing work is
tracked in [roadmap coverage](docs/architecture/roadmap-coverage.md).

## Quick Start

You need Git and Python 3.11 or newer. From a shell on macOS or Linux:

```sh
git clone https://github.com/MSBeni/trust_ai.git
cd trust_ai
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m trustai demo
python -m trustai verify artifacts/aitrade-proof-pack.json
```

On Windows PowerShell, create and activate the environment with
`py -3.11 -m venv .venv` and `.\.venv\Scripts\Activate.ps1`; then run the
commands from `python -m pip install -e .` onward. Install from this repository,
not from a package named `trustai` on PyPI.

The demo prints its gate outcome and writes
`artifacts/aitrade-proof-pack.json` and `artifacts/aitrade-proof-pack.pdf`.
The second command checks the generated pack and prints the verified outcome.
The demo's state and generated artifacts stay local and are ignored by Git.

## Use Your Own Evidence

Start with the [verification contract](docs/specs/verification-contract-v0.1.md)
to define what the agent must satisfy. The [ingestion
spec](docs/specs/otel-ingest-v0.1.md) describes event capture, and the
[proof-pack spec](docs/specs/proof-pack-v0.1.md) describes the exported record
and verification checks. Run `python -m trustai --help` for CLI commands and
`python -m trustai <command> --help` for a command's inputs.

The bundled aitrade records and signing keys are examples. Generate your own
keys and provide your own source records when testing your environment.

## Documentation

- [Roadmap and feature coverage](docs/architecture/roadmap-coverage.md)
- [Go offline verifier](verifier/go/trustai-verify/README.md)
- [Local deployment scaffold](docs/deployment/byoc.md)
- [Example evidence and readiness report](examples/aitrade/external-evidence/retained-external-evidence-readiness.md)
- [Contributing](CONTRIBUTING.md) and [security reports](SECURITY.md)

The detailed command examples and artifact contracts live in `docs/specs/`,
the verifier documentation, and the roadmap coverage notes rather than in this
front page.

## Development

Run the Python test suite with `python -m unittest discover -s tests`. For
changes to the Go verifier, run `go test ./...` from
`verifier/go/trustai-verify/`. The CI workflows are in
`.github/workflows/`.

Licensed under [Apache-2.0](LICENSE).
