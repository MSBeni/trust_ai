# Traffic Completeness Receipt v0.1

A traffic completeness receipt is a signed proof that a traffic holdout export was
reconciled against collector or provider-owned export evidence before the replay
window is trusted for promotion. It is the companion artifact to the traffic
holdout export receipt: the export receipt binds the replay records; the
completeness receipt binds those records to stream, cursor, and audit evidence
from the collection path. When generated from a provider export file, it also records a retained source artifact summary with path, byte SHA-256, size, canonical content hash, and artifact ID so whitespace-only or transport-level byte changes are detectable offline.

## Artifact

The receipt uses schema `trustai.traffic-completeness-receipt/0.1` and records:

- mode: `local-export`, `provider-export`, or `production-export`;
- authority ref, produced timestamp, and provider exchange evidence;
- traffic holdout export ID, hash, source ref, cursor bounds, extraction window,
  record count, and records root;
- provider export ref, provider/environment/source refs, stream topic, window,
  cursor bounds, traffic record count/root, stream record root, and audit root;
- optional `provider_export_artifact` with retained provider export path, byte SHA-256,
  size, canonical content hash, and artifact ID;
- matched replay/export records with provider cursor refs, provider record
  hashes, provider source refs, previous export-record hash bindings, and
  per-record binding mismatch lists;
- extra provider records, missing provider matches, duplicate provider cursor
  refs, duplicate provider record identities, and duplicate provider export
  record hashes;
- matched audit records that bind the traffic export ID or records root;
- explicit completeness violations and pass/fail status;
- `production_claim`, a canonical object that says whether the receipt claims
  live provider-owned production completeness, whether that claim passed, and
  the non-production limitation for local/provider rehearsal modes;
- privacy metadata confirming raw production traffic payloads and provider
  credentials are not embedded.

## Verification

`traffic-completeness-verify` recalculates the receipt ID, verifies the signature,
checks the provider exchange status, recomputes completeness violations from the
embedded coverage summary, and can replay both source artifacts:

- the signed traffic holdout export receipt; and
- the provider export JSON containing stream records and audit records.

When source artifacts are supplied, the verifier recomputes the traffic export
hash, provider export hash, stream record root, audit record root, matched record
set, missing/extra record counts, matched audit records, provider stream cursor
presence/uniqueness, provider record-key uniqueness, matched row source/ref hash-chain
metadata, controls, violations, and pass/fail status. If the receipt contains
`provider_export_artifact`, the verifier also replays the retained provider export
file bytes and rejects byte SHA-256 mismatches even when the canonical parsed JSON
content is unchanged. Editing a provider stream record, removing a replay record,
reusing a cursor ref, changing a matched provider row's previous export hash or
source ref, changing only provider export formatting bytes, or changing the provider
audit export changes the receipt verification result.

`production-export` is required for production completeness claims. The other
modes are useful for local and design-partner rehearsal but do not claim live
provider-owned completeness. Verifiers recompute `production_claim` from the mode
and completeness violations, so a receipt cannot be re-signed to make a local or
failing provider export look like a passed production completeness claim.

## Chain Entry

Verified receipts append `traffic_holdout.completeness_attested` entries with:

- completeness ID and receipt hash;
- mode and authority ref;
- traffic export binding;
- provider export binding;
- provider export source artifact summary when supplied;
- source completeness summary;
- provider exchange evidence;
- violation count, pass/fail status, production-claim status, and privacy metadata.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai traffic-completeness artifacts/traffic-holdout-export.json examples/aitrade/traffic-completeness-provider-export.json --mode production-export --authority-ref authority:traffic-completeness/aitrade-prod --endpoint-url https://provider.example/aitrade/traffic-holdout/export --request-hash sha256:traffic-completeness-request --response-status 200 --response-hash sha256:traffic-completeness-response --actor-ref oidc:trustai.example/traffic-completeness-worker --produced-at 2026-07-03T12:25:00Z --out artifacts/traffic-completeness.json
python -m trustai traffic-completeness-verify artifacts/traffic-completeness.json --traffic-export artifacts/traffic-holdout-export.json --provider-export examples/aitrade/traffic-completeness-provider-export.json
python -m trustai traffic-completeness-append artifacts/traffic-completeness.json --traffic-export artifacts/traffic-holdout-export.json --provider-export examples/aitrade/traffic-completeness-provider-export.json --state .trustai/traffic-completeness-demo/evidence-chain.json --tenant traffic-completeness-local --out artifacts/traffic-completeness-entry.json
```