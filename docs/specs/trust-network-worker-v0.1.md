# Trust-Network Worker Receipt v0.1

Trust-network worker receipts record one registry or marketplace worker run as
signed, tamper-evident evidence. They bridge the gap between a hosted
trust-network service attestation and actual worker execution for registry
publication, status propagation, marketplace catalog sync, entitlement
reconciliation, and marketplace settlement reconciliation.

The receipt is intentionally a metadata and hash artifact. It does not store raw
provider responses, credentials, buyer data, payout account data, or tax
documents.

## Schema

`trustai.trust-network-worker/0.1`

Required top-level fields:

- `worker_operation_id`: canonical hash of the receipt body.
- `signatures`: detached signatures over the operation id and body.
- `service`: signed trust-network service attestation binding.
- `registry`: trust-network registry publication and optional status receipt
  binding.
- `marketplace`: optional catalog, distribution, author governance, and
  settlement receipt bindings.
- `worker`: worker ref, run ref, operation kind, actor, timing, attempt, and
  success state.
- `scheduler`: schedule, lease, checkpoint, optional cursor handoff, and next
  run metadata.
- `propagation`: queue, destination, publication log, cache invalidation,
  request/response hashes, optional external callback ref, and provider-owned
  ledger log hashes.
- `source`: replayable source artifact ids, schemas, and hashes.
- `credential`: redacted worker credential reference.
- `observability`: metrics, audit-log root, and evidence references.
- `controls`: implemented/planned control summary.

Supported operation kinds:

- `registry_publish`
- `registry_status_propagation`
- `marketplace_catalog_sync`
- `marketplace_entitlement_reconcile`
- `marketplace_settlement_reconcile`
- `registry_marketplace_reconcile`

## Verification

The verifier checks:

- schema, canonical `worker_operation_id`, and detached signature.
- supported mode and operation kind.
- worker start/completion ordering and attempt bounds.
- scheduler cadence, lease, checkpoint, and optional cursor metadata.
- source artifact replay for the service attestation, registry receipt, registry
  status receipt, marketplace catalog/distribution, marketplace author
  governance, and marketplace settlement when supplied.
- deep trust-network service verification, including supplied frontend bundle replay, when the registry and service source
  artifacts are supplied.
- deep marketplace author and settlement verification when those source
  artifacts are supplied.
- operation-specific source requirements, including settlement receipt evidence
  for `marketplace_settlement_reconcile`.
- SHA-256 references for checkpoint, publication log, audit log, request,
  response, and provider-owned invoice/payout/tax hashes.
- redacted credential references and absence of unredacted secret-like fields.

If source artifacts are omitted, the receipt remains self-describing but the
verifier emits warnings that the corresponding hashes were not replayed.

## Chain Evidence

`trust-network-worker-append` emits a `trust_network.worker_recorded` chain entry
containing:

- worker operation id and receipt hash.
- service, registry, marketplace, worker, scheduler, propagation, source, and
  credential bindings.
- control-status summary.

This gives buyers, vendors, auditors, marketplace operators, and future
standards bodies a replayable record that hosted registry/marketplace worker
execution was bound to source receipt hashes, scheduling continuity,
publication/audit roots, and redacted credential references.

## CLI

```powershell
$env:PYTHONPATH = "src"
python -m trustai trust-network-worker --service-attestation artifacts/trust-network-service-attestation.json artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root . --mode hosted-worker --environment aitrade-prod --worker-ref worker:trust-network/marketplace-settlement-reconciler --run-ref worker-run:trust-network/marketplace-settlement/2026-07-12T03:05:00Z --operation-kind marketplace_settlement_reconcile --actor-ref oidc:trustai.example/trust-network-worker --schedule-ref schedule:trust-network/marketplace-settlement/5m --cadence-seconds 300 --lease-ref lease:trust-network/marketplace-settlement/2026-07-12T03:05:00Z --checkpoint-ref checkpoint:trust-network/marketplace-settlement --checkpoint-hash sha256:trust-network-worker-checkpoint --previous-cursor-ref cursor:trust-network/marketplace-settlement/start --next-cursor-ref cursor:trust-network/marketplace-settlement/next --queue-ref queue:trust-network/subscriptions --queue-message-ref queue-message:trust-network/settlement/EXAMPLE-2026-001 --destination-ref marketplace:https://marketplace.example/catalogs/trustai --publication-log-ref publication-log:trust-network/registry-marketplace --publication-log-root sha256:trust-network-worker-publication-root --cache-invalidation-ref cache-invalidation:trust-network/EXAMPLE-2026-001 --external-callback-ref callback:marketplace/settlement/EXAMPLE-2026-001 --provider-invoice-log-ref stripe:invoice/in_EXAMPLE --provider-invoice-log-hash sha256:provider-invoice-log-hash --provider-payout-log-ref stripe:transfer/tr_EXAMPLE --provider-payout-log-hash sha256:provider-payout-log-hash --provider-tax-custody-ref vault:tax-documents/example-audit/w9-2026 --provider-tax-document-hash sha256:marketplace-tax-document-hash --request-hash sha256:trust-network-worker-request --response-status 202 --response-hash sha256:trust-network-worker-response --metrics-ref metrics:trust-network/workers --audit-log-ref audit-log:trust-network/workers --audit-log-root sha256:trust-network-worker-audit-root --credential-ref env:TRUST_NETWORK_WORKER_TOKEN --evidence-ref evidence:trust-network/worker --started-at 2026-07-12T03:05:00Z --completed-at 2026-07-12T03:06:00Z --next-run-at 2026-07-12T03:10:00Z --out artifacts/trust-network-worker.json
python -m trustai trust-network-worker-verify artifacts/trust-network-worker.json --service-attestation artifacts/trust-network-service-attestation.json artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root .
python -m trustai trust-network-worker-append artifacts/trust-network-worker.json --service-attestation artifacts/trust-network-service-attestation.json artifacts/trust-network-registry.json --manifest artifacts/trust-network-manifest.json --vendor-identity artifacts/vendor-identity-receipt.json --identity-attestation artifacts/identity-provider-attestation.json --identity-payload examples/aitrade/identity-inventory.json --procurement-receipt artifacts/procurement-clause-receipt.json --procurement-integration artifacts/procurement-integration-receipt.json --pack artifacts/aitrade-proof-pack.json --registry-status artifacts/trust-network-registry-status.json --marketplace-catalog artifacts/marketplace-catalog.json --marketplace-distribution artifacts/marketplace-distribution.json --frontend-bundle artifacts/trust-network.bundle.js --marketplace-author-governance artifacts/marketplace-author-governance.json --marketplace-settlement artifacts/marketplace-settlement.json --root . --state .trustai/trust-network-worker-demo/evidence-chain.json --tenant trust-network-worker-local --out artifacts/trust-network-worker-entry.json
python -m trustai chain-verify --state .trustai/trust-network-worker-demo/evidence-chain.json --tenant trust-network-worker-local
```

Production trust-network workers still require continuously operated hosted
worker fleets, production scheduler/lease storage, live identity-provider and
provider-owned log exports, immutable publication/audit logs, and live external
provider callbacks beyond this signed local/reference receipt.
