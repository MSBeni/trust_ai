import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.byoc_operator import build_byoc_operator_attestation, write_byoc_operator_attestation
from trustai.chain import EvidenceChain
from trustai.collector_service import (
    COLLECTOR_SERVICE_ENTRY_TYPE,
    COLLECTOR_SERVICE_SCHEMA,
    append_collector_service_attestation,
    build_collector_service_attestation,
    verify_collector_service_attestation,
)
from trustai.collector_topology import build_collector_topology, write_collector_topology
from trustai.deployment import build_deployment_manifest, write_deployment_manifest
from trustai.object_store import WORMStore


ROOT = Path(__file__).resolve().parents[1]


class CollectorServiceTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        topology = build_collector_topology(ROOT, environment="aitrade-local", generated_at="2026-07-04T00:10:00Z")
        deployment = build_deployment_manifest(ROOT, environment="aitrade-byoc", generated_at="2026-07-04T00:00:00Z")
        store_root = tmp / "worm"
        store = WORMStore(store_root)
        receipt = store.store_json(
            {"artifact": "proof-pack", "pack_id": "pack-123"},
            "proof-pack",
            retention_until="2033-07-04T00:00:00Z",
        )
        legal_hold = store.apply_legal_hold(
            receipt,
            case_id="external-audit-2026-001",
            reason="Preserve proof pack for external audit.",
            applied_by="legal@example.com",
            applied_at="2026-07-04T01:00:00Z",
        )
        byoc = build_byoc_operator_attestation(
            deployment,
            receipt,
            legal_hold=legal_hold,
            root=ROOT,
            store=store_root,
            environment="aitrade-byoc",
            operator_ref="operator:trustai/byoc",
            operator_version="0.1.0",
            operator_image="ghcr.io/trustai/operator:0.1.0",
            operator_image_digest="sha256:trustai-byoc-operator-digest",
            namespace="trustai",
            service_account_ref="k8s:sa/trustai/operator",
            reconciler_ref="controller:trustai/byoc-operator",
            upgrade_policy_ref="policy:trustai/byoc-upgrade-v0.1",
            rollback_policy_ref="policy:trustai/byoc-rollback-v0.1",
            tenant_id="aitrade-local",
            customer_account_ref="aws:123456789012",
            data_plane_ref="k8s:cluster/aitrade-prod",
            control_plane_ref="trustai:control-plane/local",
            keyring_ref="keyring:.trustai/keyring.local.json",
            object_lock_provider="Example S3 Object Lock",
            object_lock_bucket="arn:aws:s3:::trustai-aitrade-evidence",
            object_lock_region="us-east-1",
            backup_policy_ref="backup:trustai/daily",
            backup_schedule="rate(1 day)",
            restore_test_ref="restore-test:trustai/2026-07-04",
            restore_test_at="2026-07-04T02:00:00Z",
            rpo_minutes=60,
            rto_minutes=240,
            ingress_mode="private-load-balancer",
            egress_policy_ref="egress-policy:trustai/deny-by-default",
            allowed_egress_refs=["egress:kms", "egress:tsa"],
            audit_log_ref="audit-log:byoc/operator",
            audit_log_root="sha256:byoc-operator-audit-root",
            retention_until="2033-07-04T00:00:00Z",
            actor_ref="oidc:trustai.example/byoc-operator",
            credential_ref="env:BYOC_OPERATOR_TOKEN",
            attested_at="2026-07-04T03:00:00Z",
        )
        return topology, byoc, deployment, receipt, legal_hold, store_root

    def _attestation(self, tmp: Path):
        topology, byoc, deployment, receipt, legal_hold, store_root = self._sources(tmp)
        attestation = build_collector_service_attestation(
            topology,
            byoc_operator=byoc,
            deployment_manifest=deployment,
            worm_receipt=receipt,
            legal_hold=legal_hold,
            root=ROOT,
            store=store_root,
            environment="aitrade-prod",
            service_ref="collector:trustai/otel-prod",
            service_version="0.1.0",
            collector_image="ghcr.io/trustai/collector:0.1.0",
            collector_image_digest="sha256:trustai-collector-image",
            collector_binary_hash="sha256:trustai-collector-binary",
            replicas_min=3,
            replicas_max=9,
            availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"],
            mtls_policy_ref="policy:collector/mtls-required-v0.1",
            auth_policy_ref="policy:collector/oidc-tenant-authz-v0.1",
            tenant_isolation_ref="tenant-isolation:aitrade/collector",
            rate_limit_policy_ref="rate-limit:collector/aitrade",
            replay_cache_ref="redis:collector/replay-cache",
            idempotency_store_ref="postgres:collector/idempotency",
            ingress_ref="ingress:collector/private",
            network_policy_ref="netpol:collector/deny-by-default",
            egress_policy_ref="egress:collector/kms-tsa-only",
            stream_backend="redpanda",
            stream_ref="redpanda:trustai/collector-events",
            stream_topic="trustai.otel.events",
            stream_retention_hours=168,
            stream_dlq_ref="redpanda:trustai/collector-events-dlq",
            clickhouse_ref="clickhouse:trustai/traces",
            clickhouse_retention_days=2555,
            clickhouse_backup_ref="backup:clickhouse/trustai/daily",
            postgres_ref="postgres:trustai/control-plane",
            postgres_schema_hash="sha256:trustai-control-plane-schema",
            postgres_backup_ref="backup:postgres/trustai/daily",
            mcp_proxy_ref="mcp-proxy:trustai/prod",
            mcp_proxy_image_digest="sha256:trustai-mcp-proxy-image",
            framework_hook_refs=[
                "hook:langgraph/0.3",
                "hook:openai-agents/0.2",
                "hook:claude-agent-sdk/0.1",
            ],
            audit_log_ref="audit-log:collector/service",
            audit_log_root="sha256:collector-service-audit-root",
            retention_until="2033-07-04T00:00:00Z",
            actor_ref="oidc:trustai.example/collector-operator",
            credential_ref="env:COLLECTOR_SERVICE_TOKEN",
            evidence_refs=["evidence:collector/service"],
            attested_at="2026-07-04T04:00:00Z",
        )
        return attestation, topology, byoc, deployment, receipt, legal_hold, store_root

    def test_collector_service_attestation_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation, topology, byoc, deployment, receipt, legal_hold, store_root = self._attestation(tmp)
            result = verify_collector_service_attestation(
                attestation,
                topology,
                byoc_operator=byoc,
                deployment_manifest=deployment,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="collector-service-test")
            entry = append_collector_service_attestation(
                chain,
                attestation,
                topology,
                byoc_operator=byoc,
                deployment_manifest=deployment,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(COLLECTOR_SERVICE_SCHEMA, attestation["schema"])
            self.assertEqual(topology["topology_id"], attestation["source"]["topology_id"])
            self.assertEqual(byoc["attestation_id"], attestation["source"]["byoc_operator_attestation_id"])
            self.assertEqual(COLLECTOR_SERVICE_ENTRY_TYPE, entry["entry_type"])
            self.assertIn("service-attested", entry["payload"]["control_summary"])
            self.assertTrue(chain.verify_all().ok)

    def test_collector_service_attestation_rejects_stream_tls_disabled(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation, topology, byoc, deployment, receipt, legal_hold, store_root = self._attestation(tmp)
            tampered = copy.deepcopy(attestation)
            tampered["streaming"]["tls"] = False

            result = verify_collector_service_attestation(
                tampered,
                topology,
                byoc_operator=byoc,
                deployment_manifest=deployment,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )

            self.assertFalse(result.ok)
            self.assertIn("attestation_id does not match canonical collector service attestation body", result.errors)
            self.assertTrue(any("streaming.tls" in error for error in result.errors))

    def test_collector_service_attestation_rejects_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            attestation, topology, byoc, deployment, receipt, legal_hold, store_root = self._attestation(tmp)
            other_topology = copy.deepcopy(topology)
            other_topology["topology"]["environment"] = "different"

            result = verify_collector_service_attestation(
                attestation,
                other_topology,
                byoc_operator=byoc,
                deployment_manifest=deployment,
                worm_receipt=receipt,
                legal_hold=legal_hold,
                root=ROOT,
                store=store_root,
            )

            self.assertFalse(result.ok)
            self.assertTrue(any("source_artifacts" in error or "source record" in error for error in result.errors))

    def test_cli_collector_service_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            topology, byoc, deployment, receipt, legal_hold, store_root = self._sources(tmp)
            topology_path = tmp / "collector-topology.json"
            byoc_path = tmp / "byoc-operator-attestation.json"
            deployment_path = tmp / "deployment-manifest.json"
            receipt_path = tmp / "worm-receipt.json"
            hold_path = tmp / "legal-hold.json"
            attestation_path = tmp / "collector-service-attestation.json"
            entry_path = tmp / "collector-service-entry.json"
            write_collector_topology(topology_path, topology)
            write_byoc_operator_attestation(byoc_path, byoc)
            write_deployment_manifest(deployment_path, deployment)
            receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
            hold_path.write_text(json.dumps(legal_hold, indent=2, sort_keys=True), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.run(
                base
                + [
                    "collector-service-attestation",
                    str(topology_path),
                    "--byoc-operator",
                    str(byoc_path),
                    "--deployment-manifest",
                    str(deployment_path),
                    "--worm-receipt",
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                    "--environment",
                    "aitrade-prod",
                    "--service-ref",
                    "collector:trustai/otel-prod",
                    "--service-version",
                    "0.1.0",
                    "--collector-image",
                    "ghcr.io/trustai/collector:0.1.0",
                    "--collector-image-digest",
                    "sha256:trustai-collector-image",
                    "--collector-binary-hash",
                    "sha256:trustai-collector-binary",
                    "--replicas-min",
                    "3",
                    "--replicas-max",
                    "9",
                    "--availability-zone",
                    "us-east-1a",
                    "--availability-zone",
                    "us-east-1b",
                    "--mtls-policy-ref",
                    "policy:collector/mtls-required-v0.1",
                    "--auth-policy-ref",
                    "policy:collector/oidc-tenant-authz-v0.1",
                    "--tenant-isolation-ref",
                    "tenant-isolation:aitrade/collector",
                    "--rate-limit-policy-ref",
                    "rate-limit:collector/aitrade",
                    "--replay-cache-ref",
                    "redis:collector/replay-cache",
                    "--idempotency-store-ref",
                    "postgres:collector/idempotency",
                    "--ingress-ref",
                    "ingress:collector/private",
                    "--network-policy-ref",
                    "netpol:collector/deny-by-default",
                    "--egress-policy-ref",
                    "egress:collector/kms-tsa-only",
                    "--stream-ref",
                    "redpanda:trustai/collector-events",
                    "--stream-topic",
                    "trustai.otel.events",
                    "--stream-retention-hours",
                    "168",
                    "--stream-dlq-ref",
                    "redpanda:trustai/collector-events-dlq",
                    "--clickhouse-ref",
                    "clickhouse:trustai/traces",
                    "--clickhouse-retention-days",
                    "2555",
                    "--clickhouse-backup-ref",
                    "backup:clickhouse/trustai/daily",
                    "--postgres-ref",
                    "postgres:trustai/control-plane",
                    "--postgres-schema-hash",
                    "sha256:trustai-control-plane-schema",
                    "--postgres-backup-ref",
                    "backup:postgres/trustai/daily",
                    "--mcp-proxy-ref",
                    "mcp-proxy:trustai/prod",
                    "--mcp-proxy-image-digest",
                    "sha256:trustai-mcp-proxy-image",
                    "--framework-hook-ref",
                    "hook:langgraph/0.3",
                    "--audit-log-ref",
                    "audit-log:collector/service",
                    "--audit-log-root",
                    "sha256:collector-service-audit-root",
                    "--retention-until",
                    "2033-07-04T00:00:00Z",
                    "--actor-ref",
                    "oidc:trustai.example/collector-operator",
                    "--credential-ref",
                    "env:COLLECTOR_SERVICE_TOKEN",
                    "--attested-at",
                    "2026-07-04T04:00:00Z",
                    "--out",
                    str(attestation_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "collector-service-verify",
                    str(attestation_path),
                    str(topology_path),
                    "--byoc-operator",
                    str(byoc_path),
                    "--deployment-manifest",
                    str(deployment_path),
                    "--worm-receipt",
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                base
                + [
                    "collector-service-append",
                    str(attestation_path),
                    str(topology_path),
                    "--byoc-operator",
                    str(byoc_path),
                    "--deployment-manifest",
                    str(deployment_path),
                    "--worm-receipt",
                    str(receipt_path),
                    "--legal-hold",
                    str(hold_path),
                    "--root",
                    str(ROOT),
                    "--store",
                    str(store_root),
                    "--state",
                    str(tmp / "chain.json"),
                    "--tenant",
                    "collector-service-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(attestation_path.exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
