import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.delivery import write_provider_delivery
from trustai.provider_audit import write_provider_audit_correlation
from trustai.provider_delivery_service import write_provider_delivery_service_attestation
from trustai.provider_delivery_worker import write_provider_delivery_worker_receipt
from trustai.provider_delivery_worker_bundle import (
    PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE,
    PROVIDER_DELIVERY_WORKER_BUNDLE_SCHEMA,
    append_provider_delivery_worker_bundle,
    build_provider_delivery_worker_bundle,
    extract_provider_delivery_worker_bundle_sources,
    render_provider_delivery_worker_bundle_markdown,
    verify_provider_delivery_worker_bundle,
)

from tests.test_provider_delivery_worker import ProviderDeliveryWorkerTests


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class ProviderDeliveryWorkerBundleTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = ProviderDeliveryWorkerTests(methodName="test_provider_delivery_worker_verifies_and_appends")
        sources = helper._recorded_response_with_provider_audit_sources()
        receipt = helper._receipt(**sources)
        paths = {
            "worker_receipt": tmp / "provider-delivery-worker.json",
            "service_attestation": tmp / "provider-delivery-service-attestation.json",
            "delivery": tmp / "provider-delivery.json",
            "payload": tmp / "provider-payload.json",
            "provider_operations_service": tmp / "provider-operations-service-attestation.json",
            "provider_response": tmp / "provider-response.json",
            "provider_audit_correlation": tmp / "provider-audit-correlation.json",
            "provider_audit_log": tmp / "provider-audit-log.json",
        }
        write_provider_delivery_worker_receipt(paths["worker_receipt"], receipt)
        write_provider_delivery_service_attestation(paths["service_attestation"], sources["service_attestation"])
        write_provider_delivery(paths["delivery"], sources["delivery"])
        source_payload_path = Path(sources["payload_artifact_path"])
        if not source_payload_path.is_absolute():
            source_payload_path = ROOT / source_payload_path
        paths["payload"].write_bytes(source_payload_path.read_bytes())
        _write_json(paths["provider_operations_service"], sources["provider_operations_service"])
        _write_json(paths["provider_response"], sources["provider_response"])
        write_provider_audit_correlation(paths["provider_audit_correlation"], sources["provider_audit_correlation"])
        _write_json(paths["provider_audit_log"], sources["provider_audit_log"])
        return receipt, sources, paths

    def _bundle(self, tmp: Path):
        receipt, sources, paths = self._sources(tmp)
        bundle = build_provider_delivery_worker_bundle(
            receipt,
            sources["service_attestation"],
            sources["delivery"],
            payload=sources["payload"],
            provider_operations_service=sources["provider_operations_service"],
            provider_response=sources["provider_response"],
            provider_audit_correlation=sources["provider_audit_correlation"],
            provider_audit_log=sources["provider_audit_log"],
            artifact_paths=paths,
            mode="offline-review",
            environment="aitrade-prod",
            reviewer_ref="oidc:auditor.example/provider-delivery-reviewer",
            generated_at="2026-07-08T05:17:00Z",
        )
        return bundle, receipt, sources, paths

    def test_provider_delivery_worker_bundle_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, receipt, sources, _ = self._bundle(tmp)
            result = verify_provider_delivery_worker_bundle(bundle)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="provider-delivery-worker-bundle-test")
            entry = append_provider_delivery_worker_bundle(chain, bundle)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROVIDER_DELIVERY_WORKER_BUNDLE_SCHEMA, bundle["schema"])
        self.assertEqual(8, bundle["summary"]["source_artifact_count"])
        self.assertEqual(receipt["worker_operation_id"], bundle["source"]["worker_operation_id"])
        self.assertEqual(sources["delivery"]["delivery_id"], bundle["source"]["delivery_id"])
        self.assertTrue(bundle["summary"]["provider_response_replayed"])
        self.assertTrue(bundle["summary"]["provider_audit_replayed"])
        self.assertTrue(bundle["summary"]["retained_payload_artifact_replayed"])
        self.assertFalse(any("payload artifact was not replayed" in warning for warning in result.warnings))
        self.assertEqual(PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
        self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])
        self.assertTrue(chain.verify_all().ok)

    def test_provider_delivery_worker_bundle_renders_and_extracts_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, _, _, paths = self._bundle(tmp)
            markdown = render_provider_delivery_worker_bundle_markdown(bundle)
            extract_dir = tmp / "bundle-sources"
            extracted = extract_provider_delivery_worker_bundle_sources(bundle, extract_dir)

            self.assertIn("TrustAI Provider Delivery Worker Bundle", markdown)
            self.assertIn("Embedded source artifacts: 8", markdown)
            self.assertIn("Provider audit replayed: True", markdown)
            self.assertIn("Retained payload artifact replayed: True", markdown)
            self.assertEqual(8, len(extracted))
            worker_extract = extract_dir / "worker_receipt.json"
            self.assertTrue(worker_extract.exists())
            self.assertEqual(Path(paths["worker_receipt"]).read_bytes(), worker_extract.read_bytes())
            with self.assertRaisesRegex(ValueError, "already exists"):
                extract_provider_delivery_worker_bundle_sources(bundle, extract_dir)
            overwritten = extract_provider_delivery_worker_bundle_sources(bundle, extract_dir, overwrite=True)
            self.assertEqual(8, len(overwritten))

    def test_provider_delivery_worker_bundle_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["provider_audit_log"]["events"][0]["provider_payload_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            result = verify_provider_delivery_worker_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("bundle_id" in error for error in result.errors))
        self.assertTrue(any("source replay" in error for error in result.errors))
        self.assertTrue(any("source artifact does not match embedded source" in error for error in result.errors))

    def test_provider_delivery_worker_bundle_detects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["source_artifacts"][0]["content_b64"] = base64.b64encode(b"{}").decode("ascii")
            result = verify_provider_delivery_worker_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("source artifact sha256 mismatch" in error for error in result.errors))
        self.assertTrue(any("source artifact does not match embedded source" in error for error in result.errors))

    def test_provider_delivery_worker_bundle_detects_payload_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            payload_index = next(index for index, artifact in enumerate(tampered["source_artifacts"]) if artifact["name"] == "payload")
            tampered["source_artifacts"][payload_index]["content_b64"] = base64.b64encode(b"{}").decode("ascii")
            result = verify_provider_delivery_worker_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("payload_artifact" in error for error in result.errors))

    def test_provider_delivery_worker_bundle_rejects_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, *_ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["provider_response"].setdefault("headers", {})["Authorization"] = "Bearer raw-token"
            result = verify_provider_delivery_worker_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("secret-like field" in error for error in result.errors))

    def test_cli_provider_delivery_worker_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, _, paths = self._sources(tmp)
            bundle_path = tmp / "provider-delivery-worker-bundle.json"
            entry_path = tmp / "provider-delivery-worker-bundle-entry.json"
            markdown_path = tmp / "provider-delivery-worker-bundle.md"
            render_path = tmp / "provider-delivery-worker-bundle-rendered.md"
            extract_dir = tmp / "provider-delivery-worker-bundle-sources"
            state_path = tmp / "provider-delivery-worker-bundle-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]
            source_args = [
                str(paths["delivery"]),
                "--service-attestation", str(paths["service_attestation"]),
                "--payload", str(paths["payload"]),
                "--provider-operations-service", str(paths["provider_operations_service"]),
                "--provider-response", str(paths["provider_response"]),
                "--provider-audit-correlation", str(paths["provider_audit_correlation"]),
                "--provider-audit-log", str(paths["provider_audit_log"]),
            ]

            subprocess.run(
                base
                + [
                    "provider-delivery-worker-bundle",
                    str(paths["worker_receipt"]),
                    *source_args,
                    "--reviewer-ref", "oidc:auditor.example/provider-delivery-reviewer",
                    "--generated-at", "2026-07-08T05:17:00Z",
                    "--out", str(bundle_path),
                    "--markdown", str(markdown_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(base + ["provider-delivery-worker-bundle-verify", str(bundle_path)], cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            subprocess.run(
                base + ["provider-delivery-worker-bundle-render", str(bundle_path), "--out", str(render_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["provider-delivery-worker-bundle-extract", str(bundle_path), "--out-dir", str(extract_dir)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "provider-delivery-worker-bundle-append",
                    str(bundle_path),
                    "--state", str(state_path),
                    "--tenant", "provider-delivery-worker-bundle-cli",
                    "--out", str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            markdown_exists = markdown_path.exists()
            render_exists = render_path.exists()
            audit_log_extract_exists = (extract_dir / "provider_audit_log.json").exists()

        self.assertEqual(PROVIDER_DELIVERY_WORKER_BUNDLE_SCHEMA, bundle["schema"])
        self.assertEqual(PROVIDER_DELIVERY_WORKER_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
        self.assertTrue(markdown_exists)
        self.assertTrue(render_exists)
        self.assertTrue(audit_log_extract_exists)


if __name__ == "__main__":
    unittest.main()