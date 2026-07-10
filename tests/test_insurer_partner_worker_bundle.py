import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_insurer_partner_worker import InsurerPartnerWorkerTests
from trustai.actuarial import write_actuarial_corpus, write_actuarial_product
from trustai.chain import EvidenceChain
from trustai.insurer import write_insurer_telemetry
from trustai.insurer_partner_service import write_insurer_partner_service_attestation
from trustai.insurer_partner_worker import write_insurer_partner_worker_receipt
from trustai.insurer_partner_worker_bundle import (
    INSURER_PARTNER_WORKER_BUNDLE_ENTRY_TYPE,
    INSURER_PARTNER_WORKER_BUNDLE_SCHEMA,
    append_insurer_partner_worker_bundle,
    build_insurer_partner_worker_bundle,
    extract_insurer_partner_worker_bundle_sources,
    render_insurer_partner_worker_bundle_markdown,
    verify_insurer_partner_worker_bundle,
    write_insurer_partner_worker_bundle,
    write_insurer_partner_worker_bundle_markdown,
)
from trustai.underwriting_quote import write_underwriting_quote


ROOT = Path(__file__).resolve().parents[1]


class InsurerPartnerWorkerBundleTests(unittest.TestCase):
    def _sources(self, tmp: Path):
        helper = InsurerPartnerWorkerTests(methodName="test_insurer_partner_worker_verifies_and_appends")
        sources = helper._sources(tmp)
        receipt = helper._receipt(sources)
        paths = {
            "worker_receipt": tmp / "insurer-partner-worker.json",
            "service_attestation": tmp / "insurer-partner-service-attestation.json",
            "telemetry": tmp / "insurer-risk-telemetry.json",
            "underwriting_quote": tmp / "underwriting-quote.json",
            "actuarial_product": tmp / "actuarial-product.json",
            "actuarial_corpora": [tmp / "actuarial-corpus.json"],
            "frontend_bundle": sources["frontend_bundle_path"],
        }
        write_insurer_partner_worker_receipt(paths["worker_receipt"], receipt)
        write_insurer_partner_service_attestation(paths["service_attestation"], sources["service"])
        write_insurer_telemetry(paths["telemetry"], sources["telemetry"])
        write_underwriting_quote(paths["underwriting_quote"], sources["quote"])
        write_actuarial_product(paths["actuarial_product"], sources["product"])
        write_actuarial_corpus(paths["actuarial_corpora"][0], sources["corpus"])
        bundle = build_insurer_partner_worker_bundle(
            receipt,
            sources["service"],
            sources["telemetry"],
            sources["quote"],
            actuarial_product=sources["product"],
            actuarial_corpora=[sources["corpus"]],
            frontend_bundle_path=sources["frontend_bundle_path"],
            artifact_paths=paths,
            mode="underwriter-review",
            environment="aitrade-prod",
            reviewer_ref="oidc:underwriter.example/trustai-reviewer",
            generated_at="2026-07-09T00:00:00Z",
            now="2026-07-09T00:00:00Z",
        )
        return bundle, receipt, sources, paths

    def test_insurer_partner_worker_bundle_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, receipt, _, _ = self._sources(tmp)
            result = verify_insurer_partner_worker_bundle(bundle)
            chain = EvidenceChain.load(tmp / "bundle-chain.json", tenant_id="insurer-partner-worker-bundle-test")
            entry = append_insurer_partner_worker_bundle(chain, bundle)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(INSURER_PARTNER_WORKER_BUNDLE_SCHEMA, bundle["schema"])
            self.assertEqual(receipt["worker_operation_id"], bundle["source"]["worker_operation_id"])
            self.assertTrue(bundle["summary"]["frontend_bundle_replayed"])
            self.assertEqual(INSURER_PARTNER_WORKER_BUNDLE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_insurer_partner_worker_bundle_renders_and_extracts_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, _, sources, _ = self._sources(tmp)
            markdown_path = tmp / "insurer-partner-worker-bundle.md"
            bundle_path = tmp / "insurer-partner-worker-bundle.json"
            out_dir = tmp / "extracted"
            write_insurer_partner_worker_bundle(bundle_path, bundle)
            write_insurer_partner_worker_bundle_markdown(markdown_path, bundle)
            extracted = extract_insurer_partner_worker_bundle_sources(bundle, out_dir)
            names = {record["name"] for record in extracted}

            self.assertIn("TrustAI Insurer Partner Worker Bundle", render_insurer_partner_worker_bundle_markdown(bundle))
            self.assertTrue(markdown_path.exists())
            self.assertIn("frontend_bundle", names)
            self.assertEqual(sources["frontend_bundle_path"].read_bytes(), (out_dir / "frontend_bundle.js").read_bytes())

    def test_insurer_partner_worker_bundle_detects_source_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle, _, _, _ = self._sources(Path(tmp_dir))
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["telemetry"]["risk_score"] = 1
            result = verify_insurer_partner_worker_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertIn("insurer partner worker bundle source artifact does not match embedded source: telemetry", result.errors)

    def test_insurer_partner_worker_bundle_detects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle, _, _, _ = self._sources(Path(tmp_dir))
            tampered = copy.deepcopy(bundle)
            for artifact in tampered["source_artifacts"]:
                if artifact["name"] == "underwriting_quote":
                    artifact["content_b64"] = base64.b64encode(b'{"tampered": true}').decode("ascii")
                    break
            result = verify_insurer_partner_worker_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertIn("insurer partner worker bundle source artifact sha256 mismatch: underwriting_quote", result.errors)

    def test_insurer_partner_worker_bundle_rejects_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle, _, _, _ = self._sources(Path(tmp_dir))
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["worker_receipt"]["partner_credential"] = {"token": "raw-secret"}
            result = verify_insurer_partner_worker_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertIn("insurer partner worker bundle secret-like field must be redacted reference: sources.worker_receipt.partner_credential", result.errors)

    def test_cli_insurer_partner_worker_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, _, sources, paths = self._sources(tmp)
            bundle_path = tmp / "cli-insurer-partner-worker-bundle.json"
            markdown_path = tmp / "cli-insurer-partner-worker-bundle.md"
            render_path = tmp / "cli-rendered.md"
            extract_dir = tmp / "cli-extracted"
            entry_path = tmp / "cli-insurer-partner-worker-bundle-entry.json"
            state_path = tmp / "cli-insurer-partner-worker-bundle-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(paths["worker_receipt"]),
                str(paths["service_attestation"]),
                str(paths["telemetry"]),
                str(paths["underwriting_quote"]),
                "--actuarial-product",
                str(paths["actuarial_product"]),
                "--actuarial-corpus",
                str(paths["actuarial_corpora"][0]),
                "--frontend-bundle",
                str(sources["frontend_bundle_path"]),
                "--now",
                "2026-07-09T00:00:00Z",
            ]
            commands = [
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "insurer-partner-worker-bundle",
                    *source_args,
                    "--mode",
                    "underwriter-review",
                    "--environment",
                    "aitrade-prod",
                    "--reviewer-ref",
                    "oidc:underwriter.example/trustai-reviewer",
                    "--generated-at",
                    "2026-07-09T00:00:00Z",
                    "--out",
                    str(bundle_path),
                    "--markdown",
                    str(markdown_path),
                ],
                [sys.executable, "-m", "trustai", "insurer-partner-worker-bundle-verify", str(bundle_path)],
                [sys.executable, "-m", "trustai", "insurer-partner-worker-bundle-render", str(bundle_path), "--out", str(render_path)],
                [sys.executable, "-m", "trustai", "insurer-partner-worker-bundle-extract", str(bundle_path), "--out-dir", str(extract_dir)],
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "insurer-partner-worker-bundle-append",
                    str(bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "insurer-partner-worker-bundle-local",
                    "--out",
                    str(entry_path),
                ],
            ]
            for command in commands:
                completed = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(0, completed.returncode, completed.stderr)

            created = json.loads(bundle_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            self.assertEqual(bundle["source"]["worker_operation_id"], created["source"]["worker_operation_id"])
            self.assertEqual(created["bundle_id"], entry["payload"]["bundle_id"])
            self.assertTrue(markdown_path.exists())
            self.assertTrue(render_path.exists())
            self.assertTrue((extract_dir / "frontend_bundle.js").exists())


if __name__ == "__main__":
    unittest.main()
