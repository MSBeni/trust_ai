import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash
from trustai.chain import EvidenceChain
from trustai.cicd import build_promotion_check_payload, build_promotion_status_receipt, write_promotion_status_receipt
from trustai.delivery import build_provider_delivery, write_provider_delivery
from trustai.promotion_status_bundle import (
    PROMOTION_STATUS_BUNDLE_ENTRY_TYPE,
    PROMOTION_STATUS_BUNDLE_SCHEMA,
    append_promotion_status_bundle,
    build_promotion_status_bundle,
    extract_promotion_status_bundle_sources,
    render_promotion_status_bundle_markdown,
    verify_promotion_status_bundle,
)
from trustai.verifier import load_proof_pack, verify_proof_pack


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "artifacts" / "aitrade-proof-pack.json"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class PromotionStatusBundleTests(unittest.TestCase):
    def _sources(self, tmp: Path) -> tuple[dict, dict[str, Path]]:
        pack = load_proof_pack(PACK)
        verification = verify_proof_pack(pack)
        payload = build_promotion_check_payload(
            pack,
            verification,
            provider="github",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repository="volelabs/trust_ai",
            target_url="https://example.test/proof-pack",
        )
        response_body = {"id": "check-run-123", "status": "completed", "conclusion": "success"}
        paths = {
            "receipt": tmp / "promotion-status.json",
            "proof_pack": tmp / "aitrade-proof-pack.json",
            "payload": tmp / "github-check-run-payload.json",
            "delivery": tmp / "github-check-run-delivery.json",
            "delivery_response_artifact": tmp / "github-check-run-response.json",
        }
        _write_json(paths["proof_pack"], pack)
        _write_json(paths["payload"], payload)
        _write_json(paths["delivery_response_artifact"], response_body)
        delivery = build_provider_delivery(
            payload,
            endpoint_base="https://api.github.com",
            credential_ref="env:GITHUB_TOKEN",
            mode="recorded-response",
            response_status=201,
            response_body=response_body,
            delivered_at="2026-07-04T00:00:00Z",
            payload_artifact_path=paths["payload"],
            response_artifact_path=paths["delivery_response_artifact"],
        )
        receipt = build_promotion_status_receipt(
            pack,
            verification,
            payload,
            delivery=delivery,
            delivery_payload_artifact_path=paths["payload"],
            delivery_response_artifact_path=paths["delivery_response_artifact"],
            attested_at="2026-07-04T00:01:00Z",
        )
        write_provider_delivery(paths["delivery"], delivery)
        write_promotion_status_receipt(paths["receipt"], receipt)
        return {"pack": pack, "payload": payload, "delivery": delivery, "receipt": receipt}, paths

    def _bundle(self, tmp: Path) -> tuple[dict, dict, dict[str, Path]]:
        sources, paths = self._sources(tmp)
        bundle = build_promotion_status_bundle(
            sources["receipt"],
            sources["pack"],
            sources["payload"],
            delivery=sources["delivery"],
            artifact_paths=paths,
            reviewer_ref="oidc:auditor.example/cicd-reviewer",
            generated_at="2026-07-04T00:02:00Z",
        )
        return bundle, sources, paths

    def test_promotion_status_bundle_verifies_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, sources, _ = self._bundle(tmp)
            result = verify_promotion_status_bundle(bundle)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="promotion-status-bundle-test")
            entry = append_promotion_status_bundle(chain, bundle)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(PROMOTION_STATUS_BUNDLE_SCHEMA, bundle["schema"])
        self.assertEqual(5, bundle["summary"]["source_artifact_count"])
        self.assertEqual(sources["receipt"]["receipt_id"], bundle["source"]["receipt_id"])
        self.assertTrue(bundle["summary"]["provider_target_bound"])
        self.assertTrue(bundle["summary"]["provider_proof_pack_ref_bound"])
        self.assertTrue(bundle["summary"]["retained_payload_artifact_replayed"])
        self.assertTrue(bundle["summary"]["retained_response_artifact_replayed"])
        self.assertEqual(PROMOTION_STATUS_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
        self.assertEqual({"passed": 6}, entry["payload"]["control_summary"])
        self.assertTrue(chain.verify_all().ok)

    def test_promotion_status_bundle_renders_and_extracts_sources(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            bundle, _, paths = self._bundle(tmp)
            markdown = render_promotion_status_bundle_markdown(bundle)
            extract_dir = tmp / "promotion-status-bundle-sources"
            extracted = extract_promotion_status_bundle_sources(bundle, extract_dir)

            self.assertIn("TrustAI Promotion Status Review Bundle", markdown)
            self.assertIn("Provider target", markdown)
            self.assertEqual(5, len(extracted))
            receipt_extract = extract_dir / "receipt.json"
            response_extract = extract_dir / "delivery_response_artifact.json"
            self.assertTrue(receipt_extract.exists())
            self.assertTrue(response_extract.exists())
            self.assertEqual(paths["receipt"].read_bytes(), receipt_extract.read_bytes())
            with self.assertRaisesRegex(ValueError, "already exists"):
                extract_promotion_status_bundle_sources(bundle, extract_dir)
            overwritten = extract_promotion_status_bundle_sources(bundle, extract_dir, overwrite=True)
            self.assertEqual(5, len(overwritten))

    def test_promotion_status_bundle_detects_embedded_payload_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle, *_ = self._bundle(Path(tmp_dir))
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["payload"]["request"]["body"]["conclusion"] = "failure"
            result = verify_promotion_status_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("bundle_id" in error for error in result.errors))
        self.assertTrue(any("source artifact does not match embedded source: payload" in error for error in result.errors), result.errors)

    def test_promotion_status_bundle_detects_response_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bundle, *_ = self._bundle(Path(tmp_dir))
            tampered = copy.deepcopy(bundle)
            response_index = next(index for index, artifact in enumerate(tampered["source_artifacts"]) if artifact["name"] == "delivery_response_artifact")
            tampered["source_artifacts"][response_index]["content_b64"] = base64.b64encode(
                json.dumps({"id": "check-run-123", "status": "completed", "conclusion": "failure"}).encode("utf-8")
            ).decode("ascii")
            result = verify_promotion_status_bundle(tampered)

        self.assertFalse(result.ok)
        self.assertTrue(any("source artifact sha256 mismatch" in error for error in result.errors))
        self.assertTrue(any("source replay" in error for error in result.errors), result.errors)

    def test_cli_promotion_status_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, paths = self._sources(tmp)
            bundle_path = tmp / "promotion-status-review-bundle.json"
            markdown_path = tmp / "promotion-status-review-bundle.md"
            render_path = tmp / "promotion-status-review-bundle-rendered.md"
            extract_dir = tmp / "promotion-status-review-bundle-sources"
            entry_path = tmp / "promotion-status-review-bundle-entry.json"
            state_path = tmp / "promotion-status-review-bundle-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.run(
                base
                + [
                    "promotion-status-bundle",
                    str(paths["receipt"]),
                    str(paths["proof_pack"]),
                    str(paths["payload"]),
                    "--delivery",
                    str(paths["delivery"]),
                    "--delivery-response-artifact",
                    str(paths["delivery_response_artifact"]),
                    "--reviewer-ref",
                    "oidc:auditor.example/cicd-reviewer",
                    "--generated-at",
                    "2026-07-04T00:02:00Z",
                    "--out",
                    str(bundle_path),
                    "--markdown",
                    str(markdown_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(base + ["promotion-status-bundle-verify", str(bundle_path)], cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            subprocess.run(
                base + ["promotion-status-bundle-render", str(bundle_path), "--out", str(render_path)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base + ["promotion-status-bundle-extract", str(bundle_path), "--out-dir", str(extract_dir)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "promotion-status-bundle-append",
                    str(bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "promotion-status-bundle-cli",
                    "--out",
                    str(entry_path),
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
            response_extract_exists = (extract_dir / "delivery_response_artifact.json").exists()

        self.assertEqual(PROMOTION_STATUS_BUNDLE_SCHEMA, bundle["schema"])
        self.assertEqual(PROMOTION_STATUS_BUNDLE_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
        self.assertEqual(content_hash(bundle["sources"]["payload"]), bundle["summary"]["source_object_hashes"]["payload"])
        self.assertTrue(markdown_exists)
        self.assertTrue(render_exists)
        self.assertTrue(response_extract_exists)


if __name__ == "__main__":
    unittest.main()
