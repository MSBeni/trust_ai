import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.policy_backend_provider_bundle import (
    POLICY_BACKEND_PROVIDER_BUNDLE_ENTRY_TYPE,
    POLICY_BACKEND_PROVIDER_BUNDLE_SCHEMA,
    append_policy_backend_provider_bundle,
    build_policy_backend_provider_bundle,
    extract_policy_backend_provider_bundle_sources,
    verify_policy_backend_provider_bundle,
    write_policy_backend_provider_bundle_markdown,
)

from tests import test_policy_backend_provider as provider_fixtures


ROOT = provider_fixtures.worker_fixtures.ROOT


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


class PolicyBackendProviderBundleTests(unittest.TestCase):
    def _sources(self, tmp: Path) -> dict[str, object]:
        helper = provider_fixtures.PolicyBackendProviderTests()
        sources = helper._sources(tmp)
        sources["provider_receipt"] = helper._receipt(sources)
        return sources

    def _write_sources(self, tmp: Path, sources: dict[str, object]) -> dict[str, Path]:
        paths = {
            "provider_receipt": tmp / "policy-backend-provider-export.json",
            "provider_export": tmp / "policy-backend-provider-export-source.json",
            "worker_receipt": tmp / "policy-backend-worker.json",
            "service_attestation": tmp / "policy-backend-service-attestation.json",
            "enforcement": tmp / "policy-backend-enforcement.json",
            "policy_pack": tmp / "policy-pack.json",
            "runtime_action": tmp / "runtime-action.json",
            "proof_pack": tmp / "pack.json",
            "policy_decision": tmp / "policy-decision.json",
            "policy_export": tmp / "policy-export.json",
            "policy_engine_receipt": tmp / "policy-engine-receipt.json",
        }
        values = {
            "provider_receipt": sources["provider_receipt"],
            "provider_export": sources["provider_export"],
            "worker_receipt": sources["worker_receipt"],
            "service_attestation": sources["attestation"],
            "enforcement": sources["enforcement"],
            "policy_pack": sources["policy"],
            "runtime_action": sources["action"],
            "proof_pack": sources["pack"],
            "policy_decision": sources["policy_decision"],
            "policy_export": sources["policy_export"],
            "policy_engine_receipt": sources["engine_receipt"],
        }
        for name, value in values.items():
            _write_json(paths[name], value)
        return paths

    def _bundle(self, tmp: Path):
        sources = self._sources(tmp)
        paths = self._write_sources(tmp, sources)
        bundle = build_policy_backend_provider_bundle(
            sources["provider_receipt"],
            sources["provider_export"],
            sources["worker_receipt"],
            sources["attestation"],
            sources["enforcement"],
            sources["policy"],
            sources["action"],
            sources["pack"],
            sources["policy_decision"],
            sources["policy_export"],
            policy_engine_receipt=sources["engine_receipt"],
            artifact_paths=paths,
            environment="aitrade-prod",
            reviewer_ref="oidc:auditor.example/policy-backend-provider-reviewer",
            generated_at="2026-07-04T05:10:00Z",
        )
        return sources, bundle, paths

    def test_policy_backend_provider_bundle_verifies_appends_and_extracts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources, bundle, _ = self._bundle(tmp)

            result = verify_policy_backend_provider_bundle(bundle)
            entry = append_policy_backend_provider_bundle(sources["chain"], bundle)
            out_dir = tmp / "extracted"
            extracted = extract_policy_backend_provider_bundle_sources(bundle, out_dir)
            markdown_path = tmp / "bundle.md"
            write_policy_backend_provider_bundle_markdown(markdown_path, bundle)

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(POLICY_BACKEND_PROVIDER_BUNDLE_SCHEMA, bundle["schema"])
            self.assertEqual("offline-review", bundle["mode"])
            self.assertEqual(11, bundle["summary"]["source_artifact_count"])
            self.assertTrue(bundle["summary"]["policy_engine_receipt_replayed"])
            self.assertEqual(POLICY_BACKEND_PROVIDER_BUNDLE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(bundle["bundle_id"], entry["payload"]["bundle_id"])
            self.assertEqual(11, len(extracted))
            self.assertTrue((out_dir / "provider_receipt.json").exists())
            self.assertIn("TrustAI Policy Backend Provider Export Bundle", markdown_path.read_text(encoding="utf-8"))
            self.assertTrue(sources["chain"].verify_all().ok)

    def test_policy_backend_provider_bundle_rejects_artifact_source_swap(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            paths = self._write_sources(tmp, sources)
            tampered_export = copy.deepcopy(sources["provider_export"])
            tampered_export["backend_records"][0]["response_hash"] = "sha256:other-policy-backend-response"
            _write_json(paths["provider_export"], tampered_export)

            with self.assertRaisesRegex(ValueError, "artifact content hash mismatch: provider_export"):
                build_policy_backend_provider_bundle(
                    sources["provider_receipt"],
                    sources["provider_export"],
                    sources["worker_receipt"],
                    sources["attestation"],
                    sources["enforcement"],
                    sources["policy"],
                    sources["action"],
                    sources["pack"],
                    sources["policy_decision"],
                    sources["policy_export"],
                    policy_engine_receipt=sources["engine_receipt"],
                    artifact_paths=paths,
                    reviewer_ref="oidc:auditor.example/policy-backend-provider-reviewer",
                )

    def test_policy_backend_provider_bundle_rejects_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, bundle, _ = self._bundle(tmp)
            tampered = copy.deepcopy(bundle)
            tampered["sources"]["provider_receipt"]["credential"] = "raw-token"

            result = verify_policy_backend_provider_bundle(tampered)

            self.assertFalse(result.ok)
            self.assertTrue(any("secret-like field" in error for error in result.errors), result.errors)

    def test_cli_policy_backend_provider_bundle_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            sources = self._sources(tmp)
            paths = self._write_sources(tmp, sources)
            bundle_path = tmp / "policy-backend-provider-export-bundle.json"
            markdown_path = tmp / "policy-backend-provider-export-bundle.md"
            rendered_path = tmp / "rendered.md"
            extracted_dir = tmp / "sources"
            entry_path = tmp / "policy-backend-provider-export-bundle-entry.json"
            state_path = tmp / "policy-backend-provider-export-bundle-chain.json"

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            common = [
                str(paths["provider_receipt"]),
                str(paths["provider_export"]),
                str(paths["worker_receipt"]),
                str(paths["service_attestation"]),
                str(paths["enforcement"]),
                str(paths["policy_pack"]),
                str(paths["runtime_action"]),
                "--pack",
                str(paths["proof_pack"]),
                "--decision",
                str(paths["policy_decision"]),
                "--export",
                str(paths["policy_export"]),
                "--policy-engine-receipt",
                str(paths["policy_engine_receipt"]),
            ]

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-provider-export-bundle",
                    *common,
                    "--environment",
                    "aitrade-prod",
                    "--reviewer-ref",
                    "oidc:auditor.example/policy-backend-provider-reviewer",
                    "--generated-at",
                    "2026-07-04T05:10:00Z",
                    "--out",
                    str(bundle_path),
                    "--markdown",
                    str(markdown_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run([sys.executable, "-m", "trustai", "policy-backend-provider-export-bundle-verify", str(bundle_path)], cwd=ROOT, env=env, check=True)
            subprocess.run([sys.executable, "-m", "trustai", "policy-backend-provider-export-bundle-render", str(bundle_path), "--out", str(rendered_path)], cwd=ROOT, env=env, check=True)
            subprocess.run([sys.executable, "-m", "trustai", "policy-backend-provider-export-bundle-extract", str(bundle_path), "--out-dir", str(extracted_dir)], cwd=ROOT, env=env, check=True)
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "policy-backend-provider-export-bundle-append",
                    str(bundle_path),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "policy-backend-provider-bundle-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(bundle_path.exists())
            self.assertTrue(markdown_path.exists())
            self.assertTrue(rendered_path.exists())
            self.assertTrue((extracted_dir / "provider_receipt.json").exists())
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
