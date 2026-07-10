import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.vertical_pack import (
    SUPPORTED_VERTICAL_PACKS,
    VERTICAL_PACK_ENTRY_TYPE,
    VERTICAL_PACK_SCHEMA,
    append_vertical_pack,
    build_vertical_pack,
    verify_vertical_pack,
)


ROOT = Path(__file__).resolve().parents[1]


class VerticalPackTests(unittest.TestCase):
    def test_healthcare_pack_binds_sources_and_appends(self):
        pack = build_vertical_pack(
            ROOT,
            pack_ref="vertical-pack:healthcare-rcm/local",
            vertical="healthcare-rcm",
            producer_ref="oidc:trustai.example/vertical-pack-author",
            reviewer_ref="oidc:auditor.example/vertical-pack-reviewer",
            generated_at="2026-07-17T00:00:00Z",
        )
        result = verify_vertical_pack(pack, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="vertical-pack-test")
            entry = append_vertical_pack(chain, pack, root=ROOT)

            self.assertTrue(chain.verify_all().ok)

        self.assertTrue(result.ok, result.errors)
        self.assertIn("external requirements", result.warnings[0])
        self.assertEqual(VERTICAL_PACK_SCHEMA, pack["schema"])
        self.assertEqual("healthcare-rcm", pack["vertical"])
        self.assertEqual({"external-required": 1, "passed": 7}, entry["payload"]["control_summary"])
        self.assertEqual(2, entry["payload"]["external_requirement_count"])
        self.assertEqual(VERTICAL_PACK_ENTRY_TYPE, entry["entry_type"])

    def test_every_supported_vertical_verifies(self):
        for vertical in sorted(SUPPORTED_VERTICAL_PACKS):
            with self.subTest(vertical=vertical):
                pack = build_vertical_pack(
                    ROOT,
                    pack_ref=f"vertical-pack:{vertical}/local",
                    vertical=vertical,
                    producer_ref="oidc:trustai.example/vertical-pack-author",
                )
                result = verify_vertical_pack(pack, root=ROOT)

                self.assertTrue(result.ok, result.errors)
                self.assertGreaterEqual(len(pack["source_artifacts"]), 16)
                self.assertIn("production-claim-limited", {control["id"] for control in pack["controls"]})

    def test_pack_detects_source_artifact_tamper(self):
        pack = build_vertical_pack(
            ROOT,
            pack_ref="vertical-pack:insurance-claims/local",
            vertical="insurance-claims",
            producer_ref="oidc:trustai.example/vertical-pack-author",
        )
        tampered = copy.deepcopy(pack)
        tampered["source_artifacts"][0]["sha256"] = "sha256:tampered"

        result = verify_vertical_pack(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("pack_id does not match canonical vertical pack body", result.errors)
        self.assertTrue(any("source artifact hash mismatch" in error for error in result.errors), result.errors)

    def test_unsupported_vertical_rejected(self):
        with self.assertRaisesRegex(ValueError, "vertical must be one of"):
            build_vertical_pack(
                ROOT,
                pack_ref="vertical-pack:unsupported/local",
                vertical="unsupported",
                producer_ref="oidc:trustai.example/vertical-pack-author",
            )

    def test_cli_vertical_pack_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pack_path = tmp / "public-sector-vertical-pack.json"
            entry_path = tmp / "public-sector-vertical-pack-entry.json"
            state_path = tmp / "chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "vertical-pack",
                    "--root",
                    str(ROOT),
                    "--pack-ref",
                    "vertical-pack:public-sector/local",
                    "--vertical",
                    "public-sector",
                    "--producer-ref",
                    "oidc:trustai.example/vertical-pack-author",
                    "--reviewer-ref",
                    "oidc:auditor.example/vertical-pack-reviewer",
                    "--generated-at",
                    "2026-07-17T00:00:00Z",
                    "--out",
                    str(pack_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [sys.executable, "-m", "trustai", "vertical-pack-verify", str(pack_path), "--root", str(ROOT)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)

            appended = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "vertical-pack-append",
                    str(pack_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "vertical-pack-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(VERTICAL_PACK_SCHEMA, json.loads(pack_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
