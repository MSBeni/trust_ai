import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DemoCliTests(unittest.TestCase):
    def test_demo_no_clean_preserves_existing_state_directory(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_dir = tmp / ".trustai" / "demo"
            state_dir.mkdir(parents=True)
            sentinel = state_dir / "sentinel.txt"
            sentinel.write_text("preserve me", encoding="utf-8")
            state_path = state_dir / "evidence-chain.json"
            proof_path = tmp / "artifacts" / "proof-pack.json"
            pdf_path = tmp / "artifacts" / "proof-pack.pdf"
            runner_path = tmp / "artifacts" / "reexecution-runner-evidence.json"
            report_path = tmp / "artifacts" / "reexecution-report.json"
            markdown_path = tmp / "artifacts" / "reexecution-report.md"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "demo",
                    "--no-clean",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "self-serve-demo-test",
                    "--out",
                    str(proof_path),
                    "--pdf",
                    str(pdf_path),
                    "--reexecution-runner-out",
                    str(runner_path),
                    "--reexecution-out",
                    str(report_path),
                    "--reexecution-markdown",
                    str(markdown_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(0, generated.returncode, generated.stderr)
            self.assertTrue(sentinel.exists())
            self.assertTrue(state_path.exists())
            self.assertTrue(proof_path.exists())
            self.assertTrue(pdf_path.exists())
            verified = subprocess.run(
                [sys.executable, "-m", "trustai", "verify", str(proof_path)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            proof = json.loads(proof_path.read_text(encoding="utf-8-sig"))
            self.assertEqual("self-serve-demo-test", proof["chain"]["tenant_id"])