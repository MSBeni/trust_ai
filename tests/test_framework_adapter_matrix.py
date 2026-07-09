import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.framework_adapter_matrix import (
    FRAMEWORK_ADAPTER_MATRIX_ENTRY_TYPE,
    FRAMEWORK_ADAPTER_MATRIX_SCHEMA,
    append_framework_adapter_matrix,
    build_framework_adapter_matrix,
    load_framework_adapter_matrix_source,
    verify_framework_adapter_matrix,
)


ROOT = Path(__file__).resolve().parents[1]
MATRIX_SOURCE = ROOT / "examples" / "aitrade" / "framework-adapter-matrix.json"


class FrameworkAdapterMatrixTests(unittest.TestCase):
    def _matrix(self) -> dict:
        return build_framework_adapter_matrix(
            load_framework_adapter_matrix_source(MATRIX_SOURCE),
            root=ROOT,
            issued_at="2026-07-09T00:00:00Z",
        )

    def test_framework_adapter_matrix_replays_fixture_events(self):
        matrix = self._matrix()

        result = verify_framework_adapter_matrix(matrix, root=ROOT)
        frameworks = {entry["framework"] for entry in matrix["entries"]}
        fixture_roots = {entry["trace_fixture"]["normalized_event_root"] for entry in matrix["entries"]}

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(FRAMEWORK_ADAPTER_MATRIX_SCHEMA, matrix["schema"])
        self.assertEqual(6, matrix["summary"]["row_count"])
        self.assertEqual(6, matrix["summary"]["framework_count"])
        self.assertEqual(12, matrix["summary"]["total_fixture_events"])
        self.assertEqual(
            {"bedrock", "claude_agent", "crewai", "langgraph", "openai_agents", "vertex"},
            frameworks,
        )
        self.assertEqual(6, len(fixture_roots))
        self.assertTrue(all(entry["compatibility_hash"] for entry in matrix["entries"]))
        self.assertTrue(any("no production-certified" in warning for warning in result.warnings))

    def test_framework_adapter_matrix_appends_to_chain(self):
        matrix = self._matrix()

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-matrix-test")
            entry = append_framework_adapter_matrix(chain, matrix, root=ROOT)

            self.assertEqual(FRAMEWORK_ADAPTER_MATRIX_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(matrix["matrix_id"], entry["payload"]["matrix_id"])
            self.assertEqual(6, entry["payload"]["summary"]["row_count"])
            self.assertEqual(6, len(entry["payload"]["compatibility_hashes"]))
            self.assertTrue(chain.verify_all().ok)

    def test_framework_adapter_matrix_tamper_is_rejected(self):
        matrix = self._matrix()
        tampered = copy.deepcopy(matrix)
        tampered["entries"][0]["runtime"]["version"] = "0.3.x"

        result = verify_framework_adapter_matrix(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("matrix_id" in error or "signature" in error for error in result.errors))
        self.assertTrue(any("entry hash mismatch" in error for error in result.errors))

    def test_framework_adapter_matrix_rejects_missing_required_event(self):
        source = load_framework_adapter_matrix_source(MATRIX_SOURCE)
        source["entries"][0]["required_event_names"].append("gen_ai.agent.nonexistent")

        with self.assertRaisesRegex(ValueError, "missing required events"):
            build_framework_adapter_matrix(source, root=ROOT, issued_at="2026-07-09T00:00:00Z")

    def test_cli_framework_adapter_matrix_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            matrix_path = tmp / "framework-adapter-matrix.json"
            entry_path = tmp / "framework-adapter-matrix-entry.json"
            state_path = tmp / "evidence-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "framework-adapter-matrix",
                    str(MATRIX_SOURCE),
                    "--root",
                    str(ROOT),
                    "--issued-at",
                    "2026-07-09T00:00:00Z",
                    "--out",
                    str(matrix_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "framework-adapter-matrix-verify",
                    str(matrix_path),
                    "--root",
                    str(ROOT),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "framework-adapter-matrix-append",
                    str(matrix_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-matrix-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_adapter_matrix(matrix, root=ROOT)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(matrix["matrix_id"], entry["payload"]["matrix_id"])


if __name__ == "__main__":
    unittest.main()
