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
    build_framework_adapter_matrix,
    load_framework_adapter_matrix_source,
    write_framework_adapter_matrix,
)
from trustai.framework_hook_release import (
    FRAMEWORK_HOOK_RELEASE_ENTRY_TYPE,
    FRAMEWORK_HOOK_RELEASE_SCHEMA,
    append_framework_hook_release,
    build_framework_hook_release,
    load_framework_hook_release_source,
    verify_framework_hook_release,
)
from trustai.framework_hooks import capture_framework_trace


ROOT = Path(__file__).resolve().parents[1]
MATRIX_SOURCE = ROOT / "examples" / "aitrade" / "framework-adapter-matrix.json"
HOOK_SOURCE = ROOT / "examples" / "aitrade" / "framework-hook-release.json"
TRACE_FIXTURE = ROOT / "examples" / "aitrade" / "framework-traces.json"


class FrameworkHookReleaseTests(unittest.TestCase):
    def _matrix(self) -> dict:
        return build_framework_adapter_matrix(
            load_framework_adapter_matrix_source(MATRIX_SOURCE),
            root=ROOT,
            issued_at="2026-07-09T00:00:00Z",
        )

    def _release(self) -> tuple[dict, dict]:
        matrix = self._matrix()
        release = build_framework_hook_release(
            load_framework_hook_release_source(HOOK_SOURCE),
            matrix,
            root=ROOT,
            released_at="2026-07-09T00:30:00Z",
        )
        return release, matrix

    def test_framework_hook_release_verifies_and_appends(self):
        release, matrix = self._release()
        result = verify_framework_hook_release(release, matrix, root=ROOT)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="framework-hook-test")
            entry = append_framework_hook_release(chain, release, matrix, root=ROOT)

            self.assertTrue(result.ok, result.errors)
            self.assertTrue(result.warnings)
            self.assertEqual(FRAMEWORK_HOOK_RELEASE_SCHEMA, release["schema"])
            self.assertEqual(6, release["summary"]["row_count"])
            self.assertEqual(6, release["summary"]["framework_count"])
            self.assertTrue(all(row["trace_fixture"]["event_chain_verified"] for row in release["entries"]))
            self.assertTrue(all(row["trace_fixture"]["trace_roots"] for row in release["entries"]))
            self.assertEqual(FRAMEWORK_HOOK_RELEASE_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(release["release_id"], entry["payload"]["release_id"])
            self.assertEqual(6, len(entry["payload"]["hook_release_hashes"]))
            self.assertTrue(chain.verify_all().ok)

    def test_framework_hook_release_rejects_source_artifact_tamper(self):
        release, matrix = self._release()
        tampered = copy.deepcopy(release)
        tampered["entries"][0]["source_artifacts"][0]["sha256"] = "sha256:tampered"

        result = verify_framework_hook_release(tampered, matrix, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("release_id" in error for error in result.errors))
        self.assertTrue(any("source_artifact" in error and "sha256" in error for error in result.errors))

    def test_framework_hook_release_rejects_matrix_mismatch(self):
        release, matrix = self._release()
        tampered = copy.deepcopy(release)
        tampered["entries"][0]["adapter_matrix_binding"]["compatibility_hash"] = "wrong"

        result = verify_framework_hook_release(tampered, matrix, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("compatibility_hash" in error for error in result.errors))

    def test_reference_hook_entrypoint_emits_chained_adapter_events(self):
        payload = json.loads(TRACE_FIXTURE.read_text(encoding="utf-8"))["traces"][0]
        events = capture_framework_trace(payload)

        self.assertTrue(events)
        self.assertTrue(all("trustai.adapter.event_node_hash" in event["attributes"] for event in events))
        self.assertEqual(
            events[-1]["attributes"]["trustai.adapter.event_node_hash"],
            events[-1]["attributes"]["trustai.adapter.trace_root"],
        )

    def test_cli_framework_hook_release_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            matrix_path = tmp / "framework-adapter-matrix.json"
            release_path = tmp / "framework-hook-release.json"
            entry_path = tmp / "framework-hook-release-entry.json"
            state_path = tmp / "evidence-chain.json"
            matrix = self._matrix()
            write_framework_adapter_matrix(matrix_path, matrix)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            base = [sys.executable, "-m", "trustai"]

            subprocess.run(
                base
                + [
                    "framework-hook-release",
                    str(HOOK_SOURCE),
                    str(matrix_path),
                    "--root",
                    str(ROOT),
                    "--released-at",
                    "2026-07-09T00:30:00Z",
                    "--out",
                    str(release_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                base
                + [
                    "framework-hook-release-verify",
                    str(release_path),
                    "--matrix",
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
                base
                + [
                    "framework-hook-release-append",
                    str(release_path),
                    "--matrix",
                    str(matrix_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "framework-hook-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            release = json.loads(release_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        result = verify_framework_hook_release(release, matrix, root=ROOT)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(release["release_id"], entry["payload"]["release_id"])


if __name__ == "__main__":
    unittest.main()