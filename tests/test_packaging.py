import json
import os
import subprocess
import tempfile
import unittest
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _venv_command(venv_dir: Path, command: str) -> Path:
    scripts_dir = "Scripts" if os.name == "nt" else "bin"
    suffix = ".exe" if os.name == "nt" else ""
    return venv_dir / scripts_dir / f"{command}{suffix}"


class PackagingSmokeTests(unittest.TestCase):
    def _run(self, args: list[str], *, cwd: Path, timeout: int = 240) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        completed = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        if completed.returncode != 0:
            joined = " ".join(args)
            self.fail(
                f"command failed ({completed.returncode}): {joined}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            )
        return completed

    def test_non_editable_install_exposes_console_and_module_cli(self):
        with tempfile.TemporaryDirectory(prefix="trustai-packaging-") as tmp:
            tmp_path = Path(tmp)
            venv_dir = tmp_path / "venv"
            venv.EnvBuilder(with_pip=True).create(venv_dir)

            python = _venv_command(venv_dir, "python")
            trustai = _venv_command(venv_dir, "trustai")

            self._run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--no-deps",
                    str(ROOT),
                ],
                cwd=ROOT,
            )

            origin = self._run(
                [
                    str(python),
                    "-c",
                    "import json, trustai; print(json.dumps({'file': trustai.__file__}))",
                ],
                cwd=tmp_path,
            )
            installed_file = Path(json.loads(origin.stdout)["file"]).resolve()
            self.assertIn(str(venv_dir.resolve()).lower(), str(installed_file).lower())

            help_result = self._run([str(trustai), "--help"], cwd=tmp_path)
            self.assertIn("TrustAI proof-pack CLI", help_result.stdout)
            self.assertIn("roadmap-audit", help_result.stdout)

            audit_path = tmp_path / "roadmap-audit.json"
            markdown_path = tmp_path / "roadmap-audit.md"
            self._run(
                [
                    str(python),
                    "-m",
                    "trustai",
                    "roadmap-audit",
                    "--root",
                    str(ROOT),
                    "--out",
                    str(audit_path),
                    "--markdown",
                    str(markdown_path),
                ],
                cwd=tmp_path,
            )

            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            self.assertEqual(26, audit["summary"]["requirement_count"])
            self.assertEqual(0, audit["summary"]["missing-local-evidence"])
            self.assertGreater(audit["summary"]["implemented-local"], 0)
            self.assertTrue(markdown_path.exists())


if __name__ == "__main__":
    unittest.main()