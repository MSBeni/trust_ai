import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_CI = ROOT / ".github" / "workflows" / "python-ci.yml"
GO_CI = ROOT / ".github" / "workflows" / "go-verifier.yml"


class RepositoryCiTests(unittest.TestCase):
    def test_python_ci_bootstraps_artifacts_before_smoke_tests(self):
        workflow = PYTHON_CI.read_text(encoding="utf-8")

        self.assertIn("actions/setup-python@v5", workflow)
        self.assertIn("python-version: \"3.12\"", workflow)
        self.assertIn("python -m pip install -e .", workflow)
        self.assertIn("python -m compileall -q src tests", workflow)
        self.assertIn("python -m trustai demo", workflow)
        self.assertIn("python -m trustai verify artifacts/aitrade-proof-pack.json", workflow)
        self.assertIn("tests.test_go_verifier_release_workflow", workflow)
        self.assertIn("tests.test_repository_ci", workflow)
        self.assertIn("tests.test_standards", workflow)

    def test_public_repo_has_python_and_go_ci_workflows(self):
        self.assertTrue(PYTHON_CI.exists())
        self.assertTrue(GO_CI.exists())


if __name__ == "__main__":
    unittest.main()
