import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_CI = ROOT / ".github" / "workflows" / "python-ci.yml"
GO_CI = ROOT / ".github" / "workflows" / "go-verifier.yml"
TESTS_INIT = ROOT / "tests" / "__init__.py"


class RepositoryCiTests(unittest.TestCase):
    def test_python_ci_bootstraps_artifacts_before_smoke_tests(self):
        workflow = PYTHON_CI.read_text(encoding="utf-8")

        self.assertIn("actions/setup-python@v5", workflow)
        self.assertIn("python-version: \"3.12\"", workflow)
        self.assertIn("python -m pip install -e .", workflow)
        self.assertIn("python -m compileall -q src tests", workflow)
        self.assertIn("python -m trustai demo", workflow)
        self.assertIn("python -m trustai verify artifacts/aitrade-proof-pack.json", workflow)
        self.assertIn("python -m trustai roadmap-audit --out artifacts/roadmap-audit.json --markdown artifacts/roadmap-audit.md", workflow)
        self.assertIn("python -m trustai roadmap-audit-verify artifacts/roadmap-audit.json", workflow)
        self.assertIn("python -m trustai roadmap-audit-append artifacts/roadmap-audit.json", workflow)
        self.assertIn("python -m trustai chain-verify --state .trustai/roadmap-audit-ci/evidence-chain.json", workflow)
        self.assertIn("python -m trustai external-evidence-manifest artifacts/roadmap-audit.json", workflow)
        self.assertIn("python -m trustai external-evidence-plan artifacts/external-evidence-manifest.json artifacts/roadmap-audit.json", workflow)
        self.assertIn("python -m trustai external-evidence-plan-verify artifacts/external-evidence-plan.json artifacts/external-evidence-manifest.json artifacts/roadmap-audit.json", workflow)
        self.assertIn("python -m trustai external-evidence-plan artifacts/external-evidence-manifest.json artifacts/roadmap-audit.json --status-filter all", workflow)
        self.assertIn("python -m trustai external-evidence-collect artifacts/external-evidence-plan-all.json artifacts/external-evidence-manifest.json artifacts/roadmap-audit.json", workflow)
        self.assertIn("--snapshot-out artifacts/external-evidence-source-snapshot.json", workflow)
        self.assertIn("--intake-out artifacts/external-evidence-intake.json", workflow)
        self.assertIn("python -m trustai external-evidence-snapshot-verify artifacts/external-evidence-source-snapshot.json", workflow)
        self.assertIn("python -m trustai external-evidence-intake-verify artifacts/external-evidence-intake.json artifacts/external-evidence-plan-all.json artifacts/external-evidence-manifest.json artifacts/roadmap-audit.json", workflow)
        self.assertIn("python -m trustai external-evidence-intake artifacts/external-evidence-plan-all.json artifacts/external-evidence-manifest.json artifacts/roadmap-audit.json --root . --task oss-verifier-and-public-spec:provider-api", workflow)
        self.assertIn("--artifact examples/aitrade/external-evidence/github-main-ref-source-snapshot.json", workflow)
        self.assertIn("--out artifacts/external-evidence-provider-api-intake.json", workflow)
        self.assertIn("python -m trustai external-evidence-intake-verify artifacts/external-evidence-provider-api-intake.json artifacts/external-evidence-plan-all.json artifacts/external-evidence-manifest.json artifacts/roadmap-audit.json --root .", workflow)
        self.assertIn("--task oss-verifier-and-public-spec:hosted-service", workflow)
        self.assertIn("--artifact examples/aitrade/external-evidence/github-hosted-service-source-snapshot.json", workflow)
        self.assertIn("--out artifacts/external-evidence-hosted-service-intake.json", workflow)
        self.assertIn("oss-verifier-provider-api.json", workflow)
        self.assertIn("oss-verifier-hosted-service.json", workflow)
        self.assertIn("covered_authority_kind_count", workflow)
        self.assertIn("missing_authority_kind_count", workflow)
        self.assertIn("python -m trustai external-evidence-manifest-from-intakes artifacts/external-evidence-plan-all.json artifacts/external-evidence-manifest.json artifacts/roadmap-audit.json", workflow)
        self.assertIn("--intake-dir artifacts/external-evidence-intakes", workflow)
        self.assertIn("python -m trustai external-evidence-source-map-verify examples/aitrade/external-evidence/remaining-external-evidence-source-map-template.json examples/aitrade/external-evidence/remaining-external-evidence-plan.json", workflow)
        self.assertIn("python -m trustai external-evidence-gap-report-verify examples/aitrade/external-evidence/retained-external-evidence-gap-report.json", workflow)
        self.assertIn("python -m trustai external-evidence-verify examples/aitrade/external-evidence/retained-external-evidence-manifest.json", workflow)
        self.assertIn("python -m trustai external-evidence-plan-verify examples/aitrade/external-evidence/remaining-external-evidence-plan.json", workflow)
        self.assertIn("remaining_task_count", workflow)
        self.assertIn("source_map_entry_count", workflow)
        self.assertIn("placeholder_source_uri_count", workflow)
        self.assertIn("live_source_uri_count", workflow)
        self.assertIn("require_live_source_uris", workflow)
        self.assertIn("python -m trustai external-evidence-append artifacts/external-evidence-manifest-from-intakes.json", workflow)
        self.assertIn("--require-fresh --now 2026-07-12T00:00:00Z", workflow)
        self.assertIn("python -m trustai roadmap-evidence-verify --state .trustai/roadmap-audit-ci/evidence-chain.json", workflow)
        self.assertIn("--require-external --require-fresh", workflow)
        self.assertIn("python -m trustai roadmap-evidence-report --state .trustai/roadmap-audit-ci/evidence-chain.json", workflow)
        self.assertIn("python -m trustai roadmap-evidence-report-verify artifacts/roadmap-evidence-report.json", workflow)
        self.assertIn("python -m trustai roadmap-evidence-bundle --state .trustai/roadmap-audit-ci/evidence-chain.json", workflow)
        self.assertIn("--source-artifact \"roadmap-audit,artifacts/roadmap-audit.json,Generated roadmap audit JSON\"", workflow)
        self.assertIn("--include-manifest-evidence", workflow)
        self.assertIn("--require-source-artifacts", workflow)
        self.assertIn("python -m trustai roadmap-evidence-bundle-verify artifacts/roadmap-evidence-bundle.json", workflow)
        self.assertIn("python -m trustai roadmap-evidence-bundle-extract artifacts/roadmap-evidence-bundle.json", workflow)
        self.assertIn("python -m unittest discover -v -p test_repository_ci.py", workflow)
        self.assertIn("tests.test_go_verifier_release_workflow", workflow)
        self.assertIn("tests.test_repository_ci", workflow)
        self.assertIn("tests.test_roadmap_audit", workflow)
        self.assertIn("tests.test_external_evidence", workflow)
        self.assertIn("tests.test_tamper_stress", workflow)
        self.assertIn("tests.test_standards", workflow)

    def test_public_repo_has_python_and_go_ci_workflows(self):
        self.assertTrue(PYTHON_CI.exists())
        self.assertTrue(GO_CI.exists())
        self.assertTrue(TESTS_INIT.exists())


if __name__ == "__main__":
    unittest.main()
