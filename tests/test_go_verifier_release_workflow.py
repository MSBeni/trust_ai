import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "go-verifier.yml"
SPEC = ROOT / "docs" / "specs" / "go-verifier-release-workflow-v0.1.md"
README = ROOT / "verifier" / "go" / "trustai-verify" / "README.md"


class GoVerifierReleaseWorkflowTests(unittest.TestCase):
    def test_workflow_builds_static_verifier_artifacts(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("actions/setup-go@v5", workflow)
        self.assertIn("go test ./...", workflow)
        self.assertIn('CGO_ENABLED: "0"', workflow)
        self.assertIn("go build -trimpath -ldflags \"-s -w\"", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)
        self.assertIn("actions/attest-build-provenance@v2", workflow)
        self.assertIn("sha256sum", workflow)
        self.assertIn("trustai.go-verifier-ci-sbom/0.1", workflow)
        self.assertIn("trustai.go-verifier-ci-provenance/0.1", workflow)
        for target in (
            "goos: linux\n            goarch: amd64",
            "goos: linux\n            goarch: arm64",
            "goos: darwin\n            goarch: amd64",
            "goos: darwin\n            goarch: arm64",
            "goos: windows\n            goarch: amd64",
        ):
            self.assertIn(target, workflow)

    def test_workflow_spec_documents_release_controls(self):
        spec = SPEC.read_text(encoding="utf-8")

        for required in (
            ".github/workflows/go-verifier.yml",
            "CGO_ENABLED=0",
            'go build -trimpath -ldflags "-s -w"',
            "SHA-256 checksum",
            "SBOM JSON",
            "provenance JSON",
            "binary-attested",
        ):
            self.assertIn(required, spec)

    def test_go_verifier_readme_points_to_ci_release_workflow(self):
        readme = README.read_text(encoding="utf-8")

        self.assertIn(".github/workflows/go-verifier.yml", readme)
        self.assertIn("go test .", readme)
        self.assertIn("go build -trimpath", readme)
        self.assertIn("artifacts/trustai-verify-go.exe artifacts/aitrade-proof-pack.json", readme)


if __name__ == "__main__":
    unittest.main()
