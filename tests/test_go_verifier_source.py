import re
import shutil
import subprocess
import unittest
from pathlib import Path

from trustai.verifier import load_proof_pack, verify_proof_pack
from trustai.verifier_release import build_verifier_release_manifest


ROOT = Path(__file__).resolve().parents[1]
GO_VERIFIER_DIR = ROOT / "verifier" / "go" / "trustai-verify"
MAIN_GO = GO_VERIFIER_DIR / "main.go"
README = GO_VERIFIER_DIR / "README.md"
GO_MOD = GO_VERIFIER_DIR / "go.mod"


class GoVerifierSourceTests(unittest.TestCase):
    def test_go_verifier_source_is_present_and_dependency_free(self):
        source = MAIN_GO.read_text(encoding="utf-8")
        go_mod = GO_MOD.read_text(encoding="utf-8")

        self.assertIn("module trustai.dev/verifier/trustai-verify", go_mod)
        import_block = re.search(r"import\s*\((.*?)\)", source, re.S)
        self.assertIsNotNone(import_block)
        imports = re.findall(r'"([^"]+)"', import_block.group(1))
        self.assertTrue(imports)
        allowed = {
            "bytes",
            "crypto/hmac",
            "crypto/sha256",
            "encoding/hex",
            "encoding/json",
            "flag",
            "fmt",
            "io",
            "os",
            "sort",
            "strconv",
            "strings",
            "time",
        }
        for imported in imports:
            self.assertIn(imported, allowed)

    def test_go_verifier_mirrors_required_offline_checks(self):
        source = MAIN_GO.read_text(encoding="utf-8")
        required_markers = [
            "proofPackSpecVersion",
            "canonicalBytes",
            "verifyValue",
            "verifyTimestampToken",
            "verifyInclusion",
            "evaluateContract",
            "evaluateHoldout",
            "evaluateApprovals",
            "pack_id does not match canonical pack body",
            "proof pack signature invalid",
            "chain ordering must be contract registration < eval < gate",
            "eval results hash mismatch",
            "gate decision mismatch for",
            "packed gate decision mismatch for",
        ]
        for marker in required_markers:
            self.assertIn(marker, source)

    def test_go_verifier_docs_include_static_build_and_reference_command(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("go build -trimpath", readme)
        self.assertIn("artifacts/trustai-verify-go.exe artifacts/aitrade-proof-pack.json", readme)
        self.assertIn("does not include `go` on PATH", readme)

    def test_python_reference_pack_still_verifies(self):
        pack = load_proof_pack(ROOT / "artifacts" / "aitrade-proof-pack.json")
        result = verify_proof_pack(pack)
        self.assertTrue(result.ok, result.errors)

    def test_release_manifest_binds_go_verifier_source(self):
        manifest = build_verifier_release_manifest(ROOT)
        source_paths = {source["path"] for source in manifest["source_files"]}
        target_ids = {target["id"] for target in manifest["targets"]}

        self.assertIn("verifier/go/trustai-verify/main.go", source_paths)
        self.assertIn("verifier/go/trustai-verify/go.mod", source_paths)
        self.assertIn("verifier/go/trustai-verify/README.md", source_paths)
        self.assertIn("go-offline-verifier-source", target_ids)

    @unittest.skipUnless(shutil.which("go"), "Go toolchain is not installed in this workspace")
    def test_go_verifier_builds_when_toolchain_is_available(self):
        subprocess.run(["go", "test", "."], cwd=GO_VERIFIER_DIR, check=True)


if __name__ == "__main__":
    unittest.main()
