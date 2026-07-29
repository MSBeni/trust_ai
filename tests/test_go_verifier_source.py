import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.verifier import verify_proof_pack
from trustai.verifier_release import build_verifier_release_manifest


ROOT = Path(__file__).resolve().parents[1]
GO_VERIFIER_DIR = ROOT / "verifier" / "go" / "trustai-verify"
MAIN_GO = GO_VERIFIER_DIR / "main.go"
README = GO_VERIFIER_DIR / "README.md"
GO_MOD = GO_VERIFIER_DIR / "go.mod"
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
RESULTS = ROOT / "examples" / "aitrade" / "eval-results.json"


class GoVerifierSourceTests(unittest.TestCase):
    def _fresh_reference_pack(self, tmp: Path) -> dict:
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="go-verifier-source-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        eval_entry, gate_entry, decision = append_eval_and_gate(chain, contract, results)
        return compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

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
            "encoding/base64",
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
            "roadmapEvidenceBundleSchema",
            "verifyRoadmapEvidenceBundle",
            "--require-source-artifacts",
            "bundle_id does not match canonical bundle body",
            "bundle source_artifacts must be a list",
            "external evidence collection run artifact is not committed to bundled chain",
            "external evidence source snapshot referenced by embedded collection run is not embedded",
            "source audit proof inclusion failed",
            "canonicalBytes",
            "verifyValue",
            "verifyTimestampToken",
            "verifyInclusion",
            "verifyPackedChainTree",
            "merkleRoot",
            " tree root does not match packed entries",
            " tree size is smaller than packed entry indexes",
            "evaluateContract",
            "evaluateHoldout",
            "evaluateApprovals",
            "defaultFrameworkMappings",
            "pack_id does not match canonical pack body",
            "proof pack signature invalid",
            "proof pack issued_at missing",
            "proof pack issued_at invalid",
            "chain ordering must be contract registration < eval < gate",
            "packed contract chain_entry_id mismatch",
            "packed eval chain_entry_id mismatch",
            "packed eval results_hash mismatch",
            "eval results hash mismatch",
            "gate decision mismatch for",
            "gate decision agent mismatch",
            "packed gate decision mismatch for",
            "packed subject agent mismatch",
            "packed subject environment mismatch",
            "runtime attestation entry",
            "evaluateRuntimeAction",
            "framework_mappings must be a list",
            "framework mappings do not match gate decision",
        ]
        for marker in required_markers:
            self.assertIn(marker, source)

    def test_go_verifier_docs_include_static_build_and_reference_command(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("go build -trimpath", readme)
        self.assertIn("artifacts/trustai-verify-go.exe artifacts/aitrade-proof-pack.json", readme)
        self.assertIn("artifacts/trustai-verify-go.exe --require-source-artifacts artifacts/retained-collection-run-roadmap-evidence-bundle.json", readme)
        self.assertIn("does not include `go` on PATH", readme)

    def test_fresh_python_reference_pack_still_verifies(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._fresh_reference_pack(Path(tmp_dir))
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
