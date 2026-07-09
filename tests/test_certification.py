import copy
import tempfile
import unittest
from pathlib import Path

from trustai.certification import (
    AUDITOR_CERTIFICATION_SCHEMA,
    REQUIRED_MODULE_IDS,
    build_auditor_certification_kit,
    render_auditor_certification_markdown,
    verify_auditor_certification_kit,
)
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.regulator import build_regulator_disclosure
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.standards import build_standards_submission


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


class AuditorCertificationTests(unittest.TestCase):
    def _source_artifacts(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        append_runtime_attestation(chain, contract, load_action(ACTION))
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")
        disclosure = build_regulator_disclosure(chain, pack, audience="auditor@example.test")
        standards = build_standards_submission(ROOT)
        return pack, disclosure, standards

    def test_auditor_certification_kit_deep_verifies_source_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards = self._source_artifacts(Path(tmp_dir))
            kit = build_auditor_certification_kit(
                pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
            )

            result = verify_auditor_certification_kit(
                kit,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )
            markdown = render_auditor_certification_markdown(kit)

            self.assertEqual(AUDITOR_CERTIFICATION_SCHEMA, kit["schema"])
            self.assertTrue(result["ok"], result["errors"])
            self.assertEqual(set(REQUIRED_MODULE_IDS), {module["id"] for module in kit["training_modules"]})
            self.assertIn("regulator_disclosure", kit["source_artifacts"])
            self.assertIn("standards_submission", kit["source_artifacts"])
            self.assertIn("TrustAI Auditor Certification Kit", markdown)

    def test_auditor_certification_kit_detects_source_hash_tamper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards = self._source_artifacts(Path(tmp_dir))
            kit = build_auditor_certification_kit(
                pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
            )
            tampered = copy.deepcopy(kit)
            tampered["source_artifacts"]["proof_pack"]["content_hash"] = "changed"

            result = verify_auditor_certification_kit(
                tampered,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )

            self.assertFalse(result["ok"])
            self.assertTrue(any("kit_id" in error for error in result["errors"]))
            self.assertTrue(any("proof pack source hash mismatch" in error for error in result["errors"]))

    def test_auditor_certification_kit_requires_training_modules(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack, disclosure, standards = self._source_artifacts(Path(tmp_dir))
            kit = build_auditor_certification_kit(
                pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
            )
            tampered = copy.deepcopy(kit)
            tampered["training_modules"] = [
                module for module in tampered["training_modules"] if module["id"] != "evidence-chain-forensics"
            ]

            result = verify_auditor_certification_kit(
                tampered,
                proof_pack=pack,
                regulator_disclosure=disclosure,
                standards_package=standards,
                root=ROOT,
            )

            self.assertFalse(result["ok"])
            self.assertTrue(any("required training modules missing" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
