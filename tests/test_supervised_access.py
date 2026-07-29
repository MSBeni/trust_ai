import copy
import json
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.crypto import sign_value
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.regulator import build_regulator_disclosure
from trustai.regulator_view import write_regulator_html
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results
from trustai.supervised_access import (
    SUPERVISED_ACCESS_ENTRY_TYPE,
    SUPERVISED_ACCESS_SCHEMA,
    append_supervised_access_receipt,
    build_supervised_access_receipt,
    verify_supervised_access_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


class SupervisedAccessTests(unittest.TestCase):
    def _chain_pack_disclosure_view(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="supervised-test")
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
        pack_path = tmp / "pack.json"
        pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=pack_path)
        disclosure = build_regulator_disclosure(chain, pack, audience="supervisor@example.test")
        disclosure_path = tmp / "disclosure.json"
        disclosure_path.write_text(json.dumps(disclosure, indent=2, sort_keys=True), encoding="utf-8")
        view_path = tmp / "regulator-view.html"
        write_regulator_html(view_path, disclosure)
        return chain, pack, pack_path, disclosure, disclosure_path, view_path

    def _resign_disclosure(self, disclosure: dict) -> None:
        body = without_keys(disclosure, "disclosure_id", "signatures")
        disclosure_id = content_hash(body)
        disclosure["disclosure_id"] = disclosure_id
        disclosure["signatures"] = [sign_value({"disclosure_id": disclosure_id, "disclosure": body})]

    def _resign_receipt(self, receipt: dict) -> None:
        body = without_keys(receipt, "receipt_id", "signatures")
        receipt_id = content_hash(body)
        receipt["receipt_id"] = receipt_id
        receipt["signatures"] = [sign_value({"receipt_id": receipt_id, "receipt": body})]

    def test_supervised_access_receipt_verifies_sources_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain, pack, pack_path, disclosure, disclosure_path, view_path = self._chain_pack_disclosure_view(tmp)
            receipt = build_supervised_access_receipt(
                pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                subject_ref="oidc:regulator.example/supervisor-123",
                organization="Example Supervisor",
                role="regulator_reviewer",
                audience_type="regulator",
                purpose="EU AI Act supervised review",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )
            result = verify_supervised_access_receipt(
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                now="2026-07-09T00:00:00Z",
            )
            entry = append_supervised_access_receipt(chain, receipt)

            self.assertEqual(SUPERVISED_ACCESS_SCHEMA, receipt["schema"])
            self.assertTrue(result.ok, result.errors)
            self.assertEqual("regulator", receipt["audience"]["type"])
            self.assertIn("static_view", {artifact["name"] for artifact in receipt["artifacts"]})
            self.assertEqual(SUPERVISED_ACCESS_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(receipt["receipt_id"], entry["payload"]["receipt_id"])
            self.assertTrue(chain.verify_all().ok)

    def test_supervised_access_detects_receipt_tamper_and_expiry_warning(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, pack, pack_path, disclosure, disclosure_path, view_path = self._chain_pack_disclosure_view(tmp)
            receipt = build_supervised_access_receipt(
                pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                subject_ref="oidc:regulator.example/supervisor-123",
                organization="Example Supervisor",
                role="regulator_reviewer",
                audience_type="regulator",
                purpose="EU AI Act supervised review",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )
            tampered = copy.deepcopy(receipt)
            tampered["reviewer"]["role"] = "changed"

            result = verify_supervised_access_receipt(tampered, now="2026-09-01T00:00:00Z")

            self.assertFalse(result.ok)
            self.assertIn("receipt_id does not match canonical receipt body", result.errors)
            self.assertIn("supervised access receipt is expired at verification time", result.warnings)

    def test_supervised_access_rejects_resigned_scope_escalation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, pack, pack_path, disclosure, disclosure_path, view_path = self._chain_pack_disclosure_view(tmp)
            receipt = build_supervised_access_receipt(
                pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                subject_ref="oidc:regulator.example/supervisor-123",
                organization="Example Supervisor",
                role="regulator_reviewer",
                audience_type="regulator",
                purpose="EU AI Act supervised review",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )
            receipt["scope"]["write_access"] = True
            self._resign_receipt(receipt)

            result = verify_supervised_access_receipt(
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("receipt_id does not match canonical receipt body", result.errors)
            self.assertNotIn("supervised access receipt signature invalid", result.errors)
            self.assertIn("supervised access scope does not match audience and artifacts", result.errors)

    def test_supervised_access_rejects_resigned_control_removal(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, pack, pack_path, disclosure, disclosure_path, view_path = self._chain_pack_disclosure_view(tmp)
            receipt = build_supervised_access_receipt(
                pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                subject_ref="oidc:regulator.example/supervisor-123",
                organization="Example Supervisor",
                role="regulator_reviewer",
                audience_type="regulator",
                purpose="EU AI Act supervised review",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )
            receipt["controls"] = [
                control for control in receipt["controls"] if control["id"] != "hosted-portal-auth"
            ]
            self._resign_receipt(receipt)

            result = verify_supervised_access_receipt(
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("receipt_id does not match canonical receipt body", result.errors)
            self.assertNotIn("supervised access receipt signature invalid", result.errors)
            self.assertIn("supervised access controls do not match audience and artifacts", result.errors)

    def test_supervised_access_rejects_resigned_artifact_summary_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, pack, pack_path, disclosure, disclosure_path, view_path = self._chain_pack_disclosure_view(tmp)
            receipt = build_supervised_access_receipt(
                pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                subject_ref="oidc:regulator.example/supervisor-123",
                organization="Example Supervisor",
                role="regulator_reviewer",
                audience_type="regulator",
                purpose="EU AI Act supervised review",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )
            receipt["artifacts"][0]["gate_outcome"] = "failed"
            self._resign_receipt(receipt)

            result = verify_supervised_access_receipt(
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("receipt_id does not match canonical receipt body", result.errors)
            self.assertNotIn("supervised access receipt signature invalid", result.errors)
            self.assertIn("artifact proof_pack gate_outcome mismatch", result.errors)

    def test_supervised_access_rejects_resigned_disclosure_for_different_pack(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, pack, pack_path, disclosure, disclosure_path, view_path = self._chain_pack_disclosure_view(tmp)
            disclosure["source_proof_pack"]["pack_id"] = "different-pack-id"
            self._resign_disclosure(disclosure)
            disclosure_path.write_text(json.dumps(disclosure, indent=2, sort_keys=True), encoding="utf-8")
            write_regulator_html(view_path, disclosure)
            receipt = build_supervised_access_receipt(
                pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                subject_ref="oidc:regulator.example/supervisor-123",
                organization="Example Supervisor",
                role="regulator_reviewer",
                audience_type="regulator",
                purpose="EU AI Act supervised review",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )

            result = verify_supervised_access_receipt(
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
            )

            self.assertFalse(result.ok)
            self.assertNotIn("source regulator disclosure invalid: disclosure_id does not match canonical disclosure body", result.errors)
            self.assertNotIn("source regulator disclosure invalid: regulator disclosure signature invalid", result.errors)
            self.assertIn("regulator disclosure source pack_id mismatch", result.errors)

    def test_supervised_access_rejects_view_not_rendered_from_disclosure(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            _, pack, pack_path, disclosure, disclosure_path, view_path = self._chain_pack_disclosure_view(tmp)
            view_path.write_text("<html><body>different disclosure view</body></html>", encoding="utf-8")
            receipt = build_supervised_access_receipt(
                pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
                subject_ref="oidc:regulator.example/supervisor-123",
                organization="Example Supervisor",
                role="regulator_reviewer",
                audience_type="regulator",
                purpose="EU AI Act supervised review",
                issued_at="2026-07-08T00:00:00Z",
                expires_at="2026-08-08T00:00:00Z",
            )

            result = verify_supervised_access_receipt(
                receipt,
                proof_pack=pack,
                proof_pack_path=pack_path,
                disclosure=disclosure,
                disclosure_path=disclosure_path,
                view_path=view_path,
            )

            self.assertFalse(result.ok)
            self.assertIn("static view does not match regulator disclosure render", result.errors)


if __name__ == "__main__":
    unittest.main()
