import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash
from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.verifier import verify_proof_pack
from trustai.shadow import (
    SHADOW_REPLAY_ENTRY_TYPE,
    TEMPORAL_HOLDOUT_ENTRY_TYPE,
    TEMPORAL_HOLDOUT_SCHEMA,
    append_shadow_replay,
    append_temporal_holdout_manifest,
    evaluate_shadow_replay,
    build_temporal_holdout_manifest,
    load_shadow_replay,
    shadow_replay_to_eval_results,
    verify_temporal_holdout_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"

SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"


class TemporalHoldoutTests(unittest.TestCase):
    def _contract(self) -> dict:
        return load_contract(CONTRACT)

    def _replay(self) -> dict:
        return load_shadow_replay(SHADOW)

    def test_temporal_holdout_manifest_hash_chains_records(self):
        manifest = build_temporal_holdout_manifest(
            self._contract(),
            self._replay(),
            generated_at="2026-07-03T12:30:00Z",
        )
        result = verify_temporal_holdout_manifest(manifest, contract=self._contract(), replay=self._replay())

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(TEMPORAL_HOLDOUT_SCHEMA, manifest["schema"])
        self.assertEqual(3, manifest["record_count"])
        self.assertTrue(manifest["passed"])
        self.assertEqual([], manifest["violations"])
        self.assertEqual(manifest["records"][-1]["record_node_hash"], manifest["records_root"])
        self.assertIsNone(manifest["records"][0]["previous_record_node_hash"])
        self.assertEqual(
            manifest["records"][0]["record_node_hash"],
            manifest["records"][1]["previous_record_node_hash"],
        )

    def test_temporal_holdout_manifest_appends_to_chain(self):
        manifest = build_temporal_holdout_manifest(
            self._contract(),
            self._replay(),
            generated_at="2026-07-03T12:30:00Z",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="temporal-holdout-test")
            entry = append_temporal_holdout_manifest(chain, manifest, contract=self._contract(), replay=self._replay())

            self.assertEqual(TEMPORAL_HOLDOUT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(manifest["manifest_id"], entry["payload"]["manifest_id"])
            self.assertEqual(manifest["records_root"], entry["payload"]["records_root"])
            self.assertTrue(chain.verify_all().ok)

    def test_shadow_replay_entry_embeds_temporal_holdout_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="shadow-holdout-test")
            entry = append_shadow_replay(chain, self._contract(), self._replay())

            payload = entry["payload"]
            result = verify_temporal_holdout_manifest(
                payload["temporal_holdout_manifest"],
                contract=self._contract(),
                replay=self._replay(),
            )

            self.assertTrue(result.ok, result.errors)
            self.assertEqual(payload["temporal_holdout_manifest"]["manifest_id"], payload["temporal_holdout"]["manifest_id"])
            self.assertEqual(payload["temporal_holdout_manifest"]["records_root"], payload["temporal_holdout"]["records_root"])
            self.assertTrue(payload["temporal_holdout"]["passed"])

    def test_temporal_holdout_manifest_records_boundary_violations(self):
        replay = self._replay()
        replay["records"][0]["timestamp"] = "2026-06-30T23:59:00Z"

        manifest = build_temporal_holdout_manifest(
            self._contract(),
            replay,
            generated_at="2026-07-03T12:30:00Z",
        )
        result = verify_temporal_holdout_manifest(manifest, contract=self._contract(), replay=replay)

        self.assertTrue(result.ok, result.errors)
        self.assertFalse(manifest["passed"])
        self.assertTrue(manifest["violations"])
        self.assertTrue(any("post-freeze" in item["violation"] for item in manifest["violations"]))
        self.assertTrue(result.warnings)

    def test_temporal_holdout_manifest_rejects_source_replay_tamper(self):
        manifest = build_temporal_holdout_manifest(
            self._contract(),
            self._replay(),
            generated_at="2026-07-03T12:30:00Z",
        )
        tampered_replay = self._replay()
        tampered_replay["records"][1]["candidate_action"] = "allow_shadow_order"

        result = verify_temporal_holdout_manifest(manifest, contract=self._contract(), replay=tampered_replay)

        self.assertFalse(result.ok)
        self.assertTrue(any("replay_hash mismatch" in error for error in result.errors))
        self.assertTrue(any("replay record hash mismatch" in error for error in result.errors))

    def test_temporal_holdout_manifest_rejects_manifest_tamper(self):
        manifest = build_temporal_holdout_manifest(
            self._contract(),
            self._replay(),
            generated_at="2026-07-03T12:30:00Z",
        )
        tampered = copy.deepcopy(manifest)
        tampered["records"][0]["timestamp"] = "2026-07-04T00:00:00Z"

        result = verify_temporal_holdout_manifest(tampered, contract=self._contract(), replay=self._replay())

        self.assertFalse(result.ok)
        self.assertTrue(any("manifest_id" in error or "signature" in error for error in result.errors))
        self.assertTrue(any("node hash mismatch" in error for error in result.errors))

    def test_proof_pack_verifier_replays_embedded_temporal_holdout_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="temporal-holdout-pack-test")
            contract = self._contract()
            register_contract(chain, contract)
            replay = self._replay()
            manifest = build_temporal_holdout_manifest(
                contract,
                replay,
                generated_at="2026-07-03T12:30:00Z",
            )
            tampered_replay = self._replay()
            tampered_replay["records"][1]["candidate_action"] = "allow_shadow_order"
            evaluation = evaluate_shadow_replay(contract, tampered_replay)
            chain.append(
                SHADOW_REPLAY_ENTRY_TYPE,
                {
                    **evaluation,
                    "replay_hash": content_hash(tampered_replay),
                    "temporal_holdout_manifest": manifest,
                    "temporal_holdout": {
                        "manifest_id": manifest["manifest_id"],
                        "manifest_hash": content_hash(manifest),
                        "records_root": manifest["records_root"],
                        "record_count": manifest["record_count"],
                        "passed": manifest["passed"],
                    },
                    "replay": tampered_replay,
                },
                timestamp=evaluation["evaluated_at"],
            )
            eval_entry, gate_entry, decision = append_eval_and_gate(
                chain,
                contract,
                shadow_replay_to_eval_results(contract, tampered_replay),
            )
            pack = compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

            result = verify_proof_pack(pack)

            self.assertFalse(result.ok)
            self.assertTrue(
                any("temporal holdout: temporal holdout replay_hash mismatch" in error for error in result.errors)
            )
            self.assertTrue(any("temporal holdout replay record hash mismatch" in error for error in result.errors))

    def test_cli_temporal_holdout_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            manifest_path = tmp / "temporal-holdout-manifest.json"
            entry_path = tmp / "temporal-holdout-entry.json"
            state_path = tmp / "evidence-chain.json"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "temporal-holdout-manifest",
                    str(CONTRACT),
                    str(SHADOW),
                    "--generated-at",
                    "2026-07-03T12:30:00Z",
                    "--out",
                    str(manifest_path),
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
                    "temporal-holdout-verify",
                    str(manifest_path),
                    "--contract",
                    str(CONTRACT),
                    "--replay",
                    str(SHADOW),
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
                    "temporal-holdout-append",
                    str(manifest_path),
                    "--contract",
                    str(CONTRACT),
                    "--replay",
                    str(SHADOW),
                    "--state",
                    str(state_path),
                    "--tenant",
                    "temporal-holdout-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["manifest_id"], entry["payload"]["manifest_id"])


if __name__ == "__main__":
    unittest.main()
