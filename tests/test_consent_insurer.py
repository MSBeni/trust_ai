import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from trustai.actuarial import ACTUARIAL_CORPUS_SCHEMA, build_actuarial_corpus
from trustai.chain import EvidenceChain
from trustai.consent import (
    CONSENT_GRANTED_ENTRY_TYPE,
    CONSENT_REVOKED_ENTRY_TYPE,
    INSURER_SCOPE,
    append_consent_grant,
    append_consent_revocation,
    consent_status,
    load_consent,
)
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.insurer import build_insurer_telemetry
from trustai.lifecycle import append_incident, load_incident
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.server import serve
from trustai.shadow import append_shadow_replay, append_soak_report, load_shadow_replay, load_soak_window, shadow_replay_to_eval_results


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"
CONSENT = ROOT / "examples" / "aitrade" / "insurer-consent.json"
INCIDENT = ROOT / "examples" / "aitrade" / "incident.json"


class ConsentInsurerTests(unittest.TestCase):
    def _chain_and_pack(self, tmp: Path):
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
        return chain, pack

    def test_consent_grant_and_revoke_are_chain_evidence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain, pack = self._chain_and_pack(Path(tmp_dir))
            consent = load_consent(CONSENT)
            grant = append_consent_grant(chain, consent)
            active = consent_status(
                chain,
                consent["consent_id"],
                INSURER_SCOPE,
                pack_id=pack["pack_id"],
                contract_id=pack["gate_decision"]["contract_id"],
                now="2026-07-05T00:00:00Z",
            )
            telemetry = build_insurer_telemetry(pack, consent_id=consent["consent_id"], consent=active)
            append_incident(chain, load_incident(INCIDENT))
            corpus = build_actuarial_corpus(
                chain,
                [pack],
                consent_id=consent["consent_id"],
                require_consent=True,
                now="2026-07-05T00:00:00Z",
                anonymization_salt="test-salt",
            )
            revoke = append_consent_revocation(
                chain,
                consent["consent_id"],
                "customer withdrew underwriting data consent",
                revoked_at="2026-07-06T00:00:00Z",
            )
            inactive = consent_status(
                chain,
                consent["consent_id"],
                INSURER_SCOPE,
                pack_id=pack["pack_id"],
                contract_id=pack["gate_decision"]["contract_id"],
                now="2026-07-07T00:00:00Z",
            )

            self.assertEqual(CONSENT_GRANTED_ENTRY_TYPE, grant["entry_type"])
            self.assertEqual(CONSENT_REVOKED_ENTRY_TYPE, revoke["entry_type"])
            self.assertTrue(active["active"])
            self.assertFalse(inactive["active"])
            self.assertTrue(telemetry["consent"]["status"]["active"])
            self.assertEqual(ACTUARIAL_CORPUS_SCHEMA, corpus["schema"])
            self.assertEqual(1, corpus["record_count"])
            self.assertTrue(corpus["consent"]["all_active"])
            self.assertEqual(1, corpus["aggregate"]["incident_count"])
            self.assertEqual("high", corpus["records"][0]["evidence"]["lifecycle"]["max_incident_severity"])
            self.assertNotEqual(pack["pack_id"], corpus["records"][0]["pack"]["id_hash"])
            with self.assertRaisesRegex(ValueError, "actuarial export denied"):
                build_actuarial_corpus(
                    chain,
                    [pack],
                    consent_id=consent["consent_id"],
                    require_consent=True,
                    now="2026-07-07T00:00:00Z",
                )
            self.assertTrue(chain.verify_all().ok)

    def test_insurer_api_requires_token_and_active_consent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            state_path = tmp / "chain.json"
            chain, pack = self._chain_and_pack(tmp)
            consent = load_consent(CONSENT)
            append_consent_grant(chain, consent)
            chain.save()
            httpd = serve("127.0.0.1", 0, str(state_path), "test", insurer_token="secret-token")
            host, port = httpd.server_address
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                body = json.dumps(
                    {
                        "path": str(tmp / "pack.json"),
                        "consent_id": consent["consent_id"],
                        "now": "2026-07-05T00:00:00Z",
                    }
                ).encode("utf-8")
                request = urllib.request.Request(
                    f"http://{host}:{port}/v0/insurer-risk",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as unauthorized:
                    urllib.request.urlopen(request, timeout=5)
                self.assertEqual(401, unauthorized.exception.code)

                authed = urllib.request.Request(
                    f"http://{host}:{port}/v0/insurer-risk",
                    data=body,
                    headers={"Content-Type": "application/json", "Authorization": "Bearer secret-token"},
                    method="POST",
                )
                with urllib.request.urlopen(authed, timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual("trustai.insurer-risk-telemetry/0.1", payload["schema"])
                self.assertTrue(payload["consent"]["status"]["active"])
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
