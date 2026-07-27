import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.canonical import content_hash, without_keys
from trustai.chain import EvidenceChain
from trustai.crypto import sign_value
from trustai.phase_scoreboard import build_phase_scoreboard, write_phase_scoreboard
from trustai.phase_scoreboard_authority import (
    PHASE_SCOREBOARD_AUTHORITY_ENTRY_TYPE,
    PHASE_SCOREBOARD_AUTHORITY_SCHEMA,
    append_phase_scoreboard_authority_dossier,
    build_phase_scoreboard_authority_dossier,
    verify_phase_scoreboard_authority_dossier,
)

from tests.test_phase_scoreboard import _external_milestones


ROOT = Path(__file__).resolve().parents[1]


def _external_scoreboard():
    return build_phase_scoreboard(
        ROOT,
        scoreboard_ref="scoreboard:trustai/roadmap/external",
        producer_ref="oidc:trustai.example/strategy",
        mode="external-evidence",
        milestones=_external_milestones(),
        generated_at="2029-06-30T00:00:00Z",
    )


def _authority_rows():
    return [
        {
            "requirement_id": "ci-scoreboard-source-audit",
            "authority_kind": "ci-run",
            "evidence_ref": "ci:github-actions/roadmap-scoreboard-retained-evidence",
            "evidence_hash": "sha256:" + "a" * 64,
            "description": "CI run evidence for roadmap scoreboard source and retained artifact verification.",
            "issuer": "GitHub Actions",
            "subject": "roadmap phase scoreboard retained evidence",
            "source_uri": "https://github.com/MSBeni/trust_ai/actions",
            "issued_at": "2029-07-01T00:00:00Z",
            "expires_at": "2029-12-31T00:00:00Z",
        },
        {
            "requirement_id": "regulator-phase-acceptance",
            "authority_kind": "regulator",
            "evidence_ref": "regulator:exam/accepted-pack",
            "evidence_hash": "sha256:" + "b" * 64,
            "description": "Regulator or supervisor acceptance evidence for a live proof-pack examination.",
            "issuer": "Example Supervisor",
            "subject": "TrustAI proof-pack acceptance",
            "source_uri": "https://regulator.example/exams/trustai-proof-pack",
            "issued_at": "2029-07-01T00:00:00Z",
            "expires_at": "2029-12-31T00:00:00Z",
        },
        {
            "requirement_id": "insurer-phase-pricing-acceptance",
            "authority_kind": "insurer",
            "evidence_ref": "insurer:pricing-on-packs",
            "evidence_hash": "sha256:" + "c" * 64,
            "description": "Insurer pricing evidence based on proof-pack risk telemetry.",
            "issuer": "Example AI Liability Insurer",
            "subject": "proof-pack-backed pricing",
            "source_uri": "https://insurer.example/pricing/trustai-proof-packs",
            "issued_at": "2029-07-01T00:00:00Z",
            "expires_at": "2029-12-31T00:00:00Z",
        },
        {
            "requirement_id": "standards-track-recognition",
            "authority_kind": "standards-body",
            "evidence_ref": "standards:trustai/spec-track",
            "evidence_hash": "sha256:" + "d" * 64,
            "description": "Standards body evidence that the proof-pack spec entered a standards track.",
            "issuer": "Example Standards Body",
            "subject": "TrustAI proof-pack spec",
            "source_uri": "https://standards.example/trustai/proof-pack",
            "issued_at": "2029-07-01T00:00:00Z",
            "expires_at": "2029-12-31T00:00:00Z",
        },
        {
            "requirement_id": "customer-procurement-market-acceptance",
            "authority_kind": "customer",
            "evidence_ref": "customer:procurement/proof-pack-clause",
            "evidence_hash": "sha256:" + "e" * 64,
            "description": "Customer procurement evidence requiring TrustAI-format proof packs from vendors.",
            "issuer": "Example Buyer",
            "subject": "TrustAI-format proof pack procurement clause",
            "source_uri": "https://customer.example/procurement/trustai-proof-pack-clause",
            "issued_at": "2029-07-01T00:00:00Z",
            "expires_at": "2029-12-31T00:00:00Z",
        },
    ]


def _status_summary(controls):
    summary = {}
    for control in controls:
        summary[control["status"]] = summary.get(control["status"], 0) + 1
    return dict(sorted(summary.items()))


def _resign(dossier: dict):
    body = without_keys(dossier, "dossier_id", "signatures")
    dossier["dossier_id"] = content_hash(body)
    dossier["signatures"] = [sign_value({"dossier_id": dossier["dossier_id"], "phase_scoreboard_authority": body})]


class PhaseScoreboardAuthorityTests(unittest.TestCase):
    def test_partial_scoreboard_dossier_verifies_and_appends(self):
        scoreboard = _external_scoreboard()
        dossier = build_phase_scoreboard_authority_dossier(
            scoreboard,
            root=ROOT,
            mode="scoreboard-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:phase-scoreboard-authority/roadmap",
            authority_ref="authority:phase-scoreboard/roadmap",
            producer_ref="oidc:trustai.example/phase-scoreboard-authority-worker",
            authority_evidence=[_authority_rows()[0]],
            generated_at="2029-07-01T01:00:00Z",
        )
        result = verify_phase_scoreboard_authority_dossier(dossier, scoreboard=scoreboard, root=ROOT)
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="phase-scoreboard-authority-test")
            entry = append_phase_scoreboard_authority_dossier(chain, dossier, scoreboard=scoreboard, root=ROOT)

        self.assertTrue(result.ok, result.errors)
        self.assertIn("roadmap phase scoreboard authority evidence missing for", "\n".join(result.warnings))
        self.assertEqual(1, result.covered_count)
        self.assertEqual(PHASE_SCOREBOARD_AUTHORITY_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual({"deferred": 5, "passed": 4}, entry["payload"]["control_summary"])

    def test_complete_production_dossier_requires_fresh_evidence(self):
        scoreboard = _external_scoreboard()
        dossier = build_phase_scoreboard_authority_dossier(
            scoreboard,
            root=ROOT,
            mode="production-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:phase-scoreboard-authority/roadmap-production",
            authority_ref="authority:phase-scoreboard/roadmap",
            producer_ref="oidc:trustai.example/phase-scoreboard-authority-worker",
            authority_evidence=_authority_rows(),
            generated_at="2029-07-01T01:00:00Z",
        )

        result = verify_phase_scoreboard_authority_dossier(
            dossier,
            scoreboard=scoreboard,
            root=ROOT,
            require_complete=True,
            require_fresh=True,
            now="2029-07-02T00:00:00Z",
        )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual([], result.warnings)
        self.assertEqual(5, result.covered_count)
        self.assertEqual(5, result.fresh_evidence_count)
        self.assertEqual({"passed": 9}, _status_summary(dossier["controls"]))

    def test_production_dossier_rejects_readiness_source(self):
        scoreboard = build_phase_scoreboard(
            ROOT,
            scoreboard_ref="scoreboard:trustai/roadmap/readiness",
            producer_ref="oidc:trustai.example/strategy",
            generated_at="2026-07-20T00:00:00Z",
        )
        dossier = build_phase_scoreboard_authority_dossier(
            scoreboard,
            root=ROOT,
            mode="production-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:phase-scoreboard-authority/weak-source",
            authority_ref="authority:phase-scoreboard/roadmap",
            producer_ref="oidc:trustai.example/phase-scoreboard-authority-worker",
            authority_evidence=_authority_rows(),
            generated_at="2029-07-01T01:00:00Z",
        )

        result = verify_phase_scoreboard_authority_dossier(
            dossier,
            scoreboard=scoreboard,
            root=ROOT,
            require_complete=True,
            require_fresh=True,
            now="2029-07-02T00:00:00Z",
        )

        self.assertFalse(result.ok)
        self.assertIn("production-dossier requires an external-evidence scoreboard", "\n".join(result.errors))

    def test_malformed_hash_after_resign_is_rejected(self):
        scoreboard = _external_scoreboard()
        dossier = build_phase_scoreboard_authority_dossier(
            scoreboard,
            root=ROOT,
            mode="scoreboard-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:phase-scoreboard-authority/malformed",
            authority_ref="authority:phase-scoreboard/roadmap",
            producer_ref="oidc:trustai.example/phase-scoreboard-authority-worker",
            authority_evidence=[_authority_rows()[0]],
            generated_at="2029-07-01T01:00:00Z",
        )
        tampered = copy.deepcopy(dossier)
        tampered["authority_evidence"][0]["evidence_hash"] = "sha256:not-a-real-digest"
        tampered["authority_evidence"][0]["evidence_id"] = content_hash(without_keys(tampered["authority_evidence"][0], "evidence_id"))
        _resign(tampered)

        result = verify_phase_scoreboard_authority_dossier(tampered, scoreboard=scoreboard, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("evidence_hash" in error for error in result.errors), result.errors)

    def test_source_context_mismatch_after_resign_is_rejected(self):
        scoreboard = _external_scoreboard()
        dossier = build_phase_scoreboard_authority_dossier(
            scoreboard,
            root=ROOT,
            mode="scoreboard-dossier",
            environment="aitrade-prod",
            dossier_ref="dossier:phase-scoreboard-authority/source-context",
            authority_ref="authority:phase-scoreboard/roadmap",
            producer_ref="oidc:trustai.example/phase-scoreboard-authority-worker",
            authority_evidence=[_authority_rows()[0]],
            generated_at="2029-07-01T01:00:00Z",
        )
        tampered = copy.deepcopy(dossier)
        tampered["authority_evidence"][0]["source_context"]["scoreboard_id"] = "tampered"
        tampered["authority_evidence"][0]["evidence_id"] = content_hash(without_keys(tampered["authority_evidence"][0], "evidence_id"))
        _resign(tampered)

        result = verify_phase_scoreboard_authority_dossier(tampered, scoreboard=scoreboard, root=ROOT)

        self.assertFalse(result.ok)
        self.assertIn("source_context does not match scoreboard source", "\n".join(result.errors))

    def test_cli_phase_scoreboard_authority_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            scoreboard_path = tmp / "scoreboard.json"
            dossier_path = tmp / "authority.json"
            entry_path = tmp / "authority-entry.json"
            state_path = tmp / "chain.json"
            scoreboard = _external_scoreboard()
            write_phase_scoreboard(scoreboard_path, scoreboard)
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            evidence_args: list[str] = []
            for item in _authority_rows():
                metadata = (
                    f"issuer={item['issuer']};subject={item['subject']};source_uri={item['source_uri']};"
                    f"issued_at={item['issued_at']};expires_at={item['expires_at']}"
                )
                evidence_args.extend(
                    [
                        "--authority-evidence",
                        f"{item['requirement_id']},{item['authority_kind']},{item['evidence_ref']},{item['evidence_hash']},{item['description']};{metadata}",
                    ]
                )

            generated = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "phase-scoreboard-authority",
                    str(scoreboard_path),
                    "--root",
                    str(ROOT),
                    "--mode",
                    "production-dossier",
                    "--environment",
                    "aitrade-prod",
                    "--dossier-ref",
                    "dossier:phase-scoreboard-authority/roadmap-production",
                    "--authority-ref",
                    "authority:phase-scoreboard/roadmap",
                    "--producer-ref",
                    "oidc:trustai.example/phase-scoreboard-authority-worker",
                    "--generated-at",
                    "2029-07-01T01:00:00Z",
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2029-07-02T00:00:00Z",
                    "--out",
                    str(dossier_path),
                    *evidence_args,
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)

            verified = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "phase-scoreboard-authority-verify",
                    str(dossier_path),
                    str(scoreboard_path),
                    "--root",
                    str(ROOT),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2029-07-02T00:00:00Z",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)

            appended = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "phase-scoreboard-authority-append",
                    str(dossier_path),
                    str(scoreboard_path),
                    "--root",
                    str(ROOT),
                    "--require-complete",
                    "--require-fresh",
                    "--now",
                    "2029-07-02T00:00:00Z",
                    "--state",
                    str(state_path),
                    "--tenant",
                    "phase-scoreboard-authority-local",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, appended.returncode, appended.stderr)
            self.assertEqual(PHASE_SCOREBOARD_AUTHORITY_SCHEMA, json.loads(dossier_path.read_text())["schema"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
