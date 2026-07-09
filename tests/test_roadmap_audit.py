import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.roadmap_audit import (
    ROADMAP_AUDIT_ENTRY_TYPE,
    ROADMAP_AUDIT_SCHEMA,
    STATUS_IMPLEMENTED_LOCAL,
    STATUS_MISSING_LOCAL_EVIDENCE,
    STATUS_REFERENCE_ATTESTED,
    append_roadmap_audit,
    build_roadmap_audit,
    render_roadmap_audit_markdown,
    verify_roadmap_audit,
)


ROOT = Path(__file__).resolve().parents[1]


class RoadmapAuditTests(unittest.TestCase):
    def test_roadmap_audit_hashes_local_evidence_and_verifies(self):
        audit = build_roadmap_audit(ROOT)
        result = verify_roadmap_audit(audit, root=ROOT)
        statuses = {requirement["status"] for requirement in audit["requirements"]}
        requirement_ids = {requirement["id"] for requirement in audit["requirements"]}
        markdown = render_roadmap_audit_markdown(audit)

        self.assertEqual(ROADMAP_AUDIT_SCHEMA, audit["schema"])
        self.assertTrue(result.ok, result.errors)
        self.assertIn(STATUS_IMPLEMENTED_LOCAL, statuses)
        self.assertIn(STATUS_REFERENCE_ATTESTED, statuses)
        self.assertNotIn(STATUS_MISSING_LOCAL_EVIDENCE, statuses)
        self.assertIn("proof-pack-spec-and-compiler", requirement_ids)
        self.assertIn("trust-network-procurement-and-marketplace", requirement_ids)
        proof_pack_requirement = next(
            requirement for requirement in audit["requirements"] if requirement["id"] == "proof-pack-spec-and-compiler"
        )
        proof_pack_evidence = {item["path"] for item in proof_pack_requirement["evidence"]}
        self.assertIn("src/trustai/verifier.py", proof_pack_evidence)
        self.assertIn("tests/test_temporal_holdout.py", proof_pack_evidence)
        identity_requirement = next(requirement for requirement in audit["requirements"] if requirement["id"] == "agent-inventory-and-identity")
        identity_evidence = {item["path"] for item in identity_requirement["evidence"]}
        self.assertIn("src/trustai/identity_provider_lifecycle_operation.py", identity_evidence)
        self.assertIn("src/trustai/identity_provider_lifecycle_worker.py", identity_evidence)
        self.assertIn("docs/specs/identity-provider-lifecycle-worker-v0.1.md", identity_evidence)
        self.assertIn("tests/test_identity_provider_lifecycle_worker.py", identity_evidence)
        mcp_requirement = next(requirement for requirement in audit["requirements"] if requirement["id"] == "mcp-gateway")
        self.assertIn("tests/test_mcp_gateway.py", {item["path"] for item in mcp_requirement["evidence"]})
        framework_requirement = next(requirement for requirement in audit["requirements"] if requirement["id"] == "framework-adapters")
        framework_evidence = {item["path"] for item in framework_requirement["evidence"]}
        self.assertIn("src/trustai/framework_adapter_matrix.py", framework_evidence)
        self.assertIn("tests/test_framework_adapter_matrix.py", framework_evidence)
        shadow_requirement = next(requirement for requirement in audit["requirements"] if requirement["id"] == "shadow-replay-temporal-holdout")
        shadow_evidence = {item["path"] for item in shadow_requirement["evidence"]}
        self.assertIn("docs/specs/temporal-holdout-manifest-v0.1.md", shadow_evidence)
        self.assertIn("tests/test_temporal_holdout.py", shadow_evidence)
        self.assertGreater(audit["summary"][STATUS_REFERENCE_ATTESTED], 0)
        self.assertIn("TrustAI Roadmap Audit", markdown)
        self.assertIn("Deferred External Authority", markdown)

    def test_roadmap_audit_appends_to_chain(self):
        audit = build_roadmap_audit(ROOT)

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="roadmap-audit-test")
            entry = append_roadmap_audit(chain, audit, root=ROOT)

            self.assertEqual(ROADMAP_AUDIT_ENTRY_TYPE, entry["entry_type"])
            self.assertEqual(audit["audit_id"], entry["payload"]["audit_id"])
            self.assertEqual(audit["completion_position"], entry["payload"]["completion_position"])
            self.assertEqual(audit["summary"][STATUS_REFERENCE_ATTESTED], entry["payload"]["reference_attested_count"])
            self.assertTrue(chain.verify_all().ok)

    def test_roadmap_audit_append_rejects_invalid_audit(self):
        audit = build_roadmap_audit(ROOT)
        tampered = copy.deepcopy(audit)
        tampered["requirements"][0]["evidence"][0]["sha256"] = "sha256:" + "0" * 64

        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="roadmap-audit-test")
            with self.assertRaisesRegex(ValueError, "invalid roadmap audit"):
                append_roadmap_audit(chain, tampered, root=ROOT)

    def test_cli_roadmap_audit_append_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            audit_path = tmp_path / "roadmap-audit.json"
            entry_path = tmp_path / "roadmap-audit-entry.json"
            chain_path = tmp_path / "chain.json"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-audit",
                    "--root",
                    str(ROOT),
                    "--out",
                    str(audit_path),
                    "--markdown",
                    str(tmp_path / "roadmap-audit.md"),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "roadmap-audit-append",
                    str(audit_path),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(chain_path),
                    "--tenant",
                    "roadmap-audit-cli",
                    "--out",
                    str(entry_path),
                ],
                cwd=ROOT,
                check=True,
            )

            chain = EvidenceChain.load(chain_path, tenant_id="roadmap-audit-cli")
            self.assertEqual(1, len(chain.entries))
            self.assertEqual(ROADMAP_AUDIT_ENTRY_TYPE, chain.entries[0]["entry_type"])
            self.assertTrue(chain.verify_all().ok)

    def test_roadmap_audit_detects_hash_tamper(self):
        audit = build_roadmap_audit(ROOT)
        tampered = copy.deepcopy(audit)
        tampered["source"]["roadmap"]["sha256"] = "sha256:" + "0" * 64

        result = verify_roadmap_audit(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("audit_id" in error for error in result.errors))
        self.assertTrue(any("source:roadmap" in error and "hash mismatch" in error for error in result.errors))

    def test_roadmap_audit_detects_missing_local_evidence(self):
        audit = build_roadmap_audit(ROOT)
        tampered = copy.deepcopy(audit)
        requirement = tampered["requirements"][0]
        requirement["evidence"][0]["path"] = "missing/local/evidence.py"

        result = verify_roadmap_audit(tampered, root=ROOT)

        self.assertFalse(result.ok)
        self.assertTrue(any("evidence path missing" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
