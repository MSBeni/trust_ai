import tempfile
import unittest
from pathlib import Path

from trustai.object_store import WORM_LEGAL_HOLD_SCHEMA, WORMStore


class WORMLegalHoldTests(unittest.TestCase):
    def test_legal_hold_verifies_against_expired_retention_receipt(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = WORMStore(Path(tmp_dir) / "worm")
            receipt = store.store_json(
                {"artifact": "proof-pack", "pack_id": "pack-123"},
                "proof-pack",
                retention_until="2033-01-01T00:00:00Z",
            )
            hold = store.apply_legal_hold(
                receipt,
                case_id="litigation-2026-001",
                reason="Preserve proof pack for external audit review.",
                applied_by="legal@example.com",
                applied_at="2026-07-03T12:00:00Z",
            )

            audit = store.audit_receipt(receipt, now="2034-01-01T00:00:00Z", legal_hold=hold)

            self.assertTrue(audit.ok, audit.errors)
            self.assertFalse(audit.retention_active)
            self.assertTrue(audit.legal_hold_active)
            self.assertEqual(WORM_LEGAL_HOLD_SCHEMA, hold["schema"])
            self.assertEqual(hold["legal_hold_id"], audit.legal_hold_id)
            self.assertIn("retention period has expired", audit.warnings)

    def test_legal_hold_reference_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = WORMStore(Path(tmp_dir) / "worm")
            receipt = store.store_json({"artifact": "chain-anchor"}, "chain-anchor")
            hold = store.apply_legal_hold(
                receipt,
                case_id="litigation-2026-002",
                reason="Preserve chain anchor.",
                applied_by="legal@example.com",
                applied_at="2026-07-03T12:00:00Z",
            )
            hold["content_hash"] = "tampered"

            audit = store.audit_receipt(receipt, legal_hold=hold)

            self.assertFalse(audit.ok)
            self.assertFalse(audit.legal_hold_active)
            self.assertTrue(any("legal_hold_id" in error for error in audit.errors))
            self.assertTrue(any("content_hash" in error for error in audit.errors))


if __name__ == "__main__":
    unittest.main()
