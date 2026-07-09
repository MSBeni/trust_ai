from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import content_hash, parse_rfc3339, utc_now, without_keys

WORM_RECEIPT_SCHEMA = "trustai.worm-receipt/0.1"
WORM_LEGAL_HOLD_SCHEMA = "trustai.worm-legal-hold/0.1"


@dataclass
class WORMAudit:
    ok: bool
    errors: list[str]
    warnings: list[str]
    retention_active: bool
    legal_hold_active: bool = False
    object_path: str | None = None
    content_hash: str | None = None
    legal_hold_id: str | None = None


def _bytes_digest(data: bytes) -> str:
    return content_hash({"bytes_sha256": hashlib.sha256(data).hexdigest()})


class WORMStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.objects_dir = self.root / "objects"
        self.receipts_dir = self.root / "receipts"
        self.legal_holds_dir = self.root / "legal-holds"

    def store_bytes(
        self,
        data: bytes,
        artifact_type: str,
        retention_until: str = "2033-01-01T00:00:00Z",
    ) -> dict[str, Any]:
        digest = _bytes_digest(data)
        object_path = self.objects_dir / digest[:2] / digest
        if object_path.exists() and object_path.read_bytes() != data:
            raise ValueError(f"WORM object collision for {digest}")
        object_path.parent.mkdir(parents=True, exist_ok=True)
        if not object_path.exists():
            object_path.write_bytes(data)

        receipt_body = {
            "schema": WORM_RECEIPT_SCHEMA,
            "artifact_type": artifact_type,
            "content_hash": digest,
            "size_bytes": len(data),
            "stored_at": utc_now(),
            "retention_until": retention_until,
            "object_path": str(object_path.relative_to(self.root)),
        }
        receipt_body["receipt_id"] = content_hash(receipt_body)
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        (self.receipts_dir / f"{receipt_body['receipt_id']}.json").write_text(
            json.dumps(receipt_body, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return receipt_body

    def store_json(
        self,
        value: Any,
        artifact_type: str,
        retention_until: str = "2033-01-01T00:00:00Z",
    ) -> dict[str, Any]:
        data = json.dumps(value, sort_keys=True, indent=2).encode("utf-8")
        return self.store_bytes(data, artifact_type=artifact_type, retention_until=retention_until)

    def apply_legal_hold(
        self,
        receipt: dict[str, Any],
        *,
        case_id: str,
        reason: str,
        applied_by: str,
        applied_at: str | None = None,
    ) -> dict[str, Any]:
        audit = self.audit_receipt(receipt, now=applied_at)
        if not audit.ok:
            raise ValueError("cannot apply legal hold to invalid WORM receipt: " + "; ".join(audit.errors))
        if not case_id:
            raise ValueError("case_id is required")
        if not reason:
            raise ValueError("reason is required")
        if not applied_by:
            raise ValueError("applied_by is required")
        applied_at_value = applied_at or utc_now()
        parse_rfc3339(applied_at_value)
        body = {
            "schema": WORM_LEGAL_HOLD_SCHEMA,
            "status": "on",
            "worm_receipt_id": receipt.get("receipt_id"),
            "artifact_type": receipt.get("artifact_type"),
            "content_hash": receipt.get("content_hash"),
            "object_path": receipt.get("object_path"),
            "case_id": case_id,
            "reason": reason,
            "applied_by": applied_by,
            "applied_at": applied_at_value,
        }
        body["legal_hold_id"] = content_hash(body)
        self.legal_holds_dir.mkdir(parents=True, exist_ok=True)
        (self.legal_holds_dir / f"{body['legal_hold_id']}.json").write_text(
            json.dumps(body, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return body

    def audit_receipt(
        self,
        receipt: dict[str, Any],
        now: str | None = None,
        legal_hold: dict[str, Any] | None = None,
    ) -> WORMAudit:
        errors: list[str] = []
        warnings: list[str] = []
        retention_active = False
        legal_hold_active = False
        legal_hold_id = None

        if receipt.get("schema") != WORM_RECEIPT_SCHEMA:
            errors.append(f"unsupported receipt schema: {receipt.get('schema')}")

        expected_receipt_id = content_hash(without_keys(receipt, "receipt_id"))
        if receipt.get("receipt_id") != expected_receipt_id:
            errors.append("receipt_id does not match canonical receipt body")

        object_path_value = receipt.get("object_path")
        object_path = self.root / object_path_value if isinstance(object_path_value, str) else self.root
        if not isinstance(object_path_value, str) or not object_path_value:
            errors.append("receipt object_path missing")
        elif not object_path.exists():
            errors.append("WORM object is missing")
        else:
            data = object_path.read_bytes()
            actual_hash = _bytes_digest(data)
            if actual_hash != receipt.get("content_hash"):
                errors.append("WORM object content hash mismatch")
            if len(data) != receipt.get("size_bytes"):
                errors.append("WORM object size mismatch")

        try:
            retention_until = parse_rfc3339(receipt.get("retention_until", ""))
            checked_at = parse_rfc3339(now) if now else parse_rfc3339(utc_now())
            retention_active = checked_at <= retention_until
            if not retention_active:
                warnings.append("retention period has expired")
            stored_at = receipt.get("stored_at")
            if stored_at and retention_until < parse_rfc3339(stored_at):
                errors.append("retention_until is before stored_at")
        except Exception as exc:  # ValueError from timestamp parsing.
            errors.append(f"retention timestamp invalid: {exc}")

        if legal_hold is not None:
            hold_errors, hold_warnings, legal_hold_active, legal_hold_id = self._audit_legal_hold(receipt, legal_hold)
            errors.extend(hold_errors)
            warnings.extend(hold_warnings)

        return WORMAudit(
            ok=not errors,
            errors=errors,
            warnings=warnings,
            retention_active=retention_active,
            legal_hold_active=legal_hold_active,
            object_path=str(object_path_value) if isinstance(object_path_value, str) else None,
            content_hash=receipt.get("content_hash"),
            legal_hold_id=legal_hold_id,
        )

    def verify_receipt(self, receipt: dict[str, Any]) -> bool:
        return self.audit_receipt(receipt).ok

    def _audit_legal_hold(
        self,
        receipt: dict[str, Any],
        legal_hold: dict[str, Any],
    ) -> tuple[list[str], list[str], bool, str | None]:
        errors: list[str] = []
        warnings: list[str] = []
        legal_hold_id = legal_hold.get("legal_hold_id") if isinstance(legal_hold, dict) else None
        if not isinstance(legal_hold, dict):
            return ["legal hold must be an object"], warnings, False, None
        if legal_hold.get("schema") != WORM_LEGAL_HOLD_SCHEMA:
            errors.append(f"unsupported legal hold schema: {legal_hold.get('schema')}")
        expected_hold_id = content_hash(without_keys(legal_hold, "legal_hold_id"))
        if legal_hold.get("legal_hold_id") != expected_hold_id:
            errors.append("legal_hold_id does not match canonical legal hold body")
        if legal_hold.get("status") != "on":
            errors.append("legal hold status must be on")
        for field in ("case_id", "reason", "applied_by", "applied_at"):
            if not legal_hold.get(field):
                errors.append(f"legal hold {field} is required")
        try:
            parse_rfc3339(legal_hold.get("applied_at", ""))
        except ValueError as exc:
            errors.append(f"legal hold applied_at invalid: {exc}")
        checks = {
            "worm_receipt_id": receipt.get("receipt_id"),
            "artifact_type": receipt.get("artifact_type"),
            "content_hash": receipt.get("content_hash"),
            "object_path": receipt.get("object_path"),
        }
        for field, expected in checks.items():
            if legal_hold.get(field) != expected:
                errors.append(f"legal hold {field} does not match receipt")
        return errors, warnings, not errors, legal_hold_id if isinstance(legal_hold_id, str) else None