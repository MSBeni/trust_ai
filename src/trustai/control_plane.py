from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import EvidenceChain
from .cicd import PROMOTION_STATUS_ENTRY_TYPE
from .contracts import CONTRACT_ENTRY_TYPE
from .lifecycle import INCIDENT_ENTRY_TYPE
from .policy import POLICY_DECISION_ENTRY_TYPE
from .policy_engine import POLICY_ENGINE_ENTRY_TYPE
from .proofpack import PROOF_PACK_SPEC_VERSION
from .registry import AGENT_INVENTORY_ENTRY_TYPE
from .runtime import RUNTIME_ENTRY_TYPE

SCHEMA_VERSION = "trustai.control-plane/0.1"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _payload_contract_hash(entry: dict[str, Any]) -> str | None:
    payload = entry.get("payload", {})
    if not isinstance(payload, dict):
        return None
    if payload.get("contract_hash"):
        return payload["contract_hash"]
    decision = payload.get("decision")
    if isinstance(decision, dict):
        return decision.get("contract_hash")
    return None


def _decode_json_object(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


class ControlPlane:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.uses_nolock = False
        self.conn = self._connect_normal()
        try:
            self.initialize()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                self.conn.close()
                raise
            self.conn.close()
            self.uses_nolock = True
            self.conn = self._connect_nolock()
            self.initialize()
        except Exception:
            self.conn.close()
            raise

    def _configure(self, conn: sqlite3.Connection) -> sqlite3.Connection:
        conn.execute("PRAGMA busy_timeout = 2000")
        conn.row_factory = sqlite3.Row
        return conn

    def _connect_normal(self) -> sqlite3.Connection:
        return self._configure(sqlite3.connect(self.path, timeout=2))

    def _connect_nolock(self) -> sqlite3.Connection:
        uri = "file:" + self.path.as_posix() + "?nolock=1"
        return self._configure(sqlite3.connect(uri, timeout=2, uri=True))

    def close(self) -> None:
        self.conn.close()

    def initialize(self) -> None:
        self.conn.executescript(
            """
            PRAGMA journal_mode = DELETE;
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contracts (
                contract_hash TEXT PRIMARY KEY,
                contract_id TEXT NOT NULL,
                version TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                registered_entry_id TEXT,
                body_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agents (
                agent_hash TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                owner TEXT,
                risk_class TEXT,
                governed INTEGER NOT NULL,
                source TEXT,
                observed_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chain_entries (
                entry_id TEXT PRIMARY KEY,
                idx INTEGER NOT NULL,
                tenant_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                contract_hash TEXT,
                payload_hash TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS proof_packs (
                pack_id TEXT PRIMARY KEY,
                spec_version TEXT NOT NULL,
                contract_hash TEXT NOT NULL,
                contract_id TEXT,
                agent_name TEXT,
                agent_version TEXT,
                outcome TEXT,
                issued_at TEXT,
                path TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS promotion_statuses (
                receipt_id TEXT PRIMARY KEY,
                entry_id TEXT,
                provider TEXT,
                pack_id TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                gate_outcome TEXT,
                passed INTEGER NOT NULL,
                provider_status_kind TEXT,
                provider_status_success INTEGER,
                target_ref_json TEXT NOT NULL,
                violation_count INTEGER NOT NULL,
                attested_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_attestations (
                entry_id TEXT PRIMARY KEY,
                contract_id TEXT,
                contract_hash TEXT,
                action_hash TEXT,
                action_id TEXT,
                action_type TEXT,
                risk_class TEXT,
                passed INTEGER NOT NULL,
                outcome TEXT,
                check_count INTEGER NOT NULL,
                failed_check_count INTEGER NOT NULL,
                attested_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_decisions (
                entry_id TEXT PRIMARY KEY,
                policy_pack_id TEXT,
                policy_pack_version TEXT,
                policy_pack_hash TEXT,
                contract_hash TEXT,
                action_hash TEXT,
                passed INTEGER NOT NULL,
                outcome TEXT,
                matched_rule_count INTEGER NOT NULL,
                check_count INTEGER NOT NULL,
                failed_check_count INTEGER NOT NULL,
                evaluated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_engine_receipts (
                receipt_id TEXT PRIMARY KEY,
                entry_id TEXT,
                engine_name TEXT,
                engine_mode TEXT,
                policy_pack_id TEXT,
                policy_pack_version TEXT,
                policy_pack_hash TEXT,
                action_hash TEXT,
                action_id TEXT,
                action_type TEXT,
                risk_class TEXT,
                pack_id TEXT,
                contract_id TEXT,
                contract_hash TEXT,
                decision_entry_id TEXT,
                decision_outcome TEXT,
                decision_passed INTEGER,
                evaluated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                entry_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                severity TEXT,
                summary TEXT,
                detected_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anchors (
                anchor_id TEXT PRIMARY KEY,
                entry_id TEXT,
                tree_root TEXT NOT NULL,
                tree_size INTEGER NOT NULL,
                tenant_id TEXT,
                published_at TEXT,
                body_json TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("schema_version", SCHEMA_VERSION),
        )
        self.conn.commit()

    def index_chain(self, chain: EvidenceChain) -> dict[str, int]:
        counts = {
            "chain_entries": 0,
            "contracts": 0,
            "agents": 0,
            "anchors": 0,
            "promotion_statuses": 0,
            "runtime_attestations": 0,
            "policy_decisions": 0,
            "policy_engine_receipts": 0,
            "incidents": 0,
        }
        for entry in chain.entries:
            payload = entry.get("payload", {})
            contract_hash = _payload_contract_hash(entry)
            self.conn.execute(
                """
                INSERT OR REPLACE INTO chain_entries(
                    entry_id, idx, tenant_id, entry_type, timestamp,
                    contract_hash, payload_hash, body_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["entry_id"],
                    entry["index"],
                    entry["tenant_id"],
                    entry["entry_type"],
                    entry["timestamp"],
                    contract_hash,
                    entry["payload_hash"],
                    _json(entry),
                ),
            )
            counts["chain_entries"] += 1

            if entry.get("entry_type") == CONTRACT_ENTRY_TYPE:
                contract = payload.get("contract", {})
                agent = contract.get("agent", {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO contracts(
                        contract_hash, contract_id, version, agent_name,
                        agent_version, registered_entry_id, body_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["contract_hash"],
                        payload.get("contract_id"),
                        payload.get("contract_version"),
                        agent.get("name"),
                        agent.get("version"),
                        entry["entry_id"],
                        _json(contract),
                        entry["timestamp"],
                    ),
                )
                counts["contracts"] += 1

            if entry.get("entry_type") == AGENT_INVENTORY_ENTRY_TYPE:
                agent = payload.get("agent", {})
                agent_hash = payload.get("agent_hash") or content_hash(agent)
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO agents(
                        agent_hash, name, version, owner, risk_class, governed,
                        source, observed_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        agent_hash,
                        agent.get("name"),
                        agent.get("version"),
                        agent.get("owner"),
                        agent.get("risk_class"),
                        1 if agent.get("governed") else 0,
                        payload.get("source"),
                        payload.get("observed_at"),
                        _json(agent),
                    ),
                )
                counts["agents"] += 1

            if entry.get("entry_type") == "chain.anchor.published":
                anchor = payload
                tree = anchor.get("tree", {})
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO anchors(
                        anchor_id, entry_id, tree_root, tree_size, tenant_id,
                        published_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        anchor.get("anchor_id"),
                        entry["entry_id"],
                        tree.get("root"),
                        tree.get("size"),
                        anchor.get("tenant_id") or entry.get("tenant_id"),
                        anchor.get("published_at"),
                        _json(anchor),
                    ),
                )
                counts["anchors"] += 1
            if entry.get("entry_type") == PROMOTION_STATUS_ENTRY_TYPE:
                proof_pack = payload.get("proof_pack", {}) if isinstance(payload.get("proof_pack"), dict) else {}
                gate_decision = payload.get("gate_decision", {}) if isinstance(payload.get("gate_decision"), dict) else {}
                agent = gate_decision.get("agent", {}) if isinstance(gate_decision.get("agent"), dict) else {}
                provider_status = payload.get("provider_status", {}) if isinstance(payload.get("provider_status"), dict) else {}
                provider_payload = payload.get("provider_payload", {}) if isinstance(payload.get("provider_payload"), dict) else {}
                target_ref = provider_payload.get("target_ref", {}) if isinstance(provider_payload.get("target_ref"), dict) else {}
                provider_success = provider_status.get("success")
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO promotion_statuses(
                        receipt_id, entry_id, provider, pack_id, contract_id,
                        contract_hash, agent_name, agent_version, gate_outcome,
                        passed, provider_status_kind, provider_status_success,
                        target_ref_json, violation_count, attested_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("receipt_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("provider"),
                        proof_pack.get("pack_id"),
                        gate_decision.get("contract_id"),
                        gate_decision.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        gate_decision.get("outcome"),
                        1 if payload.get("passed") else 0,
                        provider_status.get("kind"),
                        None if provider_success is None else (1 if provider_success else 0),
                        _json(target_ref),
                        int(payload.get("violation_count") or 0),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["promotion_statuses"] += 1

            if entry.get("entry_type") == RUNTIME_ENTRY_TYPE:
                action = payload.get("action", {}) if isinstance(payload.get("action"), dict) else {}
                checks = payload.get("checks", []) if isinstance(payload.get("checks"), list) else []
                failed_checks = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO runtime_attestations(
                        entry_id, contract_id, contract_hash, action_hash,
                        action_id, action_type, risk_class, passed, outcome,
                        check_count, failed_check_count, attested_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        payload.get("action_hash"),
                        action.get("action_id") or action.get("id"),
                        action.get("type"),
                        action.get("risk_class"),
                        1 if payload.get("passed") else 0,
                        payload.get("outcome"),
                        len(checks),
                        len(failed_checks),
                        payload.get("timestamp") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["runtime_attestations"] += 1

            if entry.get("entry_type") == POLICY_DECISION_ENTRY_TYPE:
                checks = payload.get("checks", []) if isinstance(payload.get("checks"), list) else []
                failed_checks = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
                matched_rules = payload.get("matched_rules", []) if isinstance(payload.get("matched_rules"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO policy_decisions(
                        entry_id, policy_pack_id, policy_pack_version, policy_pack_hash,
                        contract_hash, action_hash, passed, outcome, matched_rule_count,
                        check_count, failed_check_count, evaluated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("policy_pack_id"),
                        payload.get("policy_pack_version"),
                        payload.get("policy_pack_hash"),
                        payload.get("contract_hash"),
                        payload.get("action_hash"),
                        1 if payload.get("passed") else 0,
                        payload.get("outcome"),
                        len(matched_rules),
                        len(checks),
                        len(failed_checks),
                        payload.get("evaluated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["policy_decisions"] += 1

            if entry.get("entry_type") == POLICY_ENGINE_ENTRY_TYPE:
                engine = payload.get("engine", {}) if isinstance(payload.get("engine"), dict) else {}
                policy = payload.get("policy", {}) if isinstance(payload.get("policy"), dict) else {}
                action = payload.get("action", {}) if isinstance(payload.get("action"), dict) else {}
                proof_pack = payload.get("proof_pack", {}) if isinstance(payload.get("proof_pack"), dict) else {}
                decision = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
                decision_passed = decision.get("passed")
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO policy_engine_receipts(
                        receipt_id, entry_id, engine_name, engine_mode,
                        policy_pack_id, policy_pack_version, policy_pack_hash,
                        action_hash, action_id, action_type, risk_class,
                        pack_id, contract_id, contract_hash, decision_entry_id,
                        decision_outcome, decision_passed, evaluated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("receipt_id") or entry["entry_id"],
                        entry["entry_id"],
                        engine.get("name"),
                        engine.get("mode"),
                        policy.get("id"),
                        policy.get("version"),
                        policy.get("hash"),
                        action.get("hash"),
                        action.get("id"),
                        action.get("type"),
                        action.get("risk_class"),
                        proof_pack.get("pack_id"),
                        proof_pack.get("contract_id"),
                        proof_pack.get("contract_hash"),
                        decision.get("entry_id"),
                        decision.get("outcome"),
                        None if decision_passed is None else (1 if decision_passed else 0),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["policy_engine_receipts"] += 1

            if entry.get("entry_type") == INCIDENT_ENTRY_TYPE:
                incident = payload.get("incident", {}) if isinstance(payload.get("incident"), dict) else {}
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else incident.get("agent", {})
                if not isinstance(agent, dict):
                    agent = {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO incidents(
                        incident_id, entry_id, contract_hash, agent_name, agent_version,
                        severity, summary, detected_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.get("id") or payload.get("incident_hash") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("contract_hash") or incident.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        incident.get("severity"),
                        incident.get("summary"),
                        incident.get("detected_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["incidents"] += 1
        self.conn.commit()
        return counts

    def index_proof_pack(self, proof_pack: dict[str, Any], path: str | Path | None = None) -> None:
        if proof_pack.get("spec_version") != PROOF_PACK_SPEC_VERSION:
            raise ValueError(f"unsupported proof pack: {proof_pack.get('spec_version')}")
        decision = proof_pack.get("gate_decision", {})
        agent = decision.get("agent", {})
        self.conn.execute(
            """
            INSERT OR REPLACE INTO proof_packs(
                pack_id, spec_version, contract_hash, contract_id, agent_name,
                agent_version, outcome, issued_at, path, body_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proof_pack["pack_id"],
                proof_pack["spec_version"],
                proof_pack.get("contract", {}).get("hash"),
                decision.get("contract_id"),
                agent.get("name"),
                agent.get("version"),
                decision.get("outcome"),
                proof_pack.get("issued_at"),
                str(path) if path else None,
                _json(proof_pack),
            ),
        )
        self.conn.commit()

    def summary(self) -> dict[str, Any]:
        tables = [
            "contracts",
            "agents",
            "chain_entries",
            "proof_packs",
            "anchors",
            "promotion_statuses",
            "runtime_attestations",
            "policy_decisions",
            "policy_engine_receipts",
            "incidents",
        ]
        counts = {
            table: self.conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
            for table in tables
        }
        latest_anchor = self.conn.execute(
            "SELECT anchor_id, tree_root, tree_size, published_at FROM anchors ORDER BY published_at DESC LIMIT 1"
        ).fetchone()
        latest_pack = self.conn.execute(
            "SELECT pack_id, contract_id, outcome, issued_at FROM proof_packs ORDER BY issued_at DESC LIMIT 1"
        ).fetchone()
        latest_status = self.conn.execute(
            """
            SELECT receipt_id, provider, pack_id, contract_id, gate_outcome,
                   passed, violation_count, attested_at
            FROM promotion_statuses
            ORDER BY attested_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_status_dict = dict(latest_status) if latest_status else None
        if latest_status_dict is not None:
            latest_status_dict["passed"] = bool(latest_status_dict["passed"])
        latest_runtime = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, action_id, risk_class,
                   passed, outcome, failed_check_count, attested_at
            FROM runtime_attestations
            ORDER BY attested_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_runtime_dict = dict(latest_runtime) if latest_runtime else None
        if latest_runtime_dict is not None:
            latest_runtime_dict["passed"] = bool(latest_runtime_dict["passed"])
        latest_policy_decision = self.conn.execute(
            """
            SELECT entry_id, policy_pack_id, contract_hash, passed, outcome,
                   failed_check_count, evaluated_at
            FROM policy_decisions
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_policy_decision_dict = dict(latest_policy_decision) if latest_policy_decision else None
        if latest_policy_decision_dict is not None:
            latest_policy_decision_dict["passed"] = bool(latest_policy_decision_dict["passed"])
        latest_policy_engine = self.conn.execute(
            """
            SELECT receipt_id, engine_name, engine_mode, policy_pack_id,
                   decision_outcome, decision_passed, evaluated_at
            FROM policy_engine_receipts
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_policy_engine_dict = dict(latest_policy_engine) if latest_policy_engine else None
        if latest_policy_engine_dict is not None and latest_policy_engine_dict.get("decision_passed") is not None:
            latest_policy_engine_dict["decision_passed"] = bool(latest_policy_engine_dict["decision_passed"])
        latest_incident = self.conn.execute(
            """
            SELECT incident_id, contract_hash, agent_name, severity, summary, detected_at
            FROM incidents
            ORDER BY detected_at DESC
            LIMIT 1
            """
        ).fetchone()
        return {
            "schema_version": SCHEMA_VERSION,
            "database": str(self.path),
            "locking_mode": "nolock" if self.uses_nolock else "normal",
            "indexed_at": utc_now(),
            "counts": counts,
            "latest_anchor": dict(latest_anchor) if latest_anchor else None,
            "latest_proof_pack": dict(latest_pack) if latest_pack else None,
            "latest_promotion_status": latest_status_dict,
            "latest_runtime_attestation": latest_runtime_dict,
            "latest_policy_decision": latest_policy_decision_dict,
            "latest_policy_engine_receipt": latest_policy_engine_dict,
            "latest_incident": dict(latest_incident) if latest_incident else None,
        }

    def recent_proof_packs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT pack_id, contract_id, agent_name, agent_version, outcome, issued_at, path
            FROM proof_packs
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_promotion_statuses(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT receipt_id, provider, pack_id, contract_id, contract_hash,
                   agent_name, agent_version, gate_outcome, passed,
                   provider_status_kind, provider_status_success,
                   target_ref_json, violation_count, attested_at
            FROM promotion_statuses
            ORDER BY attested_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        statuses = []
        for row in rows:
            item = dict(row)
            item["passed"] = bool(item["passed"])
            if item.get("provider_status_success") is not None:
                item["provider_status_success"] = bool(item["provider_status_success"])
            item["target_ref"] = _decode_json_object(item.pop("target_ref_json", None))
            statuses.append(item)
        return statuses

    def recent_runtime_attestations(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, action_hash, action_id,
                   action_type, risk_class, passed, outcome, check_count,
                   failed_check_count, attested_at
            FROM runtime_attestations
            ORDER BY attested_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["passed"] = bool(item["passed"])
            items.append(item)
        return items

    def recent_policy_decisions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, policy_pack_id, policy_pack_version, policy_pack_hash,
                   contract_hash, action_hash, passed, outcome, matched_rule_count,
                   check_count, failed_check_count, evaluated_at
            FROM policy_decisions
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["passed"] = bool(item["passed"])
            items.append(item)
        return items

    def recent_policy_engine_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT receipt_id, entry_id, engine_name, engine_mode, policy_pack_id,
                   policy_pack_version, policy_pack_hash, action_hash, action_id,
                   action_type, risk_class, pack_id, contract_id, contract_hash,
                   decision_entry_id, decision_outcome, decision_passed, evaluated_at
            FROM policy_engine_receipts
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            if item.get("decision_passed") is not None:
                item["decision_passed"] = bool(item["decision_passed"])
            items.append(item)
        return items

    def recent_incidents(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT incident_id, entry_id, contract_hash, agent_name, agent_version,
                   severity, summary, detected_at
            FROM incidents
            ORDER BY detected_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def runtime_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "runtime_attestations": self.recent_runtime_attestations(limit),
            "policy_decisions": self.recent_policy_decisions(limit),
            "policy_engine_receipts": self.recent_policy_engine_receipts(limit),
            "incidents": self.recent_incidents(limit),
        }

    def agents(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT name, version, owner, risk_class, governed, source, observed_at
            FROM agents
            ORDER BY name, version
            """
        ).fetchall()
        return [dict(row) for row in rows]



