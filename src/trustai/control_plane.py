from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import EvidenceChain
from .cicd import PROMOTION_STATUS_ENTRY_TYPE
from .contracts import CONTRACT_ENTRY_TYPE
from .gate import EVAL_ENTRY_TYPE, GATE_ENTRY_TYPE
from .ingest import INGEST_ENTRY_TYPE
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


def _bool_fields(item: dict[str, Any], *fields: str) -> dict[str, Any]:
    for field in fields:
        if item.get(field) is not None:
            item[field] = bool(item[field])
    return item


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
            CREATE TABLE IF NOT EXISTS ingest_events (
                entry_id TEXT PRIMARY KEY,
                event_hash TEXT NOT NULL,
                contract_hash TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                event_name TEXT NOT NULL,
                agent_name TEXT,
                agent_version TEXT,
                risk_class TEXT,
                schema_url TEXT,
                observed_at TEXT,
                attributes_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS eval_runs (
                entry_id TEXT PRIMARY KEY,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                results_hash TEXT,
                evaluated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS gate_decisions (
                entry_id TEXT PRIMARY KEY,
                contract_id TEXT,
                contract_hash TEXT,
                agent_name TEXT,
                agent_version TEXT,
                outcome TEXT,
                passed INTEGER NOT NULL,
                eval_entry_id TEXT,
                contract_entry_id TEXT,
                results_hash TEXT,
                check_count INTEGER NOT NULL,
                failed_check_count INTEGER NOT NULL,
                holdout_passed INTEGER,
                approvals_passed INTEGER,
                evaluated_at TEXT,
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
            "ingest_events": 0,
            "eval_runs": 0,
            "gate_decisions": 0,
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

            if entry.get("entry_type") == INGEST_ENTRY_TYPE:
                event = payload.get("event", {}) if isinstance(payload.get("event"), dict) else {}
                agent = event.get("agent", {}) if isinstance(event.get("agent"), dict) else {}
                attributes = event.get("attributes", {}) if isinstance(event.get("attributes"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO ingest_events(
                        entry_id, event_hash, contract_hash, trace_id, span_id,
                        parent_span_id, event_name, agent_name, agent_version,
                        risk_class, schema_url, observed_at, attributes_json, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("event_hash") or content_hash(event),
                        payload.get("contract_hash") or event.get("contract_hash"),
                        payload.get("trace_id") or event.get("trace_id"),
                        payload.get("span_id") or event.get("span_id"),
                        event.get("parent_span_id"),
                        event.get("event_name"),
                        agent.get("name"),
                        agent.get("version"),
                        event.get("risk_class"),
                        event.get("schema_url"),
                        event.get("timestamp") or entry.get("timestamp"),
                        _json(attributes),
                        _json(payload),
                    ),
                )
                counts["ingest_events"] += 1

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

            if entry.get("entry_type") == EVAL_ENTRY_TYPE:
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
                results = payload.get("results", {}) if isinstance(payload.get("results"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO eval_runs(
                        entry_id, contract_id, contract_hash, agent_name,
                        agent_version, results_hash, evaluated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("contract_id"),
                        payload.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        payload.get("results_hash"),
                        results.get("evaluated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["eval_runs"] += 1

            if entry.get("entry_type") == GATE_ENTRY_TYPE:
                decision = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
                agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else decision.get("agent", {})
                if not isinstance(agent, dict):
                    agent = {}
                checks = decision.get("checks", []) if isinstance(decision.get("checks"), list) else []
                failed_checks = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
                holdout = decision.get("holdout", {}) if isinstance(decision.get("holdout"), dict) else {}
                approvals = decision.get("approvals", {}) if isinstance(decision.get("approvals"), dict) else {}
                holdout_passed = holdout.get("passed")
                approvals_passed = approvals.get("passed")
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO gate_decisions(
                        entry_id, contract_id, contract_hash, agent_name,
                        agent_version, outcome, passed, eval_entry_id,
                        contract_entry_id, results_hash, check_count,
                        failed_check_count, holdout_passed, approvals_passed,
                        evaluated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["entry_id"],
                        payload.get("contract_id") or decision.get("contract_id"),
                        payload.get("contract_hash") or decision.get("contract_hash"),
                        agent.get("name"),
                        agent.get("version"),
                        decision.get("outcome"),
                        1 if decision.get("passed") else 0,
                        decision.get("eval_entry_id"),
                        decision.get("contract_entry_id"),
                        decision.get("results_hash"),
                        len(checks),
                        len(failed_checks),
                        None if holdout_passed is None else (1 if holdout_passed else 0),
                        None if approvals_passed is None else (1 if approvals_passed else 0),
                        decision.get("evaluated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["gate_decisions"] += 1

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
            "ingest_events",
            "eval_runs",
            "gate_decisions",
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
        latest_eval_run = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name, agent_version,
                   results_hash, evaluated_at
            FROM eval_runs
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_gate_decision = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name, agent_version,
                   outcome, passed, failed_check_count, holdout_passed,
                   approvals_passed, evaluated_at
            FROM gate_decisions
            ORDER BY evaluated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_gate_decision_dict = dict(latest_gate_decision) if latest_gate_decision else None
        if latest_gate_decision_dict is not None:
            latest_gate_decision_dict["passed"] = bool(latest_gate_decision_dict["passed"])
            if latest_gate_decision_dict.get("holdout_passed") is not None:
                latest_gate_decision_dict["holdout_passed"] = bool(latest_gate_decision_dict["holdout_passed"])
            if latest_gate_decision_dict.get("approvals_passed") is not None:
                latest_gate_decision_dict["approvals_passed"] = bool(latest_gate_decision_dict["approvals_passed"])
        latest_ingest_event = self.conn.execute(
            """
            SELECT entry_id, event_hash, contract_hash, trace_id, span_id,
                   event_name, agent_name, agent_version, risk_class, observed_at
            FROM ingest_events
            ORDER BY observed_at DESC
            LIMIT 1
            """
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
            "latest_eval_run": dict(latest_eval_run) if latest_eval_run else None,
            "latest_gate_decision": latest_gate_decision_dict,
            "latest_ingest_event": dict(latest_ingest_event) if latest_ingest_event else None,
            "latest_promotion_status": latest_status_dict,
            "latest_runtime_attestation": latest_runtime_dict,
            "latest_policy_decision": latest_policy_decision_dict,
            "latest_policy_engine_receipt": latest_policy_engine_dict,
            "latest_incident": dict(latest_incident) if latest_incident else None,
        }

    def contracts(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT contract_hash, contract_id, version, agent_name, agent_version,
                   registered_entry_id, created_at
            FROM contracts
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_eval_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name, agent_version,
                   results_hash, evaluated_at
            FROM eval_runs
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recent_gate_decisions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, contract_id, contract_hash, agent_name, agent_version,
                   outcome, passed, eval_entry_id, contract_entry_id, results_hash,
                   check_count, failed_check_count, holdout_passed, approvals_passed,
                   evaluated_at
            FROM gate_decisions
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        decisions = []
        for row in rows:
            item = dict(row)
            item["passed"] = bool(item["passed"])
            if item.get("holdout_passed") is not None:
                item["holdout_passed"] = bool(item["holdout_passed"])
            if item.get("approvals_passed") is not None:
                item["approvals_passed"] = bool(item["approvals_passed"])
            decisions.append(item)
        return decisions

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

    def recent_ingest_events(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT entry_id, event_hash, contract_hash, trace_id, span_id,
                   parent_span_id, event_name, agent_name, agent_version,
                   risk_class, schema_url, observed_at, attributes_json
            FROM ingest_events
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["attributes"] = _decode_json_object(item.pop("attributes_json", None))
            items.append(item)
        return items

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

    def _resolve_contract_scope(
        self,
        contract_id: str | None,
        contract_hash: str | None,
    ) -> tuple[dict[str, Any] | None, str | None, str | None]:
        if not contract_id and not contract_hash:
            raise ValueError("contract_id or contract_hash is required")
        clauses = []
        params: list[str] = []
        if contract_id:
            clauses.append("contract_id = ?")
            params.append(contract_id)
        if contract_hash:
            clauses.append("contract_hash = ?")
            params.append(contract_hash)
        row = self.conn.execute(
            f"""
            SELECT contract_hash, contract_id, version, agent_name, agent_version,
                   registered_entry_id, created_at
            FROM contracts
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC
            LIMIT 1
            """,
            params,
        ).fetchone()
        contract = dict(row) if row else None
        return (
            contract,
            contract_id or (contract.get("contract_id") if contract else None),
            contract_hash or (contract.get("contract_hash") if contract else None),
        )

    def _contract_scope_clause(
        self,
        contract_id: str | None,
        contract_hash: str | None,
        *,
        id_column: str | None = "contract_id",
        hash_column: str | None = "contract_hash",
    ) -> tuple[str, list[str]]:
        clauses = []
        params: list[str] = []
        if id_column and contract_id:
            clauses.append(f"{id_column} = ?")
            params.append(contract_id)
        if hash_column and contract_hash:
            clauses.append(f"{hash_column} = ?")
            params.append(contract_hash)
        if not clauses:
            return "1 = 0", []
        return "(" + " OR ".join(clauses) + ")", params

    def _scoped_rows(
        self,
        *,
        table: str,
        select_sql: str,
        order_sql: str,
        contract_id: str | None,
        contract_hash: str | None,
        limit: int,
        id_column: str | None = "contract_id",
        hash_column: str | None = "contract_hash",
    ) -> tuple[int, list[dict[str, Any]]]:
        clause, params = self._contract_scope_clause(
            contract_id,
            contract_hash,
            id_column=id_column,
            hash_column=hash_column,
        )
        count = self.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {clause}", params).fetchone()["count"]
        rows = self.conn.execute(
            f"{select_sql} WHERE {clause} {order_sql} LIMIT ?",
            [*params, limit],
        ).fetchall()
        return count, [dict(row) for row in rows]

    def contract_evidence(
        self,
        *,
        contract_id: str | None = None,
        contract_hash: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        contract, resolved_id, resolved_hash = self._resolve_contract_scope(contract_id, contract_hash)
        counts: dict[str, int] = {"contracts": 1 if contract else 0}

        count, chain_entries = self._scoped_rows(
            table="chain_entries",
            select_sql="""
            SELECT entry_id, idx, tenant_id, entry_type, timestamp,
                   contract_hash, payload_hash
            FROM chain_entries
            """,
            order_sql="ORDER BY idx DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["chain_entries"] = count

        count, eval_runs = self._scoped_rows(
            table="eval_runs",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, results_hash, evaluated_at
            FROM eval_runs
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["eval_runs"] = count

        count, gate_decisions = self._scoped_rows(
            table="gate_decisions",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, outcome, passed, eval_entry_id,
                   contract_entry_id, results_hash, check_count,
                   failed_check_count, holdout_passed, approvals_passed,
                   evaluated_at
            FROM gate_decisions
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["gate_decisions"] = count
        gate_decisions = [_bool_fields(item, "passed", "holdout_passed", "approvals_passed") for item in gate_decisions]

        count, proof_packs = self._scoped_rows(
            table="proof_packs",
            select_sql="""
            SELECT pack_id, contract_id, contract_hash, agent_name,
                   agent_version, outcome, issued_at, path
            FROM proof_packs
            """,
            order_sql="ORDER BY issued_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["proof_packs"] = count

        count, ingest_events = self._scoped_rows(
            table="ingest_events",
            select_sql="""
            SELECT entry_id, event_hash, contract_hash, trace_id, span_id,
                   parent_span_id, event_name, agent_name, agent_version,
                   risk_class, schema_url, observed_at, attributes_json
            FROM ingest_events
            """,
            order_sql="ORDER BY observed_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["ingest_events"] = count
        for item in ingest_events:
            item["attributes"] = _decode_json_object(item.pop("attributes_json", None))

        count, promotion_statuses = self._scoped_rows(
            table="promotion_statuses",
            select_sql="""
            SELECT receipt_id, provider, pack_id, contract_id, contract_hash,
                   agent_name, agent_version, gate_outcome, passed,
                   provider_status_kind, provider_status_success,
                   target_ref_json, violation_count, attested_at
            FROM promotion_statuses
            """,
            order_sql="ORDER BY attested_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["promotion_statuses"] = count
        for item in promotion_statuses:
            _bool_fields(item, "passed", "provider_status_success")
            item["target_ref"] = _decode_json_object(item.pop("target_ref_json", None))

        count, runtime_attestations = self._scoped_rows(
            table="runtime_attestations",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, action_hash,
                   action_id, action_type, risk_class, passed, outcome,
                   check_count, failed_check_count, attested_at
            FROM runtime_attestations
            """,
            order_sql="ORDER BY attested_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["runtime_attestations"] = count
        runtime_attestations = [_bool_fields(item, "passed") for item in runtime_attestations]

        count, policy_decisions = self._scoped_rows(
            table="policy_decisions",
            select_sql="""
            SELECT entry_id, policy_pack_id, policy_pack_version,
                   policy_pack_hash, contract_hash, action_hash, passed,
                   outcome, matched_rule_count, check_count,
                   failed_check_count, evaluated_at
            FROM policy_decisions
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["policy_decisions"] = count
        policy_decisions = [_bool_fields(item, "passed") for item in policy_decisions]

        count, policy_engine_receipts = self._scoped_rows(
            table="policy_engine_receipts",
            select_sql="""
            SELECT receipt_id, entry_id, engine_name, engine_mode,
                   policy_pack_id, policy_pack_version, policy_pack_hash,
                   action_hash, action_id, action_type, risk_class,
                   pack_id, contract_id, contract_hash, decision_entry_id,
                   decision_outcome, decision_passed, evaluated_at
            FROM policy_engine_receipts
            """,
            order_sql="ORDER BY evaluated_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
        )
        counts["policy_engine_receipts"] = count
        policy_engine_receipts = [_bool_fields(item, "decision_passed") for item in policy_engine_receipts]

        count, incidents = self._scoped_rows(
            table="incidents",
            select_sql="""
            SELECT incident_id, entry_id, contract_hash, agent_name,
                   agent_version, severity, summary, detected_at
            FROM incidents
            """,
            order_sql="ORDER BY detected_at DESC",
            contract_id=resolved_id,
            contract_hash=resolved_hash,
            limit=limit,
            id_column=None,
        )
        counts["incidents"] = count

        return {
            "scope": {"contract_id": resolved_id, "contract_hash": resolved_hash},
            "contract": contract,
            "counts": counts,
            "chain_entries": chain_entries,
            "eval_runs": eval_runs,
            "gate_decisions": gate_decisions,
            "proof_packs": proof_packs,
            "ingest_events": ingest_events,
            "promotion_statuses": promotion_statuses,
            "runtime_attestations": runtime_attestations,
            "policy_decisions": policy_decisions,
            "policy_engine_receipts": policy_engine_receipts,
            "incidents": incidents,
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



