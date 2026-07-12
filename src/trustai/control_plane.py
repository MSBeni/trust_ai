from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .canonical import content_hash, utc_now
from .chain import EvidenceChain
from .cicd import PROMOTION_STATUS_ENTRY_TYPE
from .contracts import CONTRACT_ENTRY_TYPE
from .external_evidence import (
    AUTHORITY_KIND_EVIDENCE_HINTS,
    AUTHORITY_KIND_OWNER_HINTS,
    EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE,
    EXTERNAL_EVIDENCE_ENTRY_TYPE,
)
from .gate import EVAL_ENTRY_TYPE, GATE_ENTRY_TYPE
from .phase_scoreboard import PHASE_SCOREBOARD_ENTRY_TYPE
from .ingest import INGEST_ENTRY_TYPE
from .lifecycle import INCIDENT_ENTRY_TYPE
from .policy import POLICY_DECISION_ENTRY_TYPE
from .policy_engine import POLICY_ENGINE_ENTRY_TYPE
from .proofpack import PROOF_PACK_SPEC_VERSION
from .registry import AGENT_INVENTORY_ENTRY_TYPE
from .roadmap_audit import ROADMAP_AUDIT_ENTRY_TYPE
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


def _decode_json_array(value: Any) -> list[Any]:
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return decoded if isinstance(decoded, list) else []


def _is_authority_dossier_payload(entry: dict[str, Any], payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if not payload.get("dossier_id") or not payload.get("authority_ref"):
        return False
    if not isinstance(payload.get("summary"), dict):
        return False
    if not isinstance(payload.get("authority_evidence"), list):
        return False
    entry_type = str(entry.get("entry_type") or "")
    return "authority" in entry_type or str(payload.get("mode") or "").endswith("dossier")


def _authority_freshness_window_count(evidence_items: list[Any]) -> int:
    return sum(
        1
        for item in evidence_items
        if isinstance(item, dict) and item.get("issued_at") and item.get("expires_at")
    )


def _decode_string_list_map(value: Any) -> dict[str, list[str]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    if not isinstance(value, dict):
        return {}
    result: dict[str, list[str]] = {}
    for key, raw_items in value.items():
        if not isinstance(raw_items, list):
            continue
        items = sorted(str(item) for item in raw_items if item)
        if items:
            result[str(key)] = items
    return {key: result[key] for key in sorted(result)}


def _count_items_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return {value: counts[value] for value in sorted(counts)}


def _authority_gap_units(missing_authority_kinds_by_requirement: dict[str, list[str]]) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    for requirement_id in sorted(missing_authority_kinds_by_requirement):
        for authority_kind in sorted(missing_authority_kinds_by_requirement[requirement_id]):
            unit_id = content_hash({"authority_kind": authority_kind, "requirement_id": requirement_id})
            unit_ref = f"{requirement_id}:{authority_kind}"
            units.append(
                {
                    "unit_id": unit_id,
                    "unit_ref": unit_ref,
                    "task_id": content_hash(
                        {"task_kind": "external-authority-evidence", "unit_id": unit_id, "unit_ref": unit_ref}
                    ),
                    "task_ref": f"external-evidence:{unit_ref}",
                    "requirement_id": requirement_id,
                    "authority_kind": authority_kind,
                    "owner_hint": AUTHORITY_KIND_OWNER_HINTS.get(
                        authority_kind,
                        AUTHORITY_KIND_OWNER_HINTS["other"],
                    ),
                    "suggested_evidence_sources": AUTHORITY_KIND_EVIDENCE_HINTS.get(
                        authority_kind,
                        AUTHORITY_KIND_EVIDENCE_HINTS["other"],
                    ),
                }
            )
    return units


def _external_authority_gap_summary(units: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "missing_authority_unit_count": len(units),
        "gap_count_by_authority_kind": _count_items_by(units, "authority_kind"),
        "gap_count_by_requirement": _count_items_by(units, "requirement_id"),
        "missing_authority_units": units,
    }


def _sqlite_nolock_uri(path: Path) -> str:
    posix_path = path.as_posix()
    if posix_path.startswith("//") and not posix_path.startswith("////"):
        posix_path = "//" + posix_path
    return "file:" + posix_path + "?nolock=1"


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
        return self._configure(sqlite3.connect(_sqlite_nolock_uri(self.path), timeout=2, uri=True))

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
            CREATE TABLE IF NOT EXISTS roadmap_audits (
                audit_id TEXT PRIMARY KEY,
                entry_id TEXT,
                audit_hash TEXT NOT NULL,
                completion_position TEXT,
                requirement_count INTEGER NOT NULL,
                implemented_local_count INTEGER NOT NULL,
                reference_attested_count INTEGER NOT NULL,
                missing_local_evidence_count INTEGER NOT NULL,
                deferred_external_count INTEGER NOT NULL,
                source_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS external_evidence_collection_runs (
                run_id TEXT PRIMARY KEY,
                entry_id TEXT,
                run_hash TEXT NOT NULL,
                source_map_hash TEXT,
                manifest_id TEXT,
                manifest_ref TEXT,
                manifest_hash TEXT,
                audit_id TEXT,
                audit_hash TEXT,
                require_fresh INTEGER NOT NULL,
                require_live_source_uris INTEGER NOT NULL,
                require_source_snapshot_artifacts INTEGER NOT NULL,
                require_fresh_source_snapshot_artifacts INTEGER NOT NULL,
                collected_count INTEGER NOT NULL,
                task_count INTEGER NOT NULL,
                collected_tasks_json TEXT NOT NULL,
                snapshot_ids_json TEXT NOT NULL,
                intake_ids_json TEXT NOT NULL,
                source_plan_json TEXT NOT NULL,
                source_manifest_json TEXT NOT NULL,
                source_roadmap_audit_json TEXT NOT NULL,
                freshness_checked_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS external_evidence_manifests (
                manifest_id TEXT PRIMARY KEY,
                entry_id TEXT,
                manifest_ref TEXT,
                manifest_hash TEXT NOT NULL,
                status TEXT,
                require_complete INTEGER NOT NULL,
                require_fresh INTEGER NOT NULL,
                require_live_source_uris INTEGER NOT NULL,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                required_authority_kind_count INTEGER NOT NULL,
                covered_authority_kind_count INTEGER NOT NULL,
                missing_authority_kind_count INTEGER NOT NULL,
                evidence_count INTEGER NOT NULL,
                fresh_evidence_count INTEGER NOT NULL,
                stale_evidence_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                source_roadmap_audit_json TEXT NOT NULL,
                missing_requirement_ids_json TEXT NOT NULL,
                freshness_checked_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS authority_dossiers (
                dossier_id TEXT PRIMARY KEY,
                entry_id TEXT,
                entry_type TEXT NOT NULL,
                dossier_hash TEXT NOT NULL,
                dossier_ref TEXT,
                mode TEXT,
                environment TEXT,
                authority_ref TEXT,
                producer_ref TEXT,
                production_claimed INTEGER NOT NULL,
                production_ready INTEGER NOT NULL,
                required_requirement_count INTEGER NOT NULL,
                covered_requirement_count INTEGER NOT NULL,
                missing_requirement_count INTEGER NOT NULL,
                authority_evidence_count INTEGER NOT NULL,
                freshness_window_count INTEGER NOT NULL,
                missing_freshness_count INTEGER NOT NULL,
                control_summary_json TEXT NOT NULL,
                covered_requirement_ids_json TEXT NOT NULL,
                missing_requirement_ids_json TEXT NOT NULL,
                generated_at TEXT,
                body_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS phase_scoreboards (
                scoreboard_id TEXT PRIMARY KEY,
                entry_id TEXT,
                scoreboard_hash TEXT NOT NULL,
                scoreboard_ref TEXT,
                mode TEXT,
                environment TEXT,
                milestone_count INTEGER NOT NULL,
                phase_counts_json TEXT NOT NULL,
                control_summary_json TEXT NOT NULL,
                generated_at TEXT,
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
            "roadmap_audits": 0,
            "external_evidence_collection_runs": 0,
            "external_evidence_manifests": 0,
            "authority_dossiers": 0,
            "phase_scoreboards": 0,
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

            if entry.get("entry_type") == ROADMAP_AUDIT_ENTRY_TYPE:
                source = payload.get("source", {}) if isinstance(payload.get("source"), dict) else {}
                limitations = payload.get("limitations", []) if isinstance(payload.get("limitations"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO roadmap_audits(
                        audit_id, entry_id, audit_hash, completion_position,
                        requirement_count, implemented_local_count,
                        reference_attested_count, missing_local_evidence_count,
                        deferred_external_count, source_json, limitations_json,
                        generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("audit_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("audit_hash") or entry.get("payload_hash"),
                        payload.get("completion_position"),
                        int(payload.get("requirement_count") or 0),
                        int(payload.get("implemented_local_count") or 0),
                        int(payload.get("reference_attested_count") or 0),
                        int(payload.get("missing_local_evidence_count") or 0),
                        int(payload.get("deferred_external_count") or 0),
                        _json(source),
                        _json(limitations),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["roadmap_audits"] += 1

            if entry.get("entry_type") == EXTERNAL_EVIDENCE_COLLECTION_RUN_ENTRY_TYPE:
                source_plan = payload.get("source_plan", {}) if isinstance(payload.get("source_plan"), dict) else {}
                source_manifest = payload.get("source_manifest", {}) if isinstance(payload.get("source_manifest"), dict) else {}
                source_audit = payload.get("source_roadmap_audit", {}) if isinstance(payload.get("source_roadmap_audit"), dict) else {}
                collected_tasks = payload.get("collected_tasks", []) if isinstance(payload.get("collected_tasks"), list) else []
                snapshot_ids = payload.get("snapshot_ids", []) if isinstance(payload.get("snapshot_ids"), list) else []
                intake_ids = payload.get("intake_ids", []) if isinstance(payload.get("intake_ids"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO external_evidence_collection_runs(
                        run_id, entry_id, run_hash, source_map_hash, manifest_id,
                        manifest_ref, manifest_hash, audit_id, audit_hash,
                        require_fresh, require_live_source_uris,
                        require_source_snapshot_artifacts,
                        require_fresh_source_snapshot_artifacts, collected_count,
                        task_count, collected_tasks_json, snapshot_ids_json,
                        intake_ids_json, source_plan_json, source_manifest_json,
                        source_roadmap_audit_json, freshness_checked_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("run_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("run_hash") or entry.get("payload_hash"),
                        payload.get("source_map_hash"),
                        source_manifest.get("manifest_id"),
                        source_manifest.get("manifest_ref"),
                        source_manifest.get("manifest_hash"),
                        source_audit.get("audit_id"),
                        source_audit.get("audit_hash"),
                        1 if payload.get("require_fresh") else 0,
                        1 if payload.get("require_live_source_uris") else 0,
                        1 if payload.get("require_source_snapshot_artifacts") else 0,
                        1 if payload.get("require_fresh_source_snapshot_artifacts") else 0,
                        int(payload.get("collected_count") or 0),
                        int(payload.get("task_count") or 0),
                        _json(collected_tasks),
                        _json(snapshot_ids),
                        _json(intake_ids),
                        _json(source_plan),
                        _json(source_manifest),
                        _json(source_audit),
                        payload.get("freshness_checked_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["external_evidence_collection_runs"] += 1

            if entry.get("entry_type") == EXTERNAL_EVIDENCE_ENTRY_TYPE:
                source_audit = payload.get("source_roadmap_audit", {}) if isinstance(payload.get("source_roadmap_audit"), dict) else {}
                missing_ids = payload.get("missing_requirement_ids", []) if isinstance(payload.get("missing_requirement_ids"), list) else []
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO external_evidence_manifests(
                        manifest_id, entry_id, manifest_ref, manifest_hash, status,
                        require_complete, require_fresh, require_live_source_uris,
                        required_requirement_count, covered_requirement_count,
                        missing_requirement_count, required_authority_kind_count,
                        covered_authority_kind_count, missing_authority_kind_count,
                        evidence_count, fresh_evidence_count, stale_evidence_count,
                        missing_freshness_count, source_roadmap_audit_json,
                        missing_requirement_ids_json, freshness_checked_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("manifest_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("manifest_ref"),
                        payload.get("manifest_hash") or entry.get("payload_hash"),
                        payload.get("status"),
                        1 if payload.get("require_complete") else 0,
                        1 if payload.get("require_fresh") else 0,
                        1 if payload.get("require_live_source_uris") else 0,
                        int(payload.get("required_requirement_count") or 0),
                        int(payload.get("covered_requirement_count") or 0),
                        int(payload.get("missing_requirement_count") or 0),
                        int(payload.get("required_authority_kind_count") or 0),
                        int(payload.get("covered_authority_kind_count") or 0),
                        int(payload.get("missing_authority_kind_count") or 0),
                        int(payload.get("evidence_count") or 0),
                        int(payload.get("fresh_evidence_count") or 0),
                        int(payload.get("stale_evidence_count") or 0),
                        int(payload.get("missing_freshness_count") or 0),
                        _json(source_audit),
                        _json(missing_ids),
                        payload.get("freshness_checked_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["external_evidence_manifests"] += 1

            if entry.get("entry_type") == PHASE_SCOREBOARD_ENTRY_TYPE:
                phase_counts = payload.get("phase_counts") if isinstance(payload.get("phase_counts"), dict) else {}
                control_summary = payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO phase_scoreboards(
                        scoreboard_id, entry_id, scoreboard_hash, scoreboard_ref,
                        mode, environment, milestone_count, phase_counts_json,
                        control_summary_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("scoreboard_id") or entry["entry_id"],
                        entry["entry_id"],
                        payload.get("scoreboard_hash") or entry.get("payload_hash"),
                        payload.get("scoreboard_ref"),
                        payload.get("mode"),
                        payload.get("environment"),
                        int(payload.get("milestone_count") or 0),
                        _json(phase_counts),
                        _json(control_summary),
                        entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["phase_scoreboards"] += 1

            if _is_authority_dossier_payload(entry, payload):
                summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
                evidence_items = (
                    payload.get("authority_evidence") if isinstance(payload.get("authority_evidence"), list) else []
                )
                control_summary = (
                    payload.get("control_summary") if isinstance(payload.get("control_summary"), dict) else {}
                )
                covered_ids = (
                    summary.get("covered_requirement_ids")
                    if isinstance(summary.get("covered_requirement_ids"), list)
                    else []
                )
                missing_ids = (
                    summary.get("missing_requirement_ids")
                    if isinstance(summary.get("missing_requirement_ids"), list)
                    else []
                )
                evidence_count = int(summary.get("authority_evidence_count") or len(evidence_items))
                freshness_window_count = int(
                    summary.get("freshness_window_count") or _authority_freshness_window_count(evidence_items)
                )
                missing_freshness_count = int(
                    summary.get("missing_freshness_count") or max(evidence_count - freshness_window_count, 0)
                )
                missing_requirement_count = int(summary.get("missing_requirement_count") or 0)
                production_claimed = payload.get("mode") == "production-dossier"
                production_ready = production_claimed and missing_requirement_count == 0 and missing_freshness_count == 0
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO authority_dossiers(
                        dossier_id, entry_id, entry_type, dossier_hash, dossier_ref,
                        mode, environment, authority_ref, producer_ref,
                        production_claimed, production_ready,
                        required_requirement_count, covered_requirement_count,
                        missing_requirement_count, authority_evidence_count,
                        freshness_window_count, missing_freshness_count,
                        control_summary_json, covered_requirement_ids_json,
                        missing_requirement_ids_json, generated_at, body_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.get("dossier_id"),
                        entry["entry_id"],
                        entry.get("entry_type"),
                        payload.get("dossier_hash") or entry.get("payload_hash"),
                        payload.get("dossier_ref"),
                        payload.get("mode"),
                        payload.get("environment"),
                        payload.get("authority_ref"),
                        payload.get("producer_ref"),
                        1 if production_claimed else 0,
                        1 if production_ready else 0,
                        int(summary.get("required_requirement_count") or 0),
                        int(summary.get("covered_requirement_count") or 0),
                        missing_requirement_count,
                        evidence_count,
                        freshness_window_count,
                        missing_freshness_count,
                        _json(control_summary),
                        _json(covered_ids),
                        _json(missing_ids),
                        payload.get("generated_at") or entry.get("timestamp"),
                        _json(payload),
                    ),
                )
                counts["authority_dossiers"] += 1
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
            "roadmap_audits",
            "external_evidence_collection_runs",
            "external_evidence_manifests",
            "authority_dossiers",
            "phase_scoreboards",
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
        latest_roadmap_audit = self.conn.execute(
            """
            SELECT audit_id, audit_hash, completion_position, requirement_count,
                   implemented_local_count, reference_attested_count,
                   missing_local_evidence_count, deferred_external_count,
                   generated_at
            FROM roadmap_audits
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_collection_run = self.conn.execute(
            """
            SELECT run_id, run_hash, source_map_hash, manifest_ref,
                   manifest_hash, audit_id, audit_hash, require_fresh,
                   require_live_source_uris, require_source_snapshot_artifacts,
                   require_fresh_source_snapshot_artifacts, collected_count,
                   task_count, freshness_checked_at
            FROM external_evidence_collection_runs
            ORDER BY freshness_checked_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_collection_run_dict = dict(latest_collection_run) if latest_collection_run else None
        if latest_collection_run_dict is not None:
            _bool_fields(
                latest_collection_run_dict,
                "require_fresh",
                "require_live_source_uris",
                "require_source_snapshot_artifacts",
                "require_fresh_source_snapshot_artifacts",
            )
        latest_external_evidence = self.conn.execute(
            """
            SELECT manifest_id, manifest_ref, status, require_complete,
                   require_fresh, require_live_source_uris,
                   covered_requirement_count, required_requirement_count,
                   missing_requirement_count, covered_authority_kind_count,
                   required_authority_kind_count, missing_authority_kind_count,
                   freshness_checked_at
            FROM external_evidence_manifests
            ORDER BY freshness_checked_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_external_evidence_dict = dict(latest_external_evidence) if latest_external_evidence else None
        if latest_external_evidence_dict is not None:
            _bool_fields(latest_external_evidence_dict, "require_complete", "require_fresh", "require_live_source_uris")
        latest_authority_dossier = self.conn.execute(
            """
            SELECT dossier_id, entry_type, dossier_ref, mode, environment,
                   authority_ref, producer_ref, production_claimed,
                   production_ready, covered_requirement_count,
                   required_requirement_count, missing_requirement_count,
                   authority_evidence_count, freshness_window_count,
                   missing_freshness_count, generated_at
            FROM authority_dossiers
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_authority_dossier_dict = dict(latest_authority_dossier) if latest_authority_dossier else None
        if latest_authority_dossier_dict is not None:
            _bool_fields(latest_authority_dossier_dict, "production_claimed", "production_ready")
        latest_phase_scoreboard = self.conn.execute(
            """
            SELECT scoreboard_id, scoreboard_hash, scoreboard_ref, mode,
                   environment, milestone_count, phase_counts_json,
                   control_summary_json, generated_at
            FROM phase_scoreboards
            ORDER BY generated_at DESC
            LIMIT 1
            """
        ).fetchone()
        latest_phase_scoreboard_dict = dict(latest_phase_scoreboard) if latest_phase_scoreboard else None
        if latest_phase_scoreboard_dict is not None:
            latest_phase_scoreboard_dict["phase_counts"] = _decode_json_object(latest_phase_scoreboard_dict.pop("phase_counts_json", None))
            latest_phase_scoreboard_dict["control_summary"] = _decode_json_object(latest_phase_scoreboard_dict.pop("control_summary_json", None))
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
            "latest_roadmap_audit": dict(latest_roadmap_audit) if latest_roadmap_audit else None,
            "latest_external_evidence_collection_run": latest_collection_run_dict,
            "latest_external_evidence_manifest": latest_external_evidence_dict,
            "latest_authority_dossier": latest_authority_dossier_dict,
            "latest_phase_scoreboard": latest_phase_scoreboard_dict,
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

    def recent_roadmap_audits(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT audit_id, entry_id, audit_hash, completion_position,
                   requirement_count, implemented_local_count,
                   reference_attested_count, missing_local_evidence_count,
                   deferred_external_count, source_json, limitations_json,
                   generated_at
            FROM roadmap_audits
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["source"] = _decode_json_object(item.pop("source_json", None))
            item["limitations"] = _decode_json_array(item.pop("limitations_json", None))
            items.append(item)
        return items

    def recent_external_evidence_collection_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT run_id, entry_id, run_hash, source_map_hash, manifest_id,
                   manifest_ref, manifest_hash, audit_id, audit_hash,
                   require_fresh, require_live_source_uris,
                   require_source_snapshot_artifacts,
                   require_fresh_source_snapshot_artifacts, collected_count,
                   task_count, collected_tasks_json, snapshot_ids_json,
                   intake_ids_json, source_plan_json, source_manifest_json,
                   source_roadmap_audit_json, freshness_checked_at
            FROM external_evidence_collection_runs
            ORDER BY freshness_checked_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(
                item,
                "require_fresh",
                "require_live_source_uris",
                "require_source_snapshot_artifacts",
                "require_fresh_source_snapshot_artifacts",
            )
            item["collected_tasks"] = _decode_json_array(item.pop("collected_tasks_json", None))
            item["snapshot_ids"] = _decode_json_array(item.pop("snapshot_ids_json", None))
            item["intake_ids"] = _decode_json_array(item.pop("intake_ids_json", None))
            item["source_plan"] = _decode_json_object(item.pop("source_plan_json", None))
            item["source_manifest"] = _decode_json_object(item.pop("source_manifest_json", None))
            item["source_roadmap_audit"] = _decode_json_object(item.pop("source_roadmap_audit_json", None))
            items.append(item)
        return items

    def recent_external_evidence_manifests(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT manifest_id, entry_id, manifest_ref, manifest_hash, status,
                   require_complete, require_fresh, require_live_source_uris,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, required_authority_kind_count,
                   covered_authority_kind_count, missing_authority_kind_count,
                   evidence_count, fresh_evidence_count, stale_evidence_count,
                   missing_freshness_count, source_roadmap_audit_json,
                   missing_requirement_ids_json, freshness_checked_at, body_json
            FROM external_evidence_manifests
            ORDER BY freshness_checked_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "require_complete", "require_fresh", "require_live_source_uris")
            item["source_roadmap_audit"] = _decode_json_object(item.pop("source_roadmap_audit_json", None))
            try:
                missing_ids = json.loads(item.pop("missing_requirement_ids_json", "[]"))
            except (TypeError, json.JSONDecodeError):
                missing_ids = []
            item["missing_requirement_ids"] = missing_ids if isinstance(missing_ids, list) else []
            payload = _decode_json_object(item.pop("body_json", None))
            covered_authority_kinds = _decode_string_list_map(payload.get("covered_authority_kinds_by_requirement"))
            missing_authority_kinds = _decode_string_list_map(payload.get("missing_authority_kinds_by_requirement"))
            missing_units = _authority_gap_units(missing_authority_kinds)
            item["covered_authority_kinds_by_requirement"] = covered_authority_kinds
            item["missing_authority_kinds_by_requirement"] = missing_authority_kinds
            item["missing_authority_units"] = missing_units
            item["external_authority_gap_summary"] = _external_authority_gap_summary(missing_units)
            items.append(item)
        return items

    def external_authority_gaps(
        self,
        *,
        authority_kind: str | None = None,
        requirement_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        if limit is not None and limit < 1:
            raise ValueError("limit must be a positive integer")
        manifests = self.recent_external_evidence_manifests(1)
        if not manifests:
            units: list[dict[str, Any]] = []
            selected_units: list[dict[str, Any]] = []
            returned_units: list[dict[str, Any]] = []
            latest_manifest = None
        else:
            latest_manifest = manifests[0]
            units = list(latest_manifest.get("missing_authority_units") or [])
            selected_units = [
                unit
                for unit in units
                if (authority_kind is None or unit.get("authority_kind") == authority_kind)
                and (requirement_id is None or unit.get("requirement_id") == requirement_id)
            ]
            returned_units = selected_units[:limit] if limit is not None else selected_units
        return {
            "schema_version": SCHEMA_VERSION,
            "filters": {
                "authority_kind": authority_kind,
                "requirement_id": requirement_id,
                "limit": limit,
            },
            "latest_external_evidence_manifest": latest_manifest,
            "summary": {
                "total_missing_authority_unit_count": len(units),
                "selected_missing_authority_unit_count": len(selected_units),
                "returned_missing_authority_unit_count": len(returned_units),
                "gap_count_by_authority_kind": _count_items_by(selected_units, "authority_kind"),
                "gap_count_by_requirement": _count_items_by(selected_units, "requirement_id"),
            },
            "missing_authority_units": returned_units,
        }

    def recent_phase_scoreboards(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT scoreboard_id, entry_id, scoreboard_hash, scoreboard_ref,
                   mode, environment, milestone_count, phase_counts_json,
                   control_summary_json, generated_at
            FROM phase_scoreboards
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["phase_counts"] = _decode_json_object(item.pop("phase_counts_json", None))
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            items.append(item)
        return items

    def recent_authority_dossiers(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT dossier_id, entry_id, entry_type, dossier_hash, dossier_ref,
                   mode, environment, authority_ref, producer_ref,
                   production_claimed, production_ready,
                   required_requirement_count, covered_requirement_count,
                   missing_requirement_count, authority_evidence_count,
                   freshness_window_count, missing_freshness_count,
                   control_summary_json, covered_requirement_ids_json,
                   missing_requirement_ids_json, generated_at
            FROM authority_dossiers
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            _bool_fields(item, "production_claimed", "production_ready")
            item["control_summary"] = _decode_json_object(item.pop("control_summary_json", None))
            item["covered_requirement_ids"] = _decode_json_array(item.pop("covered_requirement_ids_json", None))
            item["missing_requirement_ids"] = _decode_json_array(item.pop("missing_requirement_ids_json", None))
            items.append(item)
        return items

    def roadmap_evidence(self, limit: int = 20) -> dict[str, Any]:
        return {
            "roadmap_audits": self.recent_roadmap_audits(limit),
            "external_evidence_collection_runs": self.recent_external_evidence_collection_runs(limit),
            "external_evidence_manifests": self.recent_external_evidence_manifests(limit),
            "phase_scoreboards": self.recent_phase_scoreboards(limit),
        }

    def readiness(self) -> dict[str, Any]:
        summary = self.summary()
        blockers: list[str] = []

        latest_roadmap_audit = summary.get("latest_roadmap_audit")
        missing_local = int((latest_roadmap_audit or {}).get("missing_local_evidence_count") or 0)
        deferred_external = int((latest_roadmap_audit or {}).get("deferred_external_count") or 0)
        local_reference_complete = latest_roadmap_audit is not None and missing_local == 0
        if latest_roadmap_audit is None:
            blockers.append("no roadmap audit indexed")
        elif missing_local:
            blockers.append(f"local roadmap evidence incomplete: {missing_local} requirement(s) missing local evidence")

        latest_external_manifest = summary.get("latest_external_evidence_manifest")
        latest_external_manifest_details = self.recent_external_evidence_manifests(1)
        if latest_external_manifest_details:
            latest_external_manifest = latest_external_manifest_details[0]
        external_gap_summary = (latest_external_manifest or {}).get("external_authority_gap_summary") or _external_authority_gap_summary([])
        external_missing_requirements = int((latest_external_manifest or {}).get("missing_requirement_count") or 0)
        external_missing_authority_kinds = int((latest_external_manifest or {}).get("missing_authority_kind_count") or 0)
        external_missing_freshness = int((latest_external_manifest or {}).get("missing_freshness_count") or 0)
        external_manifest_strict = bool(
            latest_external_manifest
            and latest_external_manifest.get("require_complete")
            and latest_external_manifest.get("require_fresh")
            and latest_external_manifest.get("require_live_source_uris")
        )
        external_authority_complete = bool(
            latest_external_manifest
            and latest_external_manifest.get("status") == "complete"
            and external_missing_requirements == 0
            and external_missing_authority_kinds == 0
            and external_missing_freshness == 0
            and external_manifest_strict
        )
        if latest_external_manifest is None:
            blockers.append("no external-evidence manifest indexed")
        else:
            if external_missing_requirements or external_missing_authority_kinds or external_missing_freshness:
                blockers.append(
                    "external authority evidence incomplete: "
                    f"{external_missing_requirements} requirement(s), "
                    f"{external_gap_summary['missing_authority_unit_count']} authority unit(s), "
                    f"{external_missing_freshness} freshness window(s) missing"
                )
            if not external_manifest_strict:
                blockers.append("latest external-evidence manifest was not generated with strict complete, fresh, live-source URI requirements")

        latest_collection_run = summary.get("latest_external_evidence_collection_run")
        collection_run_present = latest_collection_run is not None
        collection_collected = int((latest_collection_run or {}).get("collected_count") or 0)
        collection_tasks = int((latest_collection_run or {}).get("task_count") or 0)
        collection_run_strict = bool(
            latest_collection_run
            and latest_collection_run.get("require_fresh")
            and latest_collection_run.get("require_live_source_uris")
            and latest_collection_run.get("require_source_snapshot_artifacts")
            and latest_collection_run.get("require_fresh_source_snapshot_artifacts")
        )
        collection_run_complete = bool(
            collection_run_present
            and collection_run_strict
            and collection_tasks > 0
            and collection_collected >= collection_tasks
        )
        if latest_collection_run is None:
            blockers.append("no retained external-evidence collection run indexed")
        else:
            if collection_collected < collection_tasks:
                blockers.append(
                    "latest external-evidence collection run incomplete: "
                    f"{collection_collected}/{collection_tasks} task(s) collected"
                )
            if not collection_run_strict:
                blockers.append("latest external-evidence collection run was not collected with strict source snapshot and freshness checks")

        latest_phase_scoreboard = summary.get("latest_phase_scoreboard")
        phase_control_summary = (latest_phase_scoreboard or {}).get("control_summary") or {}
        phase_external_required = int(phase_control_summary.get("external-required") or 0)
        phase_scoreboard_present = latest_phase_scoreboard is not None
        phase_scoreboard_ready = bool(
            latest_phase_scoreboard
            and latest_phase_scoreboard.get("mode") == "external-evidence"
            and phase_external_required == 0
        )
        phase_scoreboard_summary = {
            "present": phase_scoreboard_present,
            "mode": (latest_phase_scoreboard or {}).get("mode"),
            "milestone_count": int((latest_phase_scoreboard or {}).get("milestone_count") or 0),
            "phase_counts": (latest_phase_scoreboard or {}).get("phase_counts") or {},
            "control_summary": phase_control_summary,
            "external_required_control_count": phase_external_required,
        }
        if latest_phase_scoreboard is None:
            blockers.append("no roadmap phase scoreboard indexed")
        elif not phase_scoreboard_ready:
            blockers.append(
                "roadmap phase scoreboard milestones incomplete: "
                f"mode={latest_phase_scoreboard.get('mode')}, "
                f"external-required control(s)={phase_external_required}"
            )

        authority_row = self.conn.execute(
            """
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN production_claimed THEN 1 ELSE 0 END), 0) AS production_claimed,
                   COALESCE(SUM(CASE WHEN production_ready THEN 1 ELSE 0 END), 0) AS production_ready,
                   COALESCE(SUM(CASE WHEN production_ready THEN 0 ELSE 1 END), 0) AS not_ready,
                   COALESCE(SUM(missing_requirement_count), 0) AS missing_requirement_count,
                   COALESCE(SUM(missing_freshness_count), 0) AS missing_freshness_count
            FROM authority_dossiers
            """
        ).fetchone()
        authority_dossier_summary = {
            "total": int(authority_row["total"] or 0),
            "production_claimed": int(authority_row["production_claimed"] or 0),
            "production_ready": int(authority_row["production_ready"] or 0),
            "not_ready": int(authority_row["not_ready"] or 0),
            "missing_requirement_count": int(authority_row["missing_requirement_count"] or 0),
            "missing_freshness_count": int(authority_row["missing_freshness_count"] or 0),
        }
        production_authority_ready = bool(
            authority_dossier_summary["total"] > 0 and authority_dossier_summary["not_ready"] == 0
        )
        if authority_dossier_summary["total"] == 0:
            blockers.append("no production authority dossiers indexed")
        elif authority_dossier_summary["not_ready"]:
            blockers.append(
                "production authority dossiers are not ready: "
                f"{authority_dossier_summary['not_ready']}/{authority_dossier_summary['total']} dossier(s) incomplete"
            )

        latest_gate_decision = summary.get("latest_gate_decision")
        promotion_gate_ready = bool(latest_gate_decision and latest_gate_decision.get("passed"))
        if not promotion_gate_ready:
            blockers.append("no passed promotion gate decision indexed")

        latest_proof_pack = summary.get("latest_proof_pack")
        proof_pack_ready = bool(latest_proof_pack and latest_proof_pack.get("outcome") == "passed")
        if not proof_pack_ready:
            blockers.append("no passed proof pack indexed")

        latest_runtime_attestation = summary.get("latest_runtime_attestation")
        latest_policy_decision = summary.get("latest_policy_decision")
        latest_policy_engine_receipt = summary.get("latest_policy_engine_receipt")
        runtime_policy_ready = bool(
            latest_runtime_attestation
            and latest_runtime_attestation.get("passed")
            and latest_policy_decision
            and latest_policy_decision.get("passed")
            and latest_policy_engine_receipt
            and latest_policy_engine_receipt.get("decision_passed")
        )
        if not runtime_policy_ready:
            blockers.append("runtime attestation and policy-engine evidence are not both passing")

        ready = all(
            [
                local_reference_complete,
                external_authority_complete,
                collection_run_complete,
                production_authority_ready,
                phase_scoreboard_ready,
                promotion_gate_ready,
                proof_pack_ready,
                runtime_policy_ready,
            ]
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "ready" if ready else "not_ready",
            "local_reference_complete": local_reference_complete,
            "external_authority_complete": external_authority_complete,
            "collection_run_present": collection_run_present,
            "collection_run_complete": collection_run_complete,
            "production_authority_ready": production_authority_ready,
            "roadmap_phase_scoreboard_ready": phase_scoreboard_ready,
            "promotion_gate_ready": promotion_gate_ready,
            "proof_pack_ready": proof_pack_ready,
            "runtime_policy_ready": runtime_policy_ready,
            "counts": summary["counts"],
            "latest_roadmap_audit": latest_roadmap_audit,
            "latest_external_evidence_manifest": latest_external_manifest,
            "latest_external_evidence_collection_run": latest_collection_run,
            "latest_authority_dossier": summary.get("latest_authority_dossier"),
            "latest_phase_scoreboard": latest_phase_scoreboard,
            "phase_scoreboard_summary": phase_scoreboard_summary,
            "authority_dossier_summary": authority_dossier_summary,
            "external_authority_gap_summary": external_gap_summary,
            "remaining_external_evidence_count": deferred_external,
            "blockers": blockers,
        }

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

    def _agent_scope_clause(
        self,
        agent_name: str,
        agent_version: str | None,
        *,
        name_column: str = "agent_name",
        version_column: str = "agent_version",
    ) -> tuple[str, list[str]]:
        clauses = [f"{name_column} = ?"]
        params = [agent_name]
        if agent_version:
            clauses.append(f"{version_column} = ?")
            params.append(agent_version)
        return "(" + " AND ".join(clauses) + ")", params

    def _agent_scoped_rows(
        self,
        *,
        table: str,
        select_sql: str,
        order_sql: str,
        agent_name: str,
        agent_version: str | None,
        limit: int,
        name_column: str = "agent_name",
        version_column: str = "agent_version",
    ) -> tuple[int, list[dict[str, Any]]]:
        clause, params = self._agent_scope_clause(
            agent_name,
            agent_version,
            name_column=name_column,
            version_column=version_column,
        )
        count = self.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {clause}", params).fetchone()["count"]
        rows = self.conn.execute(
            f"{select_sql} WHERE {clause} {order_sql} LIMIT ?",
            [*params, limit],
        ).fetchall()
        return count, [dict(row) for row in rows]

    def _agent_contract_hashes(self, agent_name: str, agent_version: str | None) -> list[str]:
        hashes: list[str] = []
        sources = [
            ("contracts", "agent_name", "agent_version"),
            ("eval_runs", "agent_name", "agent_version"),
            ("gate_decisions", "agent_name", "agent_version"),
            ("proof_packs", "agent_name", "agent_version"),
            ("ingest_events", "agent_name", "agent_version"),
            ("promotion_statuses", "agent_name", "agent_version"),
            ("incidents", "agent_name", "agent_version"),
        ]
        for table, name_column, version_column in sources:
            clause, params = self._agent_scope_clause(
                agent_name,
                agent_version,
                name_column=name_column,
                version_column=version_column,
            )
            rows = self.conn.execute(
                f"SELECT DISTINCT contract_hash FROM {table} WHERE {clause} AND contract_hash IS NOT NULL",
                params,
            ).fetchall()
            hashes.extend(row["contract_hash"] for row in rows if row["contract_hash"])
        return list(dict.fromkeys(hashes))

    def _hash_scope_clause(self, hashes: list[str], *, hash_column: str = "contract_hash") -> tuple[str, list[str]]:
        unique_hashes = [value for value in dict.fromkeys(hashes) if value]
        if not unique_hashes:
            return "1 = 0", []
        placeholders = ", ".join("?" for _ in unique_hashes)
        return f"{hash_column} IN ({placeholders})", unique_hashes

    def _hash_scoped_rows(
        self,
        *,
        table: str,
        select_sql: str,
        order_sql: str,
        hashes: list[str],
        limit: int,
        hash_column: str = "contract_hash",
    ) -> tuple[int, list[dict[str, Any]]]:
        clause, params = self._hash_scope_clause(hashes, hash_column=hash_column)
        count = self.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {clause}", params).fetchone()["count"]
        rows = self.conn.execute(
            f"{select_sql} WHERE {clause} {order_sql} LIMIT ?",
            [*params, limit],
        ).fetchall()
        return count, [dict(row) for row in rows]

    def agent_evidence(
        self,
        *,
        agent_name: str | None,
        agent_version: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        if not agent_name:
            raise ValueError("agent_name is required")
        counts: dict[str, int] = {}

        count, agents = self._agent_scoped_rows(
            table="agents",
            select_sql="""
            SELECT name, version, owner, risk_class, governed, source, observed_at
            FROM agents
            """,
            order_sql="ORDER BY observed_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
            name_column="name",
            version_column="version",
        )
        counts["agents"] = count
        agents = [_bool_fields(item, "governed") for item in agents]

        count, contracts = self._agent_scoped_rows(
            table="contracts",
            select_sql="""
            SELECT contract_hash, contract_id, version, agent_name, agent_version,
                   registered_entry_id, created_at
            FROM contracts
            """,
            order_sql="ORDER BY created_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["contracts"] = count
        contract_hashes = self._agent_contract_hashes(agent_name, agent_version)

        count, chain_entries = self._hash_scoped_rows(
            table="chain_entries",
            select_sql="""
            SELECT entry_id, idx, tenant_id, entry_type, timestamp,
                   contract_hash, payload_hash
            FROM chain_entries
            """,
            order_sql="ORDER BY idx DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["chain_entries"] = count

        count, eval_runs = self._agent_scoped_rows(
            table="eval_runs",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, agent_name,
                   agent_version, results_hash, evaluated_at
            FROM eval_runs
            """,
            order_sql="ORDER BY evaluated_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["eval_runs"] = count

        count, gate_decisions = self._agent_scoped_rows(
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
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["gate_decisions"] = count
        gate_decisions = [_bool_fields(item, "passed", "holdout_passed", "approvals_passed") for item in gate_decisions]

        count, proof_packs = self._agent_scoped_rows(
            table="proof_packs",
            select_sql="""
            SELECT pack_id, contract_id, contract_hash, agent_name,
                   agent_version, outcome, issued_at, path
            FROM proof_packs
            """,
            order_sql="ORDER BY issued_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["proof_packs"] = count

        count, ingest_events = self._agent_scoped_rows(
            table="ingest_events",
            select_sql="""
            SELECT entry_id, event_hash, contract_hash, trace_id, span_id,
                   parent_span_id, event_name, agent_name, agent_version,
                   risk_class, schema_url, observed_at, attributes_json
            FROM ingest_events
            """,
            order_sql="ORDER BY observed_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["ingest_events"] = count
        for item in ingest_events:
            item["attributes"] = _decode_json_object(item.pop("attributes_json", None))

        count, promotion_statuses = self._agent_scoped_rows(
            table="promotion_statuses",
            select_sql="""
            SELECT receipt_id, provider, pack_id, contract_id, contract_hash,
                   agent_name, agent_version, gate_outcome, passed,
                   provider_status_kind, provider_status_success,
                   target_ref_json, violation_count, attested_at
            FROM promotion_statuses
            """,
            order_sql="ORDER BY attested_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["promotion_statuses"] = count
        for item in promotion_statuses:
            _bool_fields(item, "passed", "provider_status_success")
            item["target_ref"] = _decode_json_object(item.pop("target_ref_json", None))

        count, runtime_attestations = self._hash_scoped_rows(
            table="runtime_attestations",
            select_sql="""
            SELECT entry_id, contract_id, contract_hash, action_hash,
                   action_id, action_type, risk_class, passed, outcome,
                   check_count, failed_check_count, attested_at
            FROM runtime_attestations
            """,
            order_sql="ORDER BY attested_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["runtime_attestations"] = count
        runtime_attestations = [_bool_fields(item, "passed") for item in runtime_attestations]

        count, policy_decisions = self._hash_scoped_rows(
            table="policy_decisions",
            select_sql="""
            SELECT entry_id, policy_pack_id, policy_pack_version,
                   policy_pack_hash, contract_hash, action_hash, passed,
                   outcome, matched_rule_count, check_count,
                   failed_check_count, evaluated_at
            FROM policy_decisions
            """,
            order_sql="ORDER BY evaluated_at DESC",
            hashes=contract_hashes,
            limit=limit,
        )
        counts["policy_decisions"] = count
        policy_decisions = [_bool_fields(item, "passed") for item in policy_decisions]

        count, policy_engine_receipts = self._hash_scoped_rows(
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
            hashes=contract_hashes,
            limit=limit,
        )
        counts["policy_engine_receipts"] = count
        policy_engine_receipts = [_bool_fields(item, "decision_passed") for item in policy_engine_receipts]

        count, incidents = self._agent_scoped_rows(
            table="incidents",
            select_sql="""
            SELECT incident_id, entry_id, contract_hash, agent_name,
                   agent_version, severity, summary, detected_at
            FROM incidents
            """,
            order_sql="ORDER BY detected_at DESC",
            agent_name=agent_name,
            agent_version=agent_version,
            limit=limit,
        )
        counts["incidents"] = count

        return {
            "scope": {"agent_name": agent_name, "agent_version": agent_version},
            "contract_hashes": contract_hashes,
            "counts": counts,
            "agents": agents,
            "contracts": contracts,
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



