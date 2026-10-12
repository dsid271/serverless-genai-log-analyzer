"""
SQLite-backed incident store.

Persists incidents (lifecycle status, severity, routing, linked deployments),
analyzer outputs, operator feedback and deployment events. Triage decisions
(grouping, scoring, routing) live in core/triage.py; this module only stores.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional

STATUSES = ("open", "resolved", "false_positive")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id          TEXT PRIMARY KEY,
        kind        TEXT NOT NULL,
        status      TEXT NOT NULL,
        created_at  REAL NOT NULL,
        last_seen   REAL NOT NULL,
        occurrences INTEGER NOT NULL,
        message     TEXT NOT NULL,
        details     TEXT NOT NULL,
        severity    TEXT NOT NULL,
        routing     TEXT NOT NULL,
        deployments TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents (status, last_seen)",
    """
    CREATE TABLE IF NOT EXISTS analyses (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        created_at  REAL NOT NULL,
        analysis    TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS feedback (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id       TEXT NOT NULL,
        created_at        REAL NOT NULL,
        submitted_by      TEXT NOT NULL,
        verdict           TEXT,
        reassign_team     TEXT,
        severity_override TEXT,
        note              TEXT,
        previous          TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS deployments (
        id          TEXT PRIMARY KEY,
        service     TEXT NOT NULL,
        version     TEXT NOT NULL,
        environment TEXT NOT NULL,
        deployed_at REAL NOT NULL,
        commit_sha  TEXT,
        url         TEXT,
        received_at REAL NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_deployments_service ON deployments (service, deployed_at)",
    """
    CREATE TABLE IF NOT EXISTS tickets (
        incident_id TEXT NOT NULL,
        provider    TEXT NOT NULL,
        external_id TEXT,
        level       TEXT,
        status      TEXT NOT NULL,
        updated_at  REAL NOT NULL,
        error       TEXT,
        PRIMARY KEY (incident_id, provider)
    )
    """,
)


@dataclass
class Incident:
    id: str
    kind: str
    message: str
    details: Dict[str, Any]
    created_at: float
    last_seen: float
    status: str = "open"
    occurrences: int = 1
    severity: Dict[str, Any] = field(default_factory=dict)
    routing: Dict[str, Any] = field(default_factory=dict)
    deployments: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def new(cls, kind: str, message: str, details: Dict[str, Any], now: Optional[float] = None) -> "Incident":
        now = time.time() if now is None else now
        return cls(
            id=f"inc-{uuid.uuid4().hex[:12]}",
            kind=kind,
            message=message,
            details=details,
            created_at=now,
            last_seen=now,
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["created_at"] = int(self.created_at)
        d["last_seen"] = int(self.last_seen)
        return d


class IncidentStore:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or os.getenv("INCIDENTS_DB", "./data/incidents.sqlite3")
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
        with self._connect() as conn:
            for stmt in _SCHEMA:
                conn.execute(stmt)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # --- incidents -------------------------------------------------------

    @staticmethod
    def _incident(row: sqlite3.Row) -> Incident:
        return Incident(
            id=row["id"],
            kind=row["kind"],
            message=row["message"],
            details=json.loads(row["details"]),
            created_at=row["created_at"],
            last_seen=row["last_seen"],
            status=row["status"],
            occurrences=row["occurrences"],
            severity=json.loads(row["severity"]),
            routing=json.loads(row["routing"]),
            deployments=json.loads(row["deployments"]),
        )

    def save(self, inc: Incident) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO incidents (id, kind, status, created_at, last_seen, occurrences,"
                " message, details, severity, routing, deployments) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    inc.id, inc.kind, inc.status, inc.created_at, inc.last_seen, inc.occurrences,
                    inc.message, json.dumps(inc.details), json.dumps(inc.severity),
                    json.dumps(inc.routing), json.dumps(inc.deployments),
                ),
            )

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._incident(row) if row else None

    def find_open(self, kind: Optional[str] = None, since: float = 0.0) -> List[Incident]:
        sql = "SELECT * FROM incidents WHERE status = 'open' AND last_seen >= ?"
        params: List[Any] = [since]
        if kind is not None:
            sql += " AND kind = ?"
            params.append(kind)
        with self._connect() as conn:
            rows = conn.execute(sql + " ORDER BY last_seen DESC", params).fetchall()
        return [self._incident(r) for r in rows]

    def list(self, limit: int = 50, status: Optional[str] = None, team: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM incidents WHERE 1 = 1"
        params: List[Any] = []
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        if team is not None:
            sql += " AND json_extract(routing, '$.team') = ?"
            params.append(team)
        sql += " ORDER BY last_seen DESC, created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            d = self._incident(r).to_dict()
            d["analyses"] = self.analyses(d["id"])
            out.append(d)
        return out

    # --- analyses --------------------------------------------------------

    def attach_analysis(self, incident_id: str, analysis: Dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO analyses (incident_id, created_at, analysis) VALUES (?, ?, ?)",
                (incident_id, time.time(), json.dumps(analysis, default=str)),
            )

    def analyses(self, incident_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT analysis FROM analyses WHERE incident_id = ? ORDER BY id", (incident_id,)
            ).fetchall()
        return [json.loads(r["analysis"]) for r in rows]

    # --- feedback --------------------------------------------------------

    def add_feedback(
        self,
        incident_id: str,
        submitted_by: str,
        verdict: Optional[str],
        reassign_team: Optional[str],
        severity_override: Optional[str],
        note: Optional[str],
        previous: Dict[str, Any],
    ) -> Dict[str, Any]:
        now = time.time()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO feedback (incident_id, created_at, submitted_by, verdict, reassign_team,"
                " severity_override, note, previous) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (incident_id, now, submitted_by, verdict, reassign_team, severity_override, note, json.dumps(previous)),
            )
            feedback_id = cur.lastrowid
        return {
            "id": feedback_id, "incident_id": incident_id, "created_at": now, "submitted_by": submitted_by,
            "verdict": verdict, "reassign_team": reassign_team, "severity_override": severity_override,
            "note": note, "previous": previous,
        }

    def list_feedback(self, limit: int = 100, incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM feedback"
        params: List[Any] = []
        if incident_id is not None:
            sql += " WHERE incident_id = ?"
            params.append(incident_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["previous"] = json.loads(d["previous"])
            out.append(d)
        return out

    def false_positive_count(self, service: Optional[str], since: float, exclude: Optional[str] = None) -> int:
        """Incidents whose primary service is `service` that operators marked false positive."""
        if not service:
            return 0
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT f.incident_id) FROM feedback f JOIN incidents i ON i.id = f.incident_id"
                " WHERE f.verdict = 'false_positive' AND f.created_at >= ?"
                " AND json_extract(i.routing, '$.service') = ? AND i.id != ?",
                (since, service, exclude or ""),
            ).fetchone()
        return int(row[0])

    # --- deployments -----------------------------------------------------

    def add_deployment(
        self,
        service: str,
        version: str,
        environment: str,
        deployed_at: float,
        commit_sha: Optional[str] = None,
        url: Optional[str] = None,
    ) -> Dict[str, Any]:
        record = {
            "id": f"dep-{uuid.uuid4().hex[:12]}", "service": service, "version": version,
            "environment": environment, "deployed_at": deployed_at, "commit_sha": commit_sha,
            "url": url, "received_at": time.time(),
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO deployments (id, service, version, environment, deployed_at, commit_sha, url, received_at)"
                " VALUES (:id, :service, :version, :environment, :deployed_at, :commit_sha, :url, :received_at)",
                record,
            )
        return record

    def deployments_for(self, services: Iterable[str], start: float, end: float) -> List[Dict[str, Any]]:
        services = sorted(set(services))
        if not services:
            return []
        marks = ",".join("?" for _ in services)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM deployments WHERE service IN ({marks}) AND deployed_at BETWEEN ? AND ?"
                " ORDER BY deployed_at DESC",
                [*services, start, end],
            ).fetchall()
        return [dict(r) for r in rows]

    # --- external tickets ------------------------------------------------

    def tickets(self, incident_id: str) -> Dict[str, Dict[str, Any]]:
        """Ticket state per provider for one incident."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM tickets WHERE incident_id = ?", (incident_id,)).fetchall()
        return {r["provider"]: dict(r) for r in rows}

    def save_ticket(
        self,
        incident_id: str,
        provider: str,
        external_id: Optional[str],
        level: Optional[str],
        status: str,
        error: Optional[str] = None,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO tickets (incident_id, provider, external_id, level, status, updated_at, error)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (incident_id, provider, external_id, level, status, time.time(), error),
            )

    def list_deployments(self, limit: int = 50, service: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM deployments"
        params: List[Any] = []
        if service is not None:
            sql += " WHERE service = ?"
            params.append(service)
        sql += " ORDER BY deployed_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
