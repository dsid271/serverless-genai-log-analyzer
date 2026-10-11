"""
SQLite-backed API key store.

Key format: ``gla_<key_id>_<secret>``. Only a SHA-256 digest of the secret is
stored; the plaintext is returned once at issuance. Secrets are 256-bit random
values, so a fast digest is sufficient (slow hashes like bcrypt exist to protect
low-entropy passwords). Lookup is by ``key_id``, then a constant-time compare.

Each key is issued for a profile, which fixes its scopes and default lifetime.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterator, List, Optional, Tuple

KEY_PREFIX = "gla"

SCOPES: FrozenSet[str] = frozenset({
    "logs:ingest",
    "logs:search",
    "analyze:run",
    "incidents:read",
    "incidents:feedback",
    "events:write",
    "knowledge:write",
    "summary:read",
    "plugins:read",
    "audit:read",
    "keys:admin",
})

# profile -> (scopes, default TTL in days; None means no expiry)
PROFILES: Dict[str, Tuple[FrozenSet[str], Optional[int]]] = {
    "admin": (SCOPES, 30),
    "analyst": (frozenset({
        "logs:ingest", "logs:search", "analyze:run",
        "incidents:read", "incidents:feedback", "knowledge:write",
        "summary:read", "plugins:read",
    }), 90),
    "viewer": (frozenset({"incidents:read", "summary:read", "plugins:read"}), 180),
    "ingest-service": (frozenset({"logs:ingest"}), 365),
    "deploy-webhook": (frozenset({"events:write"}), 365),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    key_id       TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    profile      TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    secret_hash  TEXT NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL,
    revoked_at   REAL,
    last_used_at REAL
)
"""


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    name: str
    profile: str
    scopes: FrozenSet[str]
    created_at: float
    expires_at: Optional[float]
    revoked_at: Optional[float]
    last_used_at: Optional[float]

    def to_dict(self) -> Dict[str, object]:
        return {
            "key_id": self.key_id,
            "name": self.name,
            "profile": self.profile,
            "scopes": sorted(self.scopes),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
            "last_used_at": self.last_used_at,
        }


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def parse_key(raw_key: str) -> Optional[Tuple[str, str]]:
    parts = raw_key.split("_", 2)
    if len(parts) != 3 or parts[0] != KEY_PREFIX or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


class KeyStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        with self._connect() as conn:
            conn.execute(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> KeyRecord:
        return KeyRecord(
            key_id=row["key_id"],
            name=row["name"],
            profile=row["profile"],
            scopes=frozenset(row["scopes"].split()),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            revoked_at=row["revoked_at"],
            last_used_at=row["last_used_at"],
        )

    def issue(self, name: str, profile: str, ttl_days: Optional[int] = None) -> Tuple[str, KeyRecord]:
        """Create a key. Returns (plaintext_key, record). The plaintext is not stored."""
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile '{profile}'. Choose from: {sorted(PROFILES)}")
        if not name.strip():
            raise ValueError("name is required")
        scopes, default_ttl = PROFILES[profile]
        ttl = default_ttl if ttl_days is None else ttl_days
        if ttl is not None and ttl <= 0:
            raise ValueError("ttl_days must be positive")

        now = time.time()
        key_id = secrets.token_hex(6)
        secret = secrets.token_urlsafe(32)
        expires_at = now + ttl * 86400 if ttl is not None else None
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO api_keys (key_id, name, profile, scopes, secret_hash, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (key_id, name.strip(), profile, " ".join(sorted(scopes)), _digest(secret), now, expires_at),
            )
        record = KeyRecord(key_id, name.strip(), profile, scopes, now, expires_at, None, None)
        return f"{KEY_PREFIX}_{key_id}_{secret}", record

    def verify(self, raw_key: str) -> Optional[KeyRecord]:
        """Return the record for a valid, unrevoked, unexpired key; otherwise None."""
        parsed = parse_key(raw_key)
        if parsed is None:
            return None
        key_id, secret = parsed
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
            if row is None or not hmac.compare_digest(row["secret_hash"], _digest(secret)):
                return None
            now = time.time()
            if row["revoked_at"] is not None:
                return None
            if row["expires_at"] is not None and row["expires_at"] <= now:
                return None
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (now, key_id))
        return self._row(row)

    def list(self, include_revoked: bool = False) -> List[KeyRecord]:
        sql = "SELECT * FROM api_keys"
        if not include_revoked:
            sql += " WHERE revoked_at IS NULL"
        with self._connect() as conn:
            rows = conn.execute(sql + " ORDER BY created_at DESC").fetchall()
        return [self._row(r) for r in rows]

    def revoke(self, key_id: str) -> bool:
        """Revoke a key. Returns False if it does not exist or is already revoked."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                (time.time(), key_id),
            )
        return cur.rowcount == 1


_store: Optional[KeyStore] = None
_store_path: Optional[str] = None


def get_key_store() -> KeyStore:
    """Process-wide store at $API_KEYS_DB (default ./data/api_keys.sqlite3)."""
    global _store, _store_path
    path = os.getenv("API_KEYS_DB", "./data/api_keys.sqlite3")
    if _store is None or _store_path != path:
        _store = KeyStore(path)
        _store_path = path
    return _store
