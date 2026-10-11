"""Learned PII: entities found by NER become rules once a person approves them.

Only keyed hashes of the entity text are stored, never the text itself. After
PII_LEARN_MIN_HITS separate NER detections an entity becomes `pending`. Only `approved`
entities are applied, through the same admin API as the template suggestions in
processing/pii_rules.py (/admin/pii-rules?kind=entity, /admin/pii-rules/decisions), so
nothing NER sees becomes a rule without human approval. Approved entities are masked
everywhere, including rules-only paths (Spark, or NER unavailable).
Terms on the profile's allow_list are never learned or applied.
Off by default (PII_LEARNING=false); refuses to start with the public default key.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

MAX_WORDS = 4
_WORD = re.compile(r"[^\W_][\w'-]*")
_DEFAULT_ENTITIES = "PERSON,LOCATION,NRP"
DEFAULT_PSEUDONYM_KEY = "dev-only-change-me"
STATUSES = ("collecting", "pending", "approved", "rejected")
DECISIONS = ("approved", "rejected", "pending")


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    return default if val is None else val.strip().lower() in {"1", "true", "yes", "on"}


class LearnedEntities:
    def __init__(self, path: str, key: bytes, entities: Iterable[str] = (), min_hits: int = 2,
                 reload_seconds: float = 60.0, allow_list: Iterable[str] = (), read_only: bool = False):
        self.path = path
        self.entities = {e.strip().upper() for e in entities if e.strip()}
        self.min_hits = max(1, min_hits)
        self.reload_seconds = reload_seconds
        self.read_only = read_only
        self._key = hashlib.sha256(b"learned-pii|" + key).digest()
        self._blocked = {self._hash(w) for w in (self._words(a) for a in allow_list) if w}
        self._active: Dict[int, Set[str]] = {}
        self._loaded_at = float("-inf")
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        if not read_only:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS learned_pii (hash TEXT PRIMARY KEY, entity TEXT NOT NULL,"
                " words INTEGER NOT NULL, hits INTEGER NOT NULL, first_seen REAL, last_seen REAL,"
                " status TEXT NOT NULL DEFAULT 'collecting', decided_at REAL, decided_by TEXT)")
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(learned_pii)")}
            if "status" not in cols:
                # Tables from before approval existed: those entities were active without review.
                # They go to `pending`, not `approved`, so a person has to confirm them.
                for col in ("status TEXT NOT NULL DEFAULT 'collecting'", "decided_at REAL", "decided_by TEXT"):
                    self._conn.execute(f"ALTER TABLE learned_pii ADD COLUMN {col}")
                self._conn.execute("UPDATE learned_pii SET status = 'pending' WHERE hits >= ?", (self.min_hits,))
            self._conn.commit()

    @classmethod
    def from_env(cls, key: bytes, allow_list: Iterable[str] = (),
                 read_only: bool = False) -> Optional["LearnedEntities"]:
        if not _env_bool("PII_LEARNING", False):
            return None
        if key == DEFAULT_PSEUDONYM_KEY.encode():
            # Hashes of names under a public key can be reversed with a dictionary of names.
            raise RuntimeError("PII_LEARNING is on but PII_PSEUDONYM_KEY is still the public default "
                               f"{DEFAULT_PSEUDONYM_KEY!r}. Set a secret key or set PII_LEARNING=false.")
        try:
            return cls(
                path=os.getenv("PII_LEARNED_DB", "./data/learned_pii.sqlite3"),
                key=key,
                entities=os.getenv("PII_LEARN_ENTITIES", _DEFAULT_ENTITIES).split(","),
                min_hits=int(os.getenv("PII_LEARN_MIN_HITS", "2")),
                reload_seconds=float(os.getenv("PII_LEARNED_RELOAD_SECONDS", "60")),
                allow_list=allow_list,
                read_only=read_only,
            )
        except Exception as e:
            logger.error("Learned PII store unavailable (%s); continuing without it.", e)
            return None

    @staticmethod
    def _words(text: str) -> Tuple[str, ...]:
        return tuple(w.lower() for w in _WORD.findall(text))

    def _hash(self, words: Tuple[str, ...]) -> str:
        return hashlib.blake2b(" ".join(words).encode(), key=self._key, digest_size=16).hexdigest()

    # --- learning (NER path) ------------------------------------------------

    def observe(self, text: str, results: Iterable[Any]) -> None:
        """Record NER hits on `text` (results carry entity_type, start, end)."""
        if self.read_only or self._conn is None:
            return
        rows = []
        for r in results:
            if r.entity_type not in self.entities:
                continue
            words = self._words(text[r.start:r.end])
            if not 1 <= len(words) <= MAX_WORDS or len(" ".join(words)) < 3:
                continue
            h = self._hash(words)
            if h not in self._blocked:
                rows.append((h, r.entity_type, len(words)))
        if not rows:
            return
        now = time.time()
        with self._lock:
            try:
                for h, entity, n in set(rows):
                    self._conn.execute(
                        "INSERT INTO learned_pii (hash, entity, words, hits, first_seen, last_seen)"
                        " VALUES (?, ?, ?, 1, ?, ?) ON CONFLICT(hash) DO UPDATE"
                        " SET hits = hits + 1, last_seen = excluded.last_seen", (h, entity, n, now, now))
                    # Enough sightings only makes it reviewable; it is not applied until approved.
                    self._conn.execute(
                        "UPDATE learned_pii SET status = 'pending' WHERE hash = ? AND status = 'collecting'"
                        " AND hits >= ?", (h, self.min_hits))
                self._conn.commit()
            except sqlite3.Error as e:
                logger.error("Could not record learned PII: %s", e)

    # --- applying (rule tier) -----------------------------------------------

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._loaded_at < self.reload_seconds:
            return
        self._loaded_at = now
        query = "SELECT hash, words FROM learned_pii WHERE status = 'approved'"
        try:
            if self._conn is not None:
                rows = self._conn.execute(query).fetchall()
            elif os.path.exists(self.path):
                ro = sqlite3.connect(f"file:{os.path.abspath(self.path)}?mode=ro", uri=True)
                try:
                    rows = ro.execute(query).fetchall()
                finally:
                    ro.close()
            else:
                return
        except sqlite3.Error as e:
            # An unmigrated table (no status column yet) has nothing approved.
            if "no such" not in str(e):
                logger.warning("Could not load learned PII: %s", e)
            return
        active: Dict[int, Set[str]] = {}
        for h, n in rows:
            if h not in self._blocked:
                active.setdefault(int(n), set()).add(h)
        self._active = active

    def size(self) -> int:
        """Number of approved entities in use."""
        with self._lock:
            self._maybe_reload()
            return sum(len(s) for s in self._active.values())

    # --- review (API) -------------------------------------------------------

    def _rows(self, where: str, params: tuple) -> List[Dict[str, Any]]:
        cols = ("hash", "entity", "words", "status", "hits", "first_seen", "last_seen", "decided_at", "decided_by")
        out = []
        for r in self._conn.execute(f"SELECT {', '.join(cols)} FROM learned_pii {where}", params).fetchall():
            row = dict(zip(cols, r))
            row["id"] = row.pop("hash")
            row["kind"] = "entity"
            # The text is never stored, so a reviewer sees the type and size, not the value.
            row["display"] = f"{{{row['entity']}}}, {row['words']} word(s), value not stored"
            out.append(row)
        return out

    def list(self, status: Optional[str] = "pending", limit: int = 100) -> List[Dict[str, Any]]:
        if self._conn is None:
            raise RuntimeError("Learned entity store is read-only")
        where, params = ("WHERE status = ?", (status,)) if status else ("", ())
        with self._lock:
            return self._rows(f"{where} ORDER BY hits DESC LIMIT ?", params + (max(1, min(limit, 1000)),))

    def decide(self, ids: Iterable[str], status: str, by: str) -> List[Dict[str, Any]]:
        """Approve, reject or reset entities; returns the updated rows."""
        if self._conn is None:
            raise RuntimeError("Learned entity store is read-only")
        if status not in DECISIONS:
            raise ValueError(f"status must be one of {list(DECISIONS)}")
        ids = sorted(set(ids))
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        with self._lock:
            self._conn.execute(f"UPDATE learned_pii SET status = ?, decided_at = ?, decided_by = ?"
                               f" WHERE hash IN ({marks})", (status, time.time(), by, *ids))
            self._conn.commit()
            self._loaded_at = float("-inf")
            return self._rows(f"WHERE hash IN ({marks})", tuple(ids))

    def counts(self) -> Dict[str, int]:
        if self._conn is None:
            raise RuntimeError("Learned entity store is read-only")
        with self._lock:
            rows = self._conn.execute("SELECT status, COUNT(*) FROM learned_pii GROUP BY status").fetchall()
        return {s: 0 for s in STATUSES} | dict(rows)

    def apply(self, text: str) -> Tuple[str, bool]:
        with self._lock:
            self._maybe_reload()
            active = self._active
        if not active or not text:
            return text, False
        tokens = [(m.start(), m.end(), m.group(0).lower()) for m in _WORD.finditer(text)]
        spans: List[Tuple[int, int]] = []
        i = 0
        while i < len(tokens):
            for n in sorted((k for k in active if i + k <= len(tokens)), reverse=True):
                if self._hash(tuple(t[2] for t in tokens[i:i + n])) in active[n]:
                    spans.append((tokens[i][0], tokens[i + n - 1][1]))
                    i += n
                    break
            else:
                i += 1
        for start, end in reversed(spans):
            text = text[:start] + "[REDACTED]" + text[end:]
        return text, bool(spans)
