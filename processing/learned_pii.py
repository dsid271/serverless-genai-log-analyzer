"""Learned PII: entities found by NER become rules, so the rule tier improves over time.

Only keyed hashes of the entity text are stored, never the text itself. An entity
becomes active after PII_LEARN_MIN_HITS separate NER detections; the rule tier then
masks it everywhere, including rules-only paths (Spark, or NER unavailable).
Terms on the profile's allow_list are never learned or applied.
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
                " words INTEGER NOT NULL, hits INTEGER NOT NULL, first_seen REAL, last_seen REAL)")
            self._conn.commit()

    @classmethod
    def from_env(cls, key: bytes, allow_list: Iterable[str] = (),
                 read_only: bool = False) -> Optional["LearnedEntities"]:
        if not _env_bool("PII_LEARNING", True):
            return None
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
                        "INSERT INTO learned_pii VALUES (?, ?, ?, 1, ?, ?) ON CONFLICT(hash) DO UPDATE"
                        " SET hits = hits + 1, last_seen = excluded.last_seen", (h, entity, n, now, now))
                    hits = self._conn.execute("SELECT hits FROM learned_pii WHERE hash = ?", (h,)).fetchone()[0]
                    if hits >= self.min_hits:
                        self._active.setdefault(n, set()).add(h)
                self._conn.commit()
            except sqlite3.Error as e:
                logger.error("Could not record learned PII: %s", e)

    # --- applying (rule tier) -----------------------------------------------

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._loaded_at < self.reload_seconds:
            return
        self._loaded_at = now
        try:
            if self._conn is not None:
                rows = self._conn.execute(
                    "SELECT hash, words FROM learned_pii WHERE hits >= ?", (self.min_hits,)).fetchall()
            elif os.path.exists(self.path):
                with sqlite3.connect(f"file:{os.path.abspath(self.path)}?mode=ro", uri=True) as ro:
                    rows = ro.execute(
                        "SELECT hash, words FROM learned_pii WHERE hits >= ?", (self.min_hits,)).fetchall()
            else:
                return
        except sqlite3.Error as e:
            logger.warning("Could not load learned PII: %s", e)
            return
        active: Dict[int, Set[str]] = {}
        for h, n in rows:
            if h not in self._blocked:
                active.setdefault(int(n), set()).add(h)
        self._active = active

    def size(self) -> int:
        with self._lock:
            self._maybe_reload()
            return sum(len(s) for s in self._active.values())

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
