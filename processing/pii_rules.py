"""Suggested PII rules: where NER keeps finding entities, propose a rule for a person to approve.

Each NER hit turns the text (already rule-redacted) into a template: every NER span becomes
a slot such as <<PERSON>>, and ids, numbers, IPs and masked values are generalised, e.g.
"profile update failed for <<PERSON>> <masked>". A (template, slot) pair is a suggestion.
It is `pending` once PII_SUGGEST_MIN_DISTINCT different values were seen in the slot. After
approval (API: /pii-rules, page: /ui/pii-rules) the rule tier redacts that slot in every text
matching the template, including rules-only paths (Spark). Only keyed hashes of slot values
are stored, to count distinct values; templates hold the redacted message shape.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from processing.learned_pii import _DEFAULT_ENTITIES, MAX_WORDS, _env_bool

logger = logging.getLogger(__name__)

STATUSES = ("collecting", "pending", "approved", "rejected")
DECISIONS = ("approved", "rejected", "pending")
MAX_TEXT = 500
MAX_SLOTS = 4
MAX_VALUE_HASHES = 100

_GENERALISE = {
    "<masked>": r"\S*(?:\*+@|\*{2,}|\[REDACTED\]|anon_[0-9a-f]{16})\S*",
    "<uuid>": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    "<ip>": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    "<hex>": r"\b(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{8,})\b",
    "<n>": r"\d+",
}
_SHAPES = [(re.compile(rx), token) for token, rx in _GENERALISE.items()]
_TOKEN = re.compile(r"<<([A-Z0-9_]+)>>|<(?:masked|uuid|ip|hex|n)>")
_SLOT = r"(\S+?(?:\s+\S+?){0,%d}?)" % (MAX_WORDS - 1)
_SPACE = re.compile(r"\s+")
_ANCHOR = re.compile(r"[a-z]{3,}")


def _shape(segment: str) -> str:
    for rx, token in _SHAPES:
        segment = rx.sub(token, segment)
    return _SPACE.sub(" ", segment).lower()


def _literal(segment: str) -> str:
    return r"\s+".join(re.escape(w) for w in segment.split(" "))


def compile_template(template: str) -> re.Pattern:
    """Regex that fully matches texts of this shape; slot i is group i + 1."""
    parts, pos = [], 0
    for m in _TOKEN.finditer(template):
        parts.append(_literal(template[pos:m.start()]))
        parts.append(_SLOT if m.group(1) else f"(?:{_GENERALISE[m.group(0)]})")
        pos = m.end()
    parts.append(_literal(template[pos:]))
    return re.compile(r"\s*" + "".join(parts) + r"\s*", re.IGNORECASE | re.DOTALL)


def anchor(template: str) -> str:
    """Longest literal word; texts without it are skipped before the regex runs."""
    return max(_ANCHOR.findall(_TOKEN.sub(" ", template)), key=len, default="")


def display(template: str, slot: int) -> str:
    """Template for people: the suggested slot as {ENTITY}, other slots as <ENTITY>."""
    count = iter(range(MAX_SLOTS + 1))
    return _TOKEN.sub(lambda m: m.group(0) if not m.group(1) else
                      ("{%s}" if next(count) == slot else "<%s>") % m.group(1), template)


class PiiRuleStore:
    def __init__(self, path: str, key: Optional[bytes] = None, entities: Iterable[str] = (),
                 min_distinct: int = 5, reload_seconds: float = 60.0, read_only: bool = False):
        self.path = path
        self.entities = {e.strip().upper() for e in entities if e.strip()}
        self.min_distinct = max(1, min_distinct)
        self.reload_seconds = reload_seconds
        self.read_only = read_only
        self._key = hashlib.sha256(b"pii-rules|" + key).digest() if key else None
        self._approved: List[Tuple[str, re.Pattern, int]] = []
        self._compiled: Dict[str, Tuple[str, re.Pattern, int]] = {}
        self._loaded_at = float("-inf")
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        if not read_only:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS pii_rules (id TEXT PRIMARY KEY, template TEXT NOT NULL,"
                " slot INTEGER NOT NULL, entity TEXT NOT NULL, status TEXT NOT NULL, hits INTEGER NOT NULL,"
                " distinct_values INTEGER NOT NULL, first_seen REAL, last_seen REAL,"
                " decided_at REAL, decided_by TEXT)")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS pii_rule_values (rule_id TEXT NOT NULL, hash TEXT NOT NULL,"
                " PRIMARY KEY (rule_id, hash))")
            self._conn.commit()

    @classmethod
    def from_env(cls, key: Optional[bytes] = None, read_only: bool = False) -> Optional["PiiRuleStore"]:
        if not _env_bool("PII_RULE_SUGGESTIONS", True):
            return None
        try:
            return cls(
                path=os.getenv("PII_LEARNED_DB", "./data/learned_pii.sqlite3"),
                key=key,
                entities=os.getenv("PII_LEARN_ENTITIES", _DEFAULT_ENTITIES).split(","),
                min_distinct=int(os.getenv("PII_SUGGEST_MIN_DISTINCT", "5")),
                reload_seconds=float(os.getenv("PII_LEARNED_RELOAD_SECONDS", "60")),
                read_only=read_only,
            )
        except Exception as e:
            logger.error("PII rule suggestions unavailable (%s); continuing without them.", e)
            return None

    def _hash(self, value: str) -> str:
        words = " ".join(_SPACE.split(value.strip().lower()))
        return hashlib.blake2b(words.encode(), key=self._key, digest_size=16).hexdigest()


    # --- learning (NER path) ------------------------------------------------

    def observe(self, text: str, results: Iterable[Any]) -> None:
        """Record where NER found entities in `text` (results carry entity_type, start, end)."""
        if self.read_only or self._conn is None or self._key is None or not text or len(text) > MAX_TEXT:
            return
        spans: List[Tuple[int, int, str]] = []
        for r in sorted(results, key=lambda r: (r.start, -r.end)):
            if not spans or r.start >= spans[-1][1]:
                spans.append((r.start, r.end, re.sub(r"[^A-Z0-9_]", "_", str(r.entity_type).upper())))
        if not spans or len(spans) > MAX_SLOTS or not any(e in self.entities for _, _, e in spans):
            return
        pieces, pos = [], 0
        for start, end, entity in spans:
            pieces += [_shape(text[pos:start]), f"<<{entity}>>"]
            pos = end
        template = ("".join(pieces) + _shape(text[pos:])).strip()
        if not anchor(template):
            return
        # Only keep templates whose regex finds exactly the NER spans again.
        m = compile_template(template).fullmatch(text)
        if m is None or any(m.span(i + 1) != (s, e) for i, (s, e, _) in enumerate(spans)):
            return
        now = time.time()
        with self._lock:
            try:
                for i, (start, end, entity) in enumerate(spans):
                    if entity not in self.entities:
                        continue
                    rid = hashlib.sha1(f"{template}|{i}".encode()).hexdigest()[:16]
                    self._conn.execute(
                        "INSERT INTO pii_rules (id, template, slot, entity, status, hits, distinct_values,"
                        " first_seen, last_seen) VALUES (?, ?, ?, ?, 'collecting', 1, 0, ?, ?)"
                        " ON CONFLICT(id) DO UPDATE SET hits = hits + 1, last_seen = excluded.last_seen",
                        (rid, template, i, entity, now, now))
                    added = self._conn.execute(
                        "INSERT OR IGNORE INTO pii_rule_values SELECT ?, ? WHERE"
                        " (SELECT COUNT(*) FROM pii_rule_values WHERE rule_id = ?) < ?",
                        (rid, self._hash(text[start:end]), rid, MAX_VALUE_HASHES)).rowcount
                    if added:
                        self._conn.execute(
                            "UPDATE pii_rules SET distinct_values = distinct_values + 1, status = CASE"
                            " WHEN status = 'collecting' AND distinct_values + 1 >= ? THEN 'pending'"
                            " ELSE status END WHERE id = ?", (self.min_distinct, rid))
                self._conn.commit()
            except sqlite3.Error as e:
                logger.error("Could not record PII rule suggestion: %s", e)

    # --- applying (rule tier) -----------------------------------------------

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._loaded_at < self.reload_seconds:
            return
        self._loaded_at = now
        query = "SELECT id, template, slot FROM pii_rules WHERE status = 'approved'"
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
            if "no such table" not in str(e):
                logger.warning("Could not load PII rules: %s", e)
            return
        compiled = {rid: self._compiled.get(rid) or (anchor(t), compile_template(t), slot + 1)
                    for rid, t, slot in rows}
        self._compiled = compiled
        self._approved = list(compiled.values())

    def apply(self, text: str) -> Tuple[str, bool]:
        with self._lock:
            self._maybe_reload()
            rules = self._approved
        if not rules or not text or len(text) > MAX_TEXT:
            return text, False
        low = text.lower()
        spans = set()
        for word, rx, group in rules:
            if word in low:
                m = rx.fullmatch(text)
                if m is not None:
                    spans.add(m.span(group))
        last = len(text)
        for start, end in sorted(spans, reverse=True):
            if end <= last:
                text = text[:start] + "[REDACTED]" + text[end:]
                last = start
        return text, bool(spans)

    # --- review (API) -------------------------------------------------------

    def _rows(self, where: str, params: tuple) -> List[Dict[str, Any]]:
        cols = ("id", "template", "slot", "entity", "status", "hits", "distinct_values",
                "first_seen", "last_seen", "decided_at", "decided_by")
        rows = self._conn.execute(f"SELECT {', '.join(cols)} FROM pii_rules {where}", params).fetchall()
        out = [dict(zip(cols, r)) for r in rows]
        for r in out:
            r["display"] = display(r["template"], r["slot"])
        return out

    def list(self, status: Optional[str] = "pending", limit: int = 100) -> List[Dict[str, Any]]:
        if self._conn is None:
            raise RuntimeError("PII rule store is read-only")
        where, params = ("WHERE status = ?", (status,)) if status else ("", ())
        with self._lock:
            return self._rows(f"{where} ORDER BY distinct_values DESC, hits DESC LIMIT ?",
                              params + (max(1, min(limit, 1000)),))

    def decide(self, ids: Iterable[str], status: str, by: str) -> List[Dict[str, Any]]:
        """Approve, reject or reset suggestions; returns the updated rows."""
        if self._conn is None:
            raise RuntimeError("PII rule store is read-only")
        if status not in DECISIONS:
            raise ValueError(f"status must be one of {list(DECISIONS)}")
        ids = sorted(set(ids))
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        with self._lock:
            self._conn.execute(f"UPDATE pii_rules SET status = ?, decided_at = ?, decided_by = ?"
                               f" WHERE id IN ({marks})", (status, time.time(), by, *ids))
            self._conn.commit()
            self._loaded_at = float("-inf")
            return self._rows(f"WHERE id IN ({marks})", tuple(ids))

    def counts(self) -> Dict[str, int]:
        """Suggestions per status (all STATUSES, zero when absent)."""
        if self._conn is None:
            raise RuntimeError("PII rule store is read-only")
        with self._lock:
            rows = self._conn.execute("SELECT status, COUNT(*) FROM pii_rules GROUP BY status").fetchall()
        return {s: 0 for s in STATUSES} | dict(rows)
